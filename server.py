#!/usr/bin/env python3
"""
AEGIS Agent - Native Kali Orchestration Server
===============================================

FastAPI server for autonomous penetration testing.
No cloud sandboxes - pure local Kali Linux execution.

Features:
- Pre-flight environment validation
- Self-healing tool manifest
- Real-time WebSocket terminal streaming
- Native CLI tool orchestration
"""

import asyncio
import logging
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

# Load environment
load_dotenv()

# Paths
SCRIPT_DIR = Path(__file__).parent.resolve()
LOGS_DIR = SCRIPT_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)
WEB_DIST = SCRIPT_DIR / "web" / "build"

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOGS_DIR / 'aegis_server.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Add project to path
sys.path.insert(0, str(SCRIPT_DIR))

# Import Aegis modules
from tools.environment import run_preflight_check, get_environment, AuditResult
from tools.manifest_manager import get_manifest, initialize_manifest, get_apt_manager
from execution.terminal import get_executor, set_stream_callback, ExecutionResult


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class MissionRequest(BaseModel):
    target: str = Field(..., description="Target URL or IP")
    rules: str = Field(default="", description="Mission rules/scope")
    max_iterations: int = Field(default=50, description="Maximum iterations")
    auto_install: bool = Field(default=False, description="Auto-install missing tools")


class TerminalRequest(BaseModel):
    command: str = Field(..., description="Command to execute")
    timeout: int = Field(default=300, description="Timeout in seconds")
    stream: bool = Field(default=True, description="Stream output via WebSocket")


class ToolExecuteRequest(BaseModel):
    tool_name: str = Field(..., description="Tool name from manifest")
    args: Dict[str, Any] = Field(default_factory=dict, description="Tool arguments")


# ============================================================================
# APPLICATION STATE
# ============================================================================

class AppState:
    """Application state manager with WebSocket streaming."""
    
    def __init__(self):
        self.active_websockets: set = set()
        self.active_missions: Dict[str, Any] = {}
        self.mission_results: Dict[str, Any] = {}
        self.environment_audit: Optional[AuditResult] = None
        self.preflight_complete: bool = False
    
    async def add_websocket(self, ws: WebSocket):
        self.active_websockets.add(ws)
    
    async def remove_websocket(self, ws: WebSocket):
        self.active_websockets.discard(ws)
    
    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast to all connected clients."""
        for ws in list(self.active_websockets):
            try:
                await ws.send_json(message)
            except Exception:
                self.active_websockets.discard(ws)
    
    async def stream_terminal(self, stream_type: str, data: str):
        """Stream terminal output to all clients."""
        await self.broadcast({
            "type": "terminal_output",
            "stream": stream_type,
            "data": data,
            "timestamp": time.time()
        })


app_state = AppState()


# ============================================================================
# WEBSOCKET STREAM CALLBACK
# ============================================================================

def ws_stream_callback(stream_type: str, data: str):
    """Callback for terminal executor to stream output."""
    asyncio.create_task(app_state.stream_terminal(stream_type, data))


# ============================================================================
# FASTAPI APP
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle with pre-flight checks."""
    logger.info("=" * 60)
    logger.info("🚀 AEGIS Agent - Native Kali Orchestration")
    logger.info("=" * 60)
    
    # Run pre-flight environment audit
    logger.info("🔍 Running pre-flight checks...")
    auto_install = os.getenv("AUTO_INSTALL_TOOLS", "false").lower() == "true"
    app_state.environment_audit = await run_preflight_check(auto_install=auto_install)
    
    if not app_state.environment_audit.is_valid:
        logger.warning("⚠️ Environment validation failed - some features may not work")
    else:
        logger.info("✅ Environment validated successfully")
    
    # Initialize tool manifest
    logger.info("📋 Initializing tool manifest...")
    await initialize_manifest()
    
    # Set WebSocket stream callback
    set_stream_callback(ws_stream_callback)
    
    app_state.preflight_complete = True
    logger.info("🟢 Aegis Agent ready for operations")
    logger.info("=" * 60)
    
    yield
    
    # Shutdown
    logger.info("🛑 Aegis Agent shutting down...")
    
    # Kill any active processes
    executor = get_executor()
    for proc_id in list(executor.active_processes.keys()):
        executor.kill(proc_id)


app = FastAPI(
    title="Aegis Agent",
    description="Autonomous Penetration Testing Platform - Native Kali Orchestration",
    version="2.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# REST ENDPOINTS - Core
# ============================================================================

@app.get("/")
async def root():
    """Serve frontend or API info."""
    index = WEB_DIST / "index.html"
    if index.exists():
        return FileResponse(index)
    return {
        "status": "online",
        "version": "2.0.0",
        "platform": "Aegis Agent",
        "mode": "Native Kali Orchestration"
    }


@app.get("/health")
@app.get("/api/health")
async def health():
    """Health check."""
    return {
        "status": "ok",
        "version": "2.0.0",
        "platform": "Aegis Agent",
        "preflight_complete": app_state.preflight_complete,
        "connected_clients": len(app_state.active_websockets),
        "active_missions": len(app_state.active_missions),
    }


@app.get("/api/status")
async def get_status():
    """Get full platform status."""
    env = app_state.environment_audit
    manifest = get_manifest()
    
    return {
        "version": "2.0.0",
        "platform": "Aegis Agent",
        "connected_clients": len(app_state.active_websockets),
        "active_missions": list(app_state.active_missions.keys()),
        "environment": {
            "os": env.os_name if env else "unknown",
            "is_kali": env.is_kali if env else False,
            "is_docker": env.is_docker if env else False,
            "tools_available": len(env.tools_found) if env else 0,
            "tools_missing": len(env.tools_missing) if env else 0,
        },
        "manifest": {
            "total_tools": len(manifest.get_tools()),
            "available_tools": len(manifest.get_available_tools()),
        }
    }


# ============================================================================
# REST ENDPOINTS - Environment
# ============================================================================

@app.get("/api/environment")
async def get_environment_info():
    """Get environment audit results."""
    env = app_state.environment_audit
    if not env:
        return {"error": "Pre-flight not complete"}
    
    return {
        "os": env.os_name,
        "kernel": env.kernel,
        "is_kali": env.is_kali,
        "is_debian": env.is_debian,
        "is_docker": env.is_docker,
        "is_valid": env.is_valid,
        "tools_found": env.tools_found,
        "tools_missing": env.tools_missing,
        "tools_installed": env.tools_installed,
        "errors": env.errors,
    }


@app.post("/api/environment/install/{tool_name}")
async def install_tool(tool_name: str):
    """Install a missing tool."""
    
    # This would trigger apt-get install
    await app_state.broadcast({
        "type": "tool_installing",
        "tool": tool_name
    })
    
    # Run installation using thread-safe manager
    apt_manager = get_apt_manager()
    success = await apt_manager.install(tool_name)
    
    if success:
        # Re-sync manifest
        await get_manifest().sync_with_system()
        
        await app_state.broadcast({
            "type": "tool_installed",
            "tool": tool_name,
            "success": True
        })
        return {"status": "installed", "tool": tool_name}
    else:
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to install {tool_name}"}
        )


# ============================================================================
# REST ENDPOINTS - Manifest
# ============================================================================

@app.get("/api/manifest")
async def get_manifest_info():
    """Get tool manifest."""
    manifest = get_manifest()
    return {
        "metadata": manifest.manifest.get("metadata", {}),
        "tools_count": len(manifest.get_tools()),
        "available_count": len(manifest.get_available_tools()),
        "categories": list(set(t.get("category") for t in manifest.get_tools())),
    }


@app.get("/api/manifest/tools")
async def get_manifest_tools(category: str = None, available_only: bool = False):
    """Get tools from manifest."""
    manifest = get_manifest()
    
    if category:
        tools = manifest.get_tools_by_category(category)
    elif available_only:
        tools = manifest.get_available_tools()
    else:
        tools = manifest.get_tools()
    
    return {"tools": tools}


@app.post("/api/manifest/sync")
async def sync_manifest():
    """Sync manifest with system state."""
    manifest = get_manifest()
    await manifest.sync_with_system()
    
    return {
        "status": "synced",
        "available": len(manifest.get_available_tools()),
        "missing": manifest.get_missing_binaries()
    }


# ============================================================================
# REST ENDPOINTS - Terminal
# ============================================================================

@app.post("/api/terminal/execute")
async def execute_terminal(request: TerminalRequest):
    """Execute a terminal command."""
    executor = get_executor()
    
    await app_state.broadcast({
        "type": "terminal_start",
        "command": request.command
    })
    
    result = await executor.run(
        command=request.command,
        timeout=request.timeout,
        stream=request.stream
    )
    
    await app_state.broadcast({
        "type": "terminal_end",
        "command": request.command,
        "exit_code": result.exit_code
    })
    
    return {
        "command": result.command,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "duration_ms": result.duration_ms,
        "timed_out": result.timed_out
    }


@app.get("/api/terminal/processes")
async def list_processes():
    """List active long-running processes."""
    executor = get_executor()
    return {"processes": executor.list_processes()}


@app.post("/api/terminal/kill/{process_id}")
async def kill_process(process_id: str):
    """Kill a long-running process."""
    executor = get_executor()
    success = executor.kill(process_id)
    return {"killed": success, "process_id": process_id}


# ============================================================================
# REST ENDPOINTS - Tools
# ============================================================================

@app.post("/api/tools/execute")
async def execute_tool(request: ToolExecuteRequest):
    """Execute a tool from the manifest."""
    manifest = get_manifest()
    tool = manifest.get_tool(request.tool_name)
    
    if not tool:
        raise HTTPException(status_code=404, detail=f"Tool not found: {request.tool_name}")
    
    if not tool.get("_available", False):
        raise HTTPException(status_code=400, detail=f"Tool not available: {request.tool_name}")
    
    binary = tool.get("binary_name")
    
    # Build command from args schema
    # This is a simplified version - in production would use proper arg parsing
    args_str = " ".join(f"--{k}={v}" if not isinstance(v, bool) else f"--{k}" 
                        for k, v in request.args.items() if v)
    
    command = f"{binary} {args_str}"
    
    executor = get_executor()
    result = await executor.run(command, stream=True)
    
    return {
        "tool": request.tool_name,
        "command": command,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "duration_ms": result.duration_ms
    }


@app.get("/api/tools")
async def get_tools():
    """List available tools."""
    manifest = get_manifest()
    return {
        "tools": [
            {
                "name": t.get("tool_name"),
                "category": t.get("category"),
                "description": t.get("description"),
                "available": t.get("_available", False),
                "intrusive": t.get("intrusive", False)
            }
            for t in manifest.get_tools()
        ]
    }


# ============================================================================
# REST ENDPOINTS - Mission
# ============================================================================

@app.post("/api/mission/start")
async def start_mission(request: MissionRequest):
    """Start a new penetration testing mission."""
    mission_id = str(uuid.uuid4())
    
    # Store mission info
    app_state.active_missions[mission_id] = {
        "target": request.target,
        "rules": request.rules,
        "started_at": time.time(),
        "status": "running",
    }
    
    # Start mission in background
    asyncio.create_task(_run_mission_background(
        mission_id=mission_id,
        target=request.target,
        rules=request.rules,
        max_iterations=request.max_iterations,
    ))
    
    return {"status": "started", "mission_id": mission_id}


@app.post("/api/mission/{mission_id}/stop")
async def stop_mission(mission_id: str):
    """Stop a running mission."""
    if mission_id in app_state.active_missions:
        app_state.active_missions[mission_id]["status"] = "stopped"
        return {"status": "stopped", "mission_id": mission_id}
    raise HTTPException(status_code=404, detail="Mission not found")


@app.get("/api/mission/{mission_id}")
async def get_mission(mission_id: str):
    """Get mission status and results."""
    if mission_id in app_state.active_missions:
        mission = app_state.active_missions[mission_id]
        result = app_state.mission_results.get(mission_id)
        return {
            "mission_id": mission_id,
            **mission,
            "result": result,
        }
    raise HTTPException(status_code=404, detail="Mission not found")


# ============================================================================
# BACKGROUND MISSION RUNNER
# ============================================================================

async def _run_mission_background(
    mission_id: str,
    target: str,
    rules: str,
    max_iterations: int
):
    """Run mission in background with streaming."""
    try:
        # Broadcast start
        await app_state.broadcast({
            "type": "mission_start",
            "mission_id": mission_id,
            "target": target,
        })
        
        # Get available tools context for LLM
        manifest = get_manifest()
        tools_context = manifest.to_llm_context()
        
        # This is where we'd integrate with the Omega Protocol
        # For now, we'll do a basic reconnaissance flow
        
        logger.info(f"🎯 Mission started: {target}")
        
        # Example: Run basic recon
        executor = get_executor()
        
        # Subdomain enumeration if available
        if manifest.get_tool("subdomain_enumeration"):
            await app_state.broadcast({
                "type": "phase",
                "mission_id": mission_id,
                "phase": "KNOW",
                "action": "Subdomain enumeration"
            })
            
            result = await executor.run(f"subfinder -d {target} -silent", timeout=60)
            
            await app_state.broadcast({
                "type": "tool_result",
                "mission_id": mission_id,
                "tool": "subfinder",
                "output": result.stdout
            })
        
        # Mark complete
        if mission_id in app_state.active_missions:
            app_state.active_missions[mission_id]["status"] = "complete"
        
        # Broadcast end
        await app_state.broadcast({
            "type": "mission_end",
            "mission_id": mission_id,
        })
        
    except Exception as e:
        logger.error(f"❌ Mission error: {e}")
        await app_state.broadcast({
            "type": "mission_error",
            "mission_id": mission_id,
            "error": str(e),
        })
        if mission_id in app_state.active_missions:
            app_state.active_missions[mission_id]["status"] = "error"


# ============================================================================
# WEBSOCKET
# ============================================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time WebSocket connection."""
    await websocket.accept()
    await app_state.add_websocket(websocket)
    
    logger.info(f"🔌 WebSocket connected. Total: {len(app_state.active_websockets)}")
    
    # Send initial status
    await websocket.send_json({
        "type": "connected",
        "version": "2.0.0",
        "platform": "Aegis Agent"
    })
    
    try:
        while True:
            data = await websocket.receive_json()
            
            if data.get("type") == "start_mission":
                mission_id = str(uuid.uuid4())
                target = data.get("target")
                rules = data.get("rules", "")
                
                if target:
                    app_state.active_missions[mission_id] = {
                        "target": target,
                        "rules": rules,
                        "started_at": time.time(),
                        "status": "running",
                    }
                    
                    asyncio.create_task(_run_mission_background(
                        mission_id=mission_id,
                        target=target,
                        rules=rules,
                        max_iterations=50,
                    ))
                    
                    await websocket.send_json({
                        "type": "mission_started",
                        "mission_id": mission_id,
                    })
            
            elif data.get("type") == "stop_mission":
                mission_id = data.get("mission_id")
                if mission_id in app_state.active_missions:
                    app_state.active_missions[mission_id]["status"] = "stopped"
                    await websocket.send_json({
                        "type": "mission_stopped",
                        "mission_id": mission_id,
                    })
            
            elif data.get("type") == "execute_command":
                command = data.get("command")
                if command:
                    executor = get_executor()
                    result = await executor.run(command, stream=True)
                    await websocket.send_json({
                        "type": "command_result",
                        "command": command,
                        "exit_code": result.exit_code,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                    })
                    
    except WebSocketDisconnect:
        await app_state.remove_websocket(websocket)
        logger.info(f"🔌 WebSocket disconnected. Remaining: {len(app_state.active_websockets)}")


# ============================================================================
# STATIC FILES
# ============================================================================

if WEB_DIST.exists():
    from fastapi.staticfiles import StaticFiles
    app.mount("/static", StaticFiles(directory=WEB_DIST / "static"), name="static")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    print("=" * 60)
    print("🛡️  AEGIS AGENT - Native Kali Orchestration")
    print("=" * 60)
    print("   Mode:      Local Kali Linux Execution")
    print("   Backend:   http://localhost:8000")
    print("   WebSocket: ws://localhost:8000/ws")
    print("   Docs:      http://localhost:8000/docs")
    print("=" * 60)
    
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
