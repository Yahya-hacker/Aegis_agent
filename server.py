#!/usr/bin/env python3
"""
AEGIS AI v9.0 "NEXUS" - Unified FastAPI Server
==============================================

This module provides the main entry point for the Aegis v9.0 platform,
consolidating all previous entry points (app.py, dashboard.py, main.py)
into a single robust FastAPI application.

Features:
- WebSocket-based real-time chat interface
- REST API for agent control and configuration
- MCP (Model Context Protocol) server connection management
- Real-time tool status and swarm monitoring
- Mode switching (Pentest/CTF/Red Teaming/Audit)
"""

import asyncio
import json
import logging
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Load environment variables
load_dotenv()

# Get script directory for robust paths
SCRIPT_DIR = Path(__file__).parent.resolve()
LOGS_DIR = SCRIPT_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)
DATA_DIR = SCRIPT_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
UPLOADS_DIR = DATA_DIR / "uploads"
UPLOADS_DIR.mkdir(exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOGS_DIR / 'aegis_server.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Add project root to PYTHONPATH
sys.path.insert(0, str(SCRIPT_DIR))


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class OperationMode(str, Enum):
    """Operation modes for the Aegis agent"""
    PENETRATION_TESTING = "penetration_testing"
    CTF_MODE = "ctf_mode"
    RED_TEAMING = "red_teaming"
    AUDIT = "audit"


class MCPServerConfig(BaseModel):
    """Configuration for an MCP server connection"""
    name: str = Field(..., description="Friendly name for the MCP server")
    endpoint: str = Field(..., description="MCP server endpoint (sse://... or stdio)")
    enabled: bool = Field(default=True)


class MissionConfig(BaseModel):
    """Mission configuration"""
    target: str = Field(..., description="Target URL or IP")
    rules: str = Field(default="", description="Mission rules and scope")
    mode: OperationMode = Field(default=OperationMode.PENETRATION_TESTING)
    high_impact_mode: bool = Field(default=False)


class ChatMessage(BaseModel):
    """Chat message model"""
    content: str
    role: str = "user"
    timestamp: Optional[float] = None


class ToolStatus(BaseModel):
    """Real-time tool status"""
    name: str
    status: str  # running, completed, failed, pending
    progress: Optional[float] = None
    output: Optional[str] = None


class SwarmDecision(BaseModel):
    """Swarm decision (RED/BLUE/JUDGE)"""
    persona: str
    content: str
    risk_score: Optional[float] = None
    timestamp: float


# ============================================================================
# APPLICATION STATE
# ============================================================================

class AppState:
    """Application state manager"""
    
    def __init__(self):
        self.active_websockets: List[WebSocket] = []
        self.current_mode: OperationMode = OperationMode.PENETRATION_TESTING
        self.mission_config: Optional[MissionConfig] = None
        self.tool_statuses: Dict[str, ToolStatus] = {}
        self.swarm_decisions: List[SwarmDecision] = []
        self.mcp_servers: Dict[str, MCPServerConfig] = {}
        self.agent_initialized: bool = False
        self.ai_core = None
        self.conversation = None
        self.learning_engine = None
        self.chat_history: List[Dict[str, Any]] = []
        self.mcp_client = None
        
    async def initialize_agent(self):
        """Initialize the Aegis AI agent components"""
        if self.agent_initialized:
            return
        
        logger.info("🚀 Initializing Aegis AI Agent...")
        
        try:
            from agents.enhanced_ai_core import EnhancedAegisAI
            from agents.learning_engine import AegisLearningEngine
            from utils.keep_alive import start_keep_alive
            from utils.dynamic_tool_loader import get_tool_loader_async
            from agents.mcp_client import DynamicMCPClient
            
            # Initialize dynamic tool loader
            tool_loader = await get_tool_loader_async()
            stats = tool_loader.get_statistics()
            logger.info(f"🔧 Tool arsenal: {stats['available_tools']}/{stats['total_tools']} tools")
            
            # Initialize learning engine
            self.learning_engine = AegisLearningEngine()
            
            # Initialize Multi-LLM AI Core
            self.ai_core = EnhancedAegisAI(self.learning_engine)
            await self.ai_core.initialize()
            
            # Initialize MCP Client
            self.mcp_client = DynamicMCPClient()
            
            # Start keep-alive
            start_keep_alive(interval=60)
            
            self.agent_initialized = True
            logger.info("✅ Aegis AI Agent initialized successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize agent: {e}", exc_info=True)
            raise
    
    async def broadcast_message(self, message: Dict[str, Any]):
        """Broadcast message to all connected WebSocket clients"""
        disconnected = []
        for ws in self.active_websockets:
            try:
                await ws.send_json(message)
            except Exception:
                disconnected.append(ws)
        
        for ws in disconnected:
            self.active_websockets.remove(ws)
    
    def update_tool_status(self, name: str, status: str, progress: float = None, output: str = None):
        """Update tool status and broadcast to clients"""
        self.tool_statuses[name] = ToolStatus(
            name=name,
            status=status,
            progress=progress,
            output=output
        )


# Global application state
app_state = AppState()


# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logger.info("🛡️ Aegis AI v9.0 'Nexus' starting up...")
    
    # Initialize agent on startup
    try:
        await app_state.initialize_agent()
    except Exception as e:
        logger.warning(f"Agent initialization deferred: {e}")
    
    yield
    
    # Cleanup on shutdown
    logger.info("🛡️ Aegis AI shutting down...")
    
    try:
        from utils.keep_alive import stop_keep_alive
        stop_keep_alive()
    except Exception:
        pass
    
    try:
        from utils.database_manager import get_database
        db = get_database()
        db.close()
    except Exception:
        pass


app = FastAPI(
    title="Aegis AI v9.0 Nexus",
    description="State-of-the-Art Autonomous Penetration Testing Agent",
    version="9.0.0",
    lifespan=lifespan
)

# CORS origins from environment (default to localhost for development)
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:8000").split(",")

# CORS middleware for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,  # Configure via CORS_ORIGINS env var for production
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


# ============================================================================
# REST API ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint - health check"""
    return {
        "status": "online",
        "name": "Aegis AI v9.0 Nexus",
        "version": "9.0.0",
        "agent_initialized": app_state.agent_initialized
    }


@app.get("/api/status")
async def get_status():
    """Get current agent status"""
    return {
        "initialized": app_state.agent_initialized,
        "mode": app_state.current_mode.value,
        "mission_active": app_state.mission_config is not None,
        "connected_clients": len(app_state.active_websockets),
        "active_tools": len([t for t in app_state.tool_statuses.values() if t.status == "running"]),
        "mcp_servers": len(app_state.mcp_servers)
    }


# ---- Mode Management ----

@app.get("/api/modes")
async def get_modes():
    """Get available operation modes"""
    return {
        "modes": [
            {"id": m.value, "name": m.name.replace("_", " ").title()}
            for m in OperationMode
        ],
        "current": app_state.current_mode.value
    }


@app.post("/api/modes/{mode}")
async def set_mode(mode: OperationMode):
    """Switch operation mode"""
    app_state.current_mode = mode
    
    # Broadcast mode change to all clients
    await app_state.broadcast_message({
        "type": "mode_change",
        "mode": mode.value
    })
    
    logger.info(f"🎯 Mode switched to: {mode.value}")
    
    return {"status": "ok", "mode": mode.value}


# ---- Mission Management ----

@app.post("/api/mission/start")
async def start_mission(config: MissionConfig):
    """Start a new mission"""
    if not app_state.agent_initialized:
        raise HTTPException(status_code=503, detail="Agent not initialized")
    
    app_state.mission_config = config
    app_state.current_mode = config.mode
    
    # Add to chat history
    app_state.chat_history.append({
        "role": "system",
        "content": f"Mission started: Target={config.target}, Mode={config.mode.value}",
        "timestamp": time.time()
    })
    
    await app_state.broadcast_message({
        "type": "mission_start",
        "target": config.target,
        "mode": config.mode.value
    })
    
    return {"status": "started", "config": config.dict()}


@app.post("/api/mission/stop")
async def stop_mission():
    """Stop the current mission"""
    app_state.mission_config = None
    
    await app_state.broadcast_message({
        "type": "mission_stop"
    })
    
    return {"status": "stopped"}


# ---- Tool Status ----

@app.get("/api/tools/status")
async def get_tool_statuses():
    """Get status of all active tools"""
    return {
        "tools": [t.dict() for t in app_state.tool_statuses.values()]
    }


# ---- Swarm Monitor ----

@app.get("/api/swarm/decisions")
async def get_swarm_decisions():
    """Get recent swarm decisions (RED/BLUE/JUDGE)"""
    return {
        "decisions": [d.dict() for d in app_state.swarm_decisions[-20:]]
    }


# ---- MCP Server Management ----

@app.get("/api/mcp/servers")
async def list_mcp_servers():
    """List configured MCP servers"""
    return {
        "servers": [
            {
                "name": name,
                "endpoint": config.endpoint,
                "enabled": config.enabled,
                "tools": await get_mcp_server_tools(name) if config.enabled else []
            }
            for name, config in app_state.mcp_servers.items()
        ]
    }


async def get_mcp_server_tools(server_name: str) -> List[Dict[str, Any]]:
    """Get tools from an MCP server"""
    if not app_state.mcp_client:
        return []
    
    try:
        return await app_state.mcp_client.list_tools(server_name)
    except Exception as e:
        logger.error(f"Failed to get tools from MCP server {server_name}: {e}")
        return []


@app.post("/api/mcp/connect")
async def connect_mcp_server(config: MCPServerConfig):
    """Connect to a new MCP server"""
    try:
        if not app_state.mcp_client:
            from agents.mcp_client import DynamicMCPClient
            app_state.mcp_client = DynamicMCPClient()
        
        # Connect to the MCP server
        await app_state.mcp_client.connect(config.name, config.endpoint)
        
        # Store configuration
        app_state.mcp_servers[config.name] = config
        
        # Get available tools
        tools = await app_state.mcp_client.list_tools(config.name)
        
        # Broadcast to clients
        await app_state.broadcast_message({
            "type": "mcp_connected",
            "server": config.name,
            "tools_count": len(tools)
        })
        
        logger.info(f"🔌 Connected to MCP server: {config.name} ({len(tools)} tools)")
        
        return {
            "status": "connected",
            "server": config.name,
            "tools": tools
        }
        
    except Exception as e:
        logger.error(f"Failed to connect to MCP server: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/mcp/servers/{server_name}")
async def disconnect_mcp_server(server_name: str):
    """Disconnect from an MCP server"""
    if server_name not in app_state.mcp_servers:
        raise HTTPException(status_code=404, detail="Server not found")
    
    try:
        if app_state.mcp_client:
            await app_state.mcp_client.disconnect(server_name)
        
        del app_state.mcp_servers[server_name]
        
        await app_state.broadcast_message({
            "type": "mcp_disconnected",
            "server": server_name
        })
        
        return {"status": "disconnected"}
        
    except Exception as e:
        logger.error(f"Failed to disconnect MCP server: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ---- File Upload ----

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    """Upload a file for analysis"""
    try:
        # Validate file type - security-focused list
        # Analysis files (source code, docs, configs)
        safe_extensions = {
            '.txt', '.json', '.xml', '.html', '.css', '.js', '.py',
            '.php', '.java', '.c', '.cpp', '.h', '.md', '.yaml', '.yml',
            '.log', '.csv', '.sql', '.sh', '.rb', '.go', '.rs'
        }
        # Image files for visual analysis
        image_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg'}
        # Document files
        doc_extensions = {'.pdf', '.doc', '.docx'}
        # Network captures (for forensics)
        network_extensions = {'.pcap', '.pcapng'}
        
        allowed_extensions = safe_extensions | image_extensions | doc_extensions | network_extensions
        
        # Note: Binary executables (.exe, .dll, .so, .elf, .bin) are intentionally excluded
        # for security. For binary analysis, use the CLI mode or specific binary tools.
        
        file_ext = Path(file.filename).suffix.lower()
        if file_ext not in allowed_extensions:
            raise HTTPException(
                status_code=400, 
                detail=f"File type {file_ext} not allowed. For binary analysis, use CLI mode."
            )
        
        # Validate filename for path traversal
        if ".." in file.filename or "/" in file.filename or "\\" in file.filename:
            raise HTTPException(
                status_code=400,
                detail="Invalid filename"
            )
        
        # Save file with sanitized name
        file_id = str(uuid.uuid4())[:8]
        # Only keep alphanumeric, dots, underscores and hyphens in filename
        import re
        safe_basename = re.sub(r'[^a-zA-Z0-9._-]', '_', Path(file.filename).name)
        safe_filename = f"{file_id}_{safe_basename}"
        file_path = UPLOADS_DIR / safe_filename
        
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        logger.info(f"📁 File uploaded: {safe_filename}")
        
        return {
            "status": "uploaded",
            "filename": safe_filename,
            "path": str(file_path),
            "size": len(content)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File upload failed: {e}")
        raise HTTPException(status_code=500, detail="File upload failed")


# ---- Chat History ----

@app.get("/api/chat/history")
async def get_chat_history():
    """Get chat history"""
    return {
        "messages": app_state.chat_history[-100:]  # Last 100 messages
    }


@app.delete("/api/chat/history")
async def clear_chat_history():
    """Clear chat history"""
    app_state.chat_history = []
    return {"status": "cleared"}


# ============================================================================
# WEBSOCKET ENDPOINTS
# ============================================================================

@app.websocket("/ws/chat")
async def websocket_chat(websocket: WebSocket):
    """WebSocket endpoint for real-time chat"""
    await websocket.accept()
    app_state.active_websockets.append(websocket)
    
    logger.info(f"🔗 WebSocket client connected ({len(app_state.active_websockets)} active)")
    
    try:
        # Send initial status
        await websocket.send_json({
            "type": "connected",
            "agent_initialized": app_state.agent_initialized,
            "mode": app_state.current_mode.value
        })
        
        while True:
            # Receive message from client
            data = await websocket.receive_json()
            
            if data.get("type") == "chat":
                await handle_chat_message(websocket, data)
            elif data.get("type") == "command":
                await handle_command(websocket, data)
            elif data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
            
    except WebSocketDisconnect:
        logger.info("🔌 WebSocket client disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        if websocket in app_state.active_websockets:
            app_state.active_websockets.remove(websocket)


async def handle_chat_message(websocket: WebSocket, data: Dict[str, Any]):
    """Handle incoming chat message"""
    content = data.get("content", "")
    
    if not content:
        return
    
    # Add user message to history
    user_msg = {
        "role": "user",
        "content": content,
        "timestamp": time.time()
    }
    app_state.chat_history.append(user_msg)
    
    # Broadcast user message
    await app_state.broadcast_message({
        "type": "chat",
        "role": "user",
        "content": content,
        "timestamp": user_msg["timestamp"]
    })
    
    # Process with AI if initialized
    if app_state.agent_initialized and app_state.ai_core:
        try:
            # Send thinking indicator
            await websocket.send_json({
                "type": "thinking",
                "status": True
            })
            
            # Get AI response
            response = await process_ai_message(content)
            
            # Add AI response to history
            ai_msg = {
                "role": "assistant",
                "content": response,
                "timestamp": time.time()
            }
            app_state.chat_history.append(ai_msg)
            
            # Broadcast AI response
            await app_state.broadcast_message({
                "type": "chat",
                "role": "assistant",
                "content": response,
                "timestamp": ai_msg["timestamp"]
            })
            
        except Exception as e:
            logger.error(f"AI processing error: {e}")
            await websocket.send_json({
                "type": "error",
                "message": str(e)
            })
        finally:
            await websocket.send_json({
                "type": "thinking",
                "status": False
            })
    else:
        # Agent not initialized - queue message
        await websocket.send_json({
            "type": "info",
            "message": "Agent initializing... Your message has been queued."
        })


async def process_ai_message(content: str) -> str:
    """Process message with AI core"""
    if not app_state.ai_core:
        return "Agent not initialized. Please wait..."
    
    try:
        # Triage the mission or process as conversation
        conversation_history = [
            {"role": m["role"], "content": m["content"]}
            for m in app_state.chat_history[-10:]
        ]
        
        result = await app_state.ai_core.triage_mission(conversation_history)
        
        if result.get("response_type") == "start_mission":
            # Mission is ready to start
            config = MissionConfig(
                target=result.get("target", ""),
                rules=result.get("rules", ""),
                mode=app_state.current_mode
            )
            app_state.mission_config = config
            return f"🚀 Mission initialized!\n\n**Target:** {config.target}\n**Rules:** {config.rules}\n\nReady to begin reconnaissance. Type 'start' to proceed."
        
        elif result.get("response_type") == "question":
            return result.get("text", "Could you provide more details?")
        
        else:
            return result.get("text", str(result))
            
    except Exception as e:
        logger.error(f"AI message processing error: {e}", exc_info=True)
        return f"Error processing message: {str(e)}"


async def handle_command(websocket: WebSocket, data: Dict[str, Any]):
    """Handle command from client"""
    command = data.get("command", "")
    
    if command == "start":
        await start_autonomous_scan(websocket)
    elif command == "stop":
        await websocket.send_json({
            "type": "info",
            "message": "Stopping current operation..."
        })
    elif command == "status":
        await websocket.send_json({
            "type": "status",
            "data": {
                "mode": app_state.current_mode.value,
                "mission_active": app_state.mission_config is not None,
                "tools": [t.dict() for t in app_state.tool_statuses.values()]
            }
        })


async def start_autonomous_scan(websocket: WebSocket):
    """Start autonomous scanning based on mission config"""
    if not app_state.mission_config:
        await websocket.send_json({
            "type": "error",
            "message": "No mission configured. Please provide a target first."
        })
        return
    
    if not app_state.ai_core:
        await websocket.send_json({
            "type": "error",
            "message": "Agent not initialized."
        })
        return
    
    await websocket.send_json({
        "type": "info",
        "message": f"🔍 Starting autonomous scan of {app_state.mission_config.target}..."
    })
    
    # Autonomous scanning would be implemented here
    # For now, we'll simulate the start
    await app_state.broadcast_message({
        "type": "scan_started",
        "target": app_state.mission_config.target
    })


# ============================================================================
# STATIC FILES & FRONTEND SERVING
# ============================================================================

# Serve frontend static files if they exist
frontend_path = SCRIPT_DIR / "frontend" / "dist"
if frontend_path.exists():
    app.mount("/assets", StaticFiles(directory=frontend_path / "assets"), name="assets")
    
    @app.get("/{path:path}")
    async def serve_frontend(path: str):
        """Serve React frontend with path traversal protection"""
        # Security: Prevent directory traversal attacks
        if ".." in path or path.startswith("/"):
            return FileResponse(frontend_path / "index.html")
        
        # Resolve and validate path is within frontend directory
        try:
            file_path = (frontend_path / path).resolve()
            # Ensure resolved path is still within frontend_path
            if not str(file_path).startswith(str(frontend_path.resolve())):
                return FileResponse(frontend_path / "index.html")
            
            if file_path.exists() and file_path.is_file():
                return FileResponse(file_path)
        except (ValueError, OSError):
            pass
        
        return FileResponse(frontend_path / "index.html")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point"""
    import uvicorn
    
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    reload = os.getenv("RELOAD", "false").lower() == "true"
    
    logger.info(f"🛡️ Starting Aegis AI v9.0 Nexus on {host}:{port}")
    
    uvicorn.run(
        "server:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )


if __name__ == "__main__":
    main()
