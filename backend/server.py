"""
Aegis AI - Consolidated FastAPI + WebSocket Server
Provides real-time communication with the agent, MCP integration, and SSE support.
"""

import asyncio
import json
import os
import sys
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
from uuid import uuid4

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File, Form, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, Field
import aiofiles

# Add parent directory to path for importing agent modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Aegis AI Server",
    description="Consolidated FastAPI + WebSocket server for Aegis AI Cybersecurity Agent",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# Data Models
# ============================================================================

class ModeConfig(BaseModel):
    """Configuration for different operation modes"""
    id: str
    name: str
    description: str
    planner_model: str
    coder_model: str
    vision_model: str
    reasoner_model: str
    accent_color: str = "#3b82f6"

class ChatMessage(BaseModel):
    """Chat message model"""
    id: str = Field(default_factory=lambda: str(uuid4()))
    role: str  # 'user' | 'assistant' | 'system'
    content: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    reasoning: Optional[str] = None
    tool_calls: Optional[List[str]] = None
    mode: Optional[str] = None

class CommandRequest(BaseModel):
    """Command request from the UI"""
    command: str
    mode: str = "pro"
    target: Optional[str] = None

class MCPServerConfig(BaseModel):
    """MCP Server configuration"""
    name: str
    url: str
    transport: str = "stdio"  # "stdio" | "sse"
    enabled: bool = True

class ToolRegistration(BaseModel):
    """Tool registration in the unified registry"""
    name: str
    description: str
    category: str
    server: str
    parameters: Dict[str, Any] = {}
    intrusive: bool = False

# ============================================================================
# Global State
# ============================================================================

# Operation modes configuration
OPERATION_MODES: Dict[str, ModeConfig] = {
    "fast": ModeConfig(
        id="fast",
        name="Fast Scan",
        description="Lightweight, uncensored models for rapid reconnaissance and basic targets.",
        planner_model="meta-llama/llama-3.1-8b-instruct",
        coder_model="qwen/qwen-2.5-coder-7b-instruct",
        vision_model="deepseek/deepseek-vl-7b-instruct",
        reasoner_model="mistralai/mistral-nemo-12b-instruct",
        accent_color="#3b82f6"
    ),
    "pro": ModeConfig(
        id="pro",
        name="Pro Operator",
        description="Thinks longer for more accurate results. Optimized for medium-complexity targets.",
        planner_model="nousresearch/hermes-3-llama-3.1-70b",
        coder_model="qwen/qwen-2.5-72b-instruct",
        vision_model="qwen/qwen2.5-vl-32b-instruct:free",
        reasoner_model="cognitivecomputations/dolphin3.0-r1-mistral-24b",
        accent_color="#a855f7"
    ),
    "deep": ModeConfig(
        id="deep",
        name="Deep-Think",
        description="Solves complex logic problems. Best for long-term strategic analysis.",
        planner_model="deepseek/deepseek-r1",
        coder_model="qwen/qwen-2.5-72b-instruct",
        vision_model="qwen/qwen2.5-vl-32b-instruct:free",
        reasoner_model="deepseek/deepseek-r1",
        accent_color="#ef4444"
    )
}

# Active WebSocket connections
active_connections: Dict[str, WebSocket] = {}

# Chat history
chat_history: List[Dict[str, Any]] = []

# MCP Server registry
mcp_servers: Dict[str, MCPServerConfig] = {}

# Unified tool registry
tool_registry: Dict[str, ToolRegistration] = {}

# Mission state
mission_state: Dict[str, Any] = {
    "active": False,
    "target": None,
    "mode": "pro",
    "progress": 0,
    "current_step": "",
    "findings": [],
    "tools_used": [],
    "start_time": None
}

# ============================================================================
# WebSocket Connection Manager
# ============================================================================

class ConnectionManager:
    """Manages WebSocket connections"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
    
    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket
        logger.info(f"Client {client_id} connected. Total connections: {len(self.active_connections)}")
    
    def disconnect(self, client_id: str):
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            logger.info(f"Client {client_id} disconnected. Total connections: {len(self.active_connections)}")
    
    async def send_message(self, message: Dict[str, Any], client_id: str):
        if client_id in self.active_connections:
            try:
                await self.active_connections[client_id].send_json(message)
            except Exception as e:
                logger.error(f"Error sending message to {client_id}: {e}")
                self.disconnect(client_id)
    
    async def broadcast(self, message: Dict[str, Any]):
        disconnected = []
        for client_id, connection in self.active_connections.items():
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting to {client_id}: {e}")
                disconnected.append(client_id)
        
        for client_id in disconnected:
            self.disconnect(client_id)

manager = ConnectionManager()

# ============================================================================
# API Routes
# ============================================================================

@app.get("/")
async def root():
    return {
        "message": "Aegis AI Server",
        "version": "1.0.0",
        "status": "online"
    }

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "connections": len(manager.active_connections)
    }

# ============================================================================
# Mode Configuration Routes
# ============================================================================

@app.get("/api/modes")
async def get_modes():
    """Get all available operation modes"""
    return {
        "modes": [
            {
                "id": mode.id,
                "name": mode.name,
                "description": mode.description,
                "accentColor": mode.accent_color
            }
            for mode in OPERATION_MODES.values()
        ]
    }

@app.get("/api/modes/{mode_id}")
async def get_mode(mode_id: str):
    """Get specific mode configuration"""
    if mode_id not in OPERATION_MODES:
        raise HTTPException(status_code=404, detail=f"Mode '{mode_id}' not found")
    
    mode = OPERATION_MODES[mode_id]
    return {
        "id": mode.id,
        "name": mode.name,
        "description": mode.description,
        "planner_model": mode.planner_model,
        "coder_model": mode.coder_model,
        "vision_model": mode.vision_model,
        "reasoner_model": mode.reasoner_model,
        "accent_color": mode.accent_color
    }

@app.post("/api/modes/select/{mode_id}")
async def select_mode(mode_id: str):
    """Select an operation mode and update environment variables"""
    if mode_id not in OPERATION_MODES:
        raise HTTPException(status_code=404, detail=f"Mode '{mode_id}' not found")
    
    mode = OPERATION_MODES[mode_id]
    mission_state["mode"] = mode_id
    
    # Update environment variables for the agent
    os.environ["STRATEGIC_MODEL"] = mode.planner_model
    os.environ["CODE_MODEL"] = mode.coder_model
    os.environ["VISUAL_MODEL"] = mode.vision_model
    os.environ["REASONING_MODEL"] = mode.reasoner_model
    
    # Broadcast mode change to all clients
    await manager.broadcast({
        "type": "mode_change",
        "mode": mode_id,
        "config": {
            "planner": mode.planner_model,
            "coder": mode.coder_model,
            "vision": mode.vision_model,
            "reasoner": mode.reasoner_model
        }
    })
    
    logger.info(f"Mode changed to: {mode_id}")
    return {"status": "success", "mode": mode_id}

# ============================================================================
# Chat Routes
# ============================================================================

@app.get("/api/chat/history")
async def get_chat_history():
    """Get chat history"""
    return {"messages": chat_history}

@app.post("/api/chat/message")
async def send_chat_message(request: CommandRequest):
    """Send a message to the agent"""
    # Create user message
    user_message = ChatMessage(
        role="user",
        content=request.command,
        mode=request.mode
    )
    
    chat_history.append(user_message.model_dump())
    
    # Broadcast to all connected clients
    await manager.broadcast({
        "type": "chat_message",
        "message": user_message.model_dump()
    })
    
    # Process the command (this would integrate with the actual agent)
    # For now, we'll simulate a response
    response = await process_command(request)
    
    return {"status": "success", "message_id": user_message.id}

async def process_command(request: CommandRequest):
    """Process a command and send responses via WebSocket"""
    mode = OPERATION_MODES.get(request.mode, OPERATION_MODES["pro"])
    
    # Simulate agent thinking
    await asyncio.sleep(0.5)
    
    # Create assistant message
    assistant_message = ChatMessage(
        role="assistant",
        content=f"Processing: {request.command}",
        reasoning=f"Using {mode.name} mode with {mode.planner_model} for strategic planning.",
        mode=request.mode
    )
    
    chat_history.append(assistant_message.model_dump())
    
    await manager.broadcast({
        "type": "chat_message",
        "message": assistant_message.model_dump()
    })
    
    return assistant_message

@app.delete("/api/chat/history")
async def clear_chat_history():
    """Clear chat history"""
    chat_history.clear()
    await manager.broadcast({"type": "chat_cleared"})
    return {"status": "success"}

# ============================================================================
# File Upload Routes
# ============================================================================

UPLOAD_DIR = Path(__file__).parent.parent / "data" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {
    # Binaries
    ".exe", ".elf", ".bin", ".dll", ".so",
    # Documents
    ".pdf", ".doc", ".docx", ".txt", ".md",
    # Network captures
    ".pcap", ".pcapng", ".cap",
    # Images/Screenshots
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp",
    # Archives
    ".zip", ".tar", ".gz", ".7z",
    # Code
    ".py", ".js", ".html", ".css", ".php", ".rb", ".go", ".rs",
    # Config
    ".json", ".xml", ".yaml", ".yml", ".conf", ".ini"
}

@app.post("/api/upload")
async def upload_file(
    file: UploadFile = File(...),
    file_type: str = Form(default="auto")
):
    """Upload a file for analysis"""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    
    # Check extension
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"File type '{ext}' not allowed. Allowed: {ALLOWED_EXTENSIONS}"
        )
    
    # Generate unique filename
    unique_id = str(uuid4())[:8]
    safe_filename = f"{unique_id}_{file.filename}"
    file_path = UPLOAD_DIR / safe_filename
    
    # Save file
    async with aiofiles.open(file_path, 'wb') as f:
        content = await file.read()
        await f.write(content)
    
    # Determine file category
    if ext in {".exe", ".elf", ".bin", ".dll", ".so"}:
        category = "binary"
    elif ext in {".pcap", ".pcapng", ".cap"}:
        category = "pcap"
    elif ext in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}:
        category = "screenshot"
    elif ext in {".pdf", ".doc", ".docx"}:
        category = "document"
    else:
        category = "other"
    
    # Broadcast file upload notification
    await manager.broadcast({
        "type": "file_uploaded",
        "file": {
            "name": file.filename,
            "path": str(file_path),
            "size": len(content),
            "category": category
        }
    })
    
    logger.info(f"File uploaded: {safe_filename} ({category})")
    
    return {
        "status": "success",
        "file_id": unique_id,
        "filename": safe_filename,
        "path": str(file_path),
        "size": len(content),
        "category": category
    }

@app.get("/api/uploads")
async def list_uploads():
    """List all uploaded files"""
    files = []
    for file_path in UPLOAD_DIR.iterdir():
        if file_path.is_file():
            stat = file_path.stat()
            files.append({
                "name": file_path.name,
                "path": str(file_path),
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
    return {"files": files}

# ============================================================================
# MCP Server Routes
# ============================================================================

@app.get("/api/mcp/servers")
async def get_mcp_servers():
    """Get all registered MCP servers"""
    return {"servers": list(mcp_servers.values())}

@app.post("/api/mcp/servers")
async def register_mcp_server(config: MCPServerConfig):
    """Register a new MCP server"""
    mcp_servers[config.name] = config
    
    await manager.broadcast({
        "type": "mcp_server_registered",
        "server": config.model_dump()
    })
    
    logger.info(f"MCP server registered: {config.name}")
    return {"status": "success", "server": config.model_dump()}

@app.delete("/api/mcp/servers/{server_name}")
async def unregister_mcp_server(server_name: str):
    """Unregister an MCP server"""
    if server_name not in mcp_servers:
        raise HTTPException(status_code=404, detail=f"Server '{server_name}' not found")
    
    del mcp_servers[server_name]
    
    # Remove tools from this server
    tools_to_remove = [
        name for name, tool in tool_registry.items()
        if tool.server == server_name
    ]
    for tool_name in tools_to_remove:
        del tool_registry[tool_name]
    
    await manager.broadcast({
        "type": "mcp_server_unregistered",
        "server_name": server_name
    })
    
    return {"status": "success", "removed_tools": len(tools_to_remove)}

@app.post("/api/mcp/connect/{server_name}")
async def connect_mcp_server(server_name: str):
    """Connect to an MCP server without restarting the agent"""
    if server_name not in mcp_servers:
        raise HTTPException(status_code=404, detail=f"Server '{server_name}' not found")
    
    server = mcp_servers[server_name]
    
    # Simulate connection (in real implementation, this would use the MCP protocol)
    # For now, we'll just mark it as connected
    server.enabled = True
    
    await manager.broadcast({
        "type": "mcp_server_connected",
        "server_name": server_name
    })
    
    logger.info(f"Connected to MCP server: {server_name}")
    return {"status": "success", "message": f"Connected to {server_name}"}

# ============================================================================
# Tool Registry Routes
# ============================================================================

@app.get("/api/tools")
async def get_tools():
    """Get all registered tools from the unified registry"""
    return {"tools": list(tool_registry.values())}

@app.post("/api/tools")
async def register_tool(tool: ToolRegistration):
    """Register a tool in the unified registry"""
    tool_registry[tool.name] = tool
    
    await manager.broadcast({
        "type": "tool_registered",
        "tool": tool.model_dump()
    })
    
    return {"status": "success", "tool": tool.model_dump()}

@app.get("/api/tools/categories")
async def get_tool_categories():
    """Get tool categories and counts"""
    categories: Dict[str, int] = {}
    for tool in tool_registry.values():
        categories[tool.category] = categories.get(tool.category, 0) + 1
    return {"categories": categories}

# ============================================================================
# Mission State Routes
# ============================================================================

@app.get("/api/mission/state")
async def get_mission_state():
    """Get current mission state"""
    return mission_state

@app.post("/api/mission/start")
async def start_mission(request: CommandRequest):
    """Start a new mission"""
    mission_state["active"] = True
    mission_state["target"] = request.target
    mission_state["mode"] = request.mode
    mission_state["progress"] = 0
    mission_state["current_step"] = "Initializing..."
    mission_state["findings"] = []
    mission_state["tools_used"] = []
    mission_state["start_time"] = datetime.now(timezone.utc).isoformat()
    
    await manager.broadcast({
        "type": "mission_started",
        "state": mission_state
    })
    
    return {"status": "success", "state": mission_state}

@app.post("/api/mission/stop")
async def stop_mission():
    """Stop current mission"""
    mission_state["active"] = False
    
    await manager.broadcast({
        "type": "mission_stopped",
        "state": mission_state
    })
    
    return {"status": "success"}

# ============================================================================
# SSE (Server-Sent Events) Routes
# ============================================================================

@app.get("/api/events")
async def event_stream():
    """SSE endpoint for real-time events"""
    async def generate():
        while True:
            # Send heartbeat every 30 seconds
            yield f"event: heartbeat\ndata: {json.dumps({'timestamp': datetime.now(timezone.utc).isoformat()})}\n\n"
            await asyncio.sleep(30)
    
    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

# ============================================================================
# WebSocket Endpoints
# ============================================================================

@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """WebSocket endpoint for real-time bidirectional communication"""
    await manager.connect(websocket, client_id)
    
    # Send initial state
    await websocket.send_json({
        "type": "connected",
        "client_id": client_id,
        "mission_state": mission_state,
        "modes": [
            {"id": m.id, "name": m.name, "accentColor": m.accent_color}
            for m in OPERATION_MODES.values()
        ]
    })
    
    try:
        while True:
            data = await websocket.receive_json()
            
            # Handle different message types
            if data.get("type") == "chat":
                # Process chat message
                request = CommandRequest(
                    command=data.get("content", ""),
                    mode=data.get("mode", "pro"),
                    target=data.get("target")
                )
                await send_chat_message(request)
                
            elif data.get("type") == "mode_change":
                # Change operation mode
                mode_id = data.get("mode_id", "pro")
                await select_mode(mode_id)
                
            elif data.get("type") == "mission_start":
                # Start mission
                request = CommandRequest(
                    command=data.get("command", ""),
                    mode=data.get("mode", "pro"),
                    target=data.get("target")
                )
                await start_mission(request)
                
            elif data.get("type") == "mission_stop":
                # Stop mission
                await stop_mission()
                
            elif data.get("type") == "ping":
                # Respond to ping
                await websocket.send_json({"type": "pong", "timestamp": time.time()})
                
    except WebSocketDisconnect:
        manager.disconnect(client_id)
    except Exception as e:
        logger.error(f"WebSocket error for {client_id}: {e}")
        manager.disconnect(client_id)

# ============================================================================
# Startup/Shutdown Events
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize server on startup"""
    logger.info("Aegis AI Server starting...")
    
    # Register default tools
    default_tools = [
        ToolRegistration(name="nmap", description="Network port scanner", category="reconnaissance", server="local", intrusive=False),
        ToolRegistration(name="nikto", description="Web server scanner", category="reconnaissance", server="local", intrusive=True),
        ToolRegistration(name="sqlmap", description="SQL injection tool", category="exploitation", server="local", intrusive=True),
        ToolRegistration(name="dirsearch", description="Directory enumeration", category="reconnaissance", server="local", intrusive=False),
        ToolRegistration(name="ffuf", description="Fast web fuzzer", category="fuzzing", server="local", intrusive=True),
    ]
    
    for tool in default_tools:
        tool_registry[tool.name] = tool
    
    logger.info(f"Registered {len(default_tools)} default tools")
    logger.info("Aegis AI Server started successfully")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("Aegis AI Server shutting down...")
    
    # Close all WebSocket connections
    for client_id in list(manager.active_connections.keys()):
        try:
            await manager.active_connections[client_id].close()
        except Exception:
            pass
        manager.disconnect(client_id)
    
    logger.info("Aegis AI Server shutdown complete")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
