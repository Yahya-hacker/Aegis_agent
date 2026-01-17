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

Security Features:
- Magic byte (file signature) verification for uploads
- Path traversal protection
- Filename sanitization
"""

import asyncio
import json
import logging
import os
import re
import sys
import time
import uuid
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File, Depends
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
# Location of built frontend assets (Vite build output)
FRONTEND_DIST = SCRIPT_DIR / "frontend" / "dist"

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
# FILE SIGNATURE (MAGIC BYTE) VERIFICATION
# ============================================================================

# Magic byte signatures for common file types
# Format: extension -> (magic_bytes, offset)
# Reference: https://en.wikipedia.org/wiki/List_of_file_signatures
FILE_SIGNATURES: Dict[str, List[tuple]] = {
    # Images
    '.png': [(b'\x89PNG\r\n\x1a\n', 0)],
    '.jpg': [(b'\xff\xd8\xff', 0)],
    '.jpeg': [(b'\xff\xd8\xff', 0)],
    '.gif': [(b'GIF87a', 0), (b'GIF89a', 0)],
    '.bmp': [(b'BM', 0)],
    '.webp': [(b'RIFF', 0)],  # WebP is RIFF-based
    
    # Documents
    '.pdf': [(b'%PDF', 0)],
    '.doc': [(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 0)],  # OLE compound
    '.docx': [(b'PK\x03\x04', 0)],  # ZIP-based (Office Open XML)
    '.xlsx': [(b'PK\x03\x04', 0)],
    '.pptx': [(b'PK\x03\x04', 0)],
    
    # Archives
    '.zip': [(b'PK\x03\x04', 0), (b'PK\x05\x06', 0)],
    '.gz': [(b'\x1f\x8b', 0)],
    '.tar': [(b'ustar', 257)],  # ustar at offset 257
    
    # Network captures
    '.pcap': [(b'\xd4\xc3\xb2\xa1', 0), (b'\xa1\xb2\xc3\xd4', 0)],
    '.pcapng': [(b'\x0a\x0d\x0d\x0a', 0)],
    
    # Executables (blocked but checked for masquerading detection)
    '.exe': [(b'MZ', 0)],
    '.dll': [(b'MZ', 0)],
    '.elf': [(b'\x7fELF', 0)],
    '.so': [(b'\x7fELF', 0)],
}

# Text-based extensions that don't have magic bytes
TEXT_EXTENSIONS = {
    '.txt', '.json', '.xml', '.html', '.css', '.js', '.py',
    '.php', '.java', '.c', '.cpp', '.h', '.md', '.yaml', '.yml',
    '.log', '.csv', '.sql', '.sh', '.rb', '.go', '.rs', '.svg',
    '.ts', '.tsx', '.jsx', '.vue', '.scss', '.less'
}


def verify_file_signature(content: bytes, claimed_extension: str) -> tuple[bool, Optional[str]]:
    """
    Verify that file content matches the claimed file extension using magic bytes.
    
    This function detects file masquerading attacks where a malicious file
    (e.g., executable) is renamed to appear as a safe file type (e.g., .txt).
    
    Args:
        content: The file content bytes
        claimed_extension: The file extension claimed by the filename (e.g., '.png')
        
    Returns:
        Tuple of (is_valid, detected_type_or_error_message)
        - (True, None) if file is valid text or matches signature
        - (True, detected_type) if file matches its claimed signature
        - (False, error_message) if file signature doesn't match extension
    """
    ext_lower = claimed_extension.lower()
    
    # Text files don't have magic bytes - check they're not executables
    if ext_lower in TEXT_EXTENSIONS:
        # Check if content starts with executable signatures (masquerading detection)
        dangerous_signatures = [
            (b'MZ', 'Windows executable'),
            (b'\x7fELF', 'Linux executable'),
            (b'\xca\xfe\xba\xbe', 'macOS Mach-O'),
            (b'\xfe\xed\xfa\xce', 'macOS Mach-O'),
            (b'\xfe\xed\xfa\xcf', 'macOS Mach-O 64-bit'),
        ]
        
        for sig, file_type in dangerous_signatures:
            if content.startswith(sig):
                return False, f"File masquerading detected: content is {file_type}, not {ext_lower}"
        
        # For text files, try to verify it's actually text
        try:
            # Check first 8KB for text validity (utf-8 or ascii-ish)
            sample = content[:8192]
            # Allow some non-printable chars (newlines, tabs, etc) but flag binary
            text_chars = set(range(32, 127)) | {9, 10, 13}  # printable + tab, newline, cr
            
            # Efficient early-exit binary detection
            # Break early if threshold exceeded to avoid scanning entire sample
            binary_chars = 0
            threshold = 0.30
            for i, b in enumerate(sample):
                if b not in text_chars:
                    binary_chars += 1
                    # Check threshold periodically (every 100 bytes after first 100)
                    if i > 100 and i % 100 == 0:
                        if binary_chars / (i + 1) > threshold:
                            return False, f"File appears to be binary, not text ({ext_lower})"
            
            # Final check after processing all bytes
            if len(sample) > 0 and (binary_chars / len(sample)) > threshold:
                return False, f"File appears to be binary, not text ({ext_lower})"
        except Exception:
            pass
        
        return True, None
    
    # Check magic bytes for known binary formats
    if ext_lower in FILE_SIGNATURES:
        signatures = FILE_SIGNATURES[ext_lower]
        
        for magic_bytes, offset in signatures:
            if len(content) > offset + len(magic_bytes):
                if content[offset:offset + len(magic_bytes)] == magic_bytes:
                    return True, ext_lower
        
        # No signature matched - check if it's masquerading
        # Try to detect what the file actually is
        detected_type = detect_file_type(content)
        if detected_type:
            return False, f"File signature mismatch: claims to be {ext_lower} but appears to be {detected_type}"
        
        return False, f"File does not have valid {ext_lower} signature"
    
    # Unknown extension - allow but warn
    logger.warning(f"No signature check available for extension: {ext_lower}")
    return True, None


def detect_file_type(content: bytes) -> Optional[str]:
    """
    Attempt to detect the actual file type from magic bytes.
    
    Args:
        content: File content bytes
        
    Returns:
        Detected file type string or None
    """
    # Check against known signatures
    detections = [
        (b'MZ', 'Windows executable (.exe/.dll)'),
        (b'\x7fELF', 'Linux executable (.elf/.so)'),
        (b'\xca\xfe\xba\xbe', 'macOS executable'),
        (b'\x89PNG\r\n\x1a\n', '.png image'),
        (b'\xff\xd8\xff', '.jpg image'),
        (b'GIF8', '.gif image'),
        (b'%PDF', '.pdf document'),
        (b'PK\x03\x04', '.zip archive or Office document'),
        (b'\xd4\xc3\xb2\xa1', '.pcap network capture'),
    ]
    
    for signature, file_type in detections:
        if content.startswith(signature):
            return file_type
    
    return None


# ============================================================================
# STATE ABSTRACTION LAYER (Repository Pattern)
# ============================================================================

class ChatHistoryRepository(ABC):
    """Abstract interface for chat history storage."""
    
    @abstractmethod
    async def add_message(self, message: Dict[str, Any]) -> None:
        """Add a message to chat history."""
        pass
    
    @abstractmethod
    async def get_messages(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent messages from chat history."""
        pass
    
    @abstractmethod
    async def clear(self) -> None:
        """Clear all chat history."""
        pass


class ToolStatusRepository(ABC):
    """Abstract interface for tool status storage."""
    
    @abstractmethod
    async def update_status(self, name: str, status: 'ToolStatus') -> None:
        """Update status of a tool."""
        pass
    
    @abstractmethod
    async def get_status(self, name: str) -> Optional['ToolStatus']:
        """Get status of a specific tool."""
        pass
    
    @abstractmethod
    async def get_all_statuses(self) -> Dict[str, 'ToolStatus']:
        """Get all tool statuses."""
        pass


class InMemoryChatHistoryRepository(ChatHistoryRepository):
    """
    In-memory implementation of chat history repository.
    
    Designed to be easily swapped for Redis/Database implementations.
    """
    
    def __init__(self, max_messages: int = 1000):
        self._messages: List[Dict[str, Any]] = []
        self._max_messages = max_messages
    
    async def add_message(self, message: Dict[str, Any]) -> None:
        """Add a message, maintaining max size."""
        self._messages.append(message)
        if len(self._messages) > self._max_messages:
            self._messages = self._messages[-self._max_messages:]
    
    async def get_messages(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get the most recent messages."""
        return self._messages[-limit:]
    
    async def clear(self) -> None:
        """Clear all messages."""
        self._messages = []


class InMemoryToolStatusRepository(ToolStatusRepository):
    """
    In-memory implementation of tool status repository.
    
    Designed to be easily swapped for Redis/Database implementations.
    """
    
    def __init__(self):
        self._statuses: Dict[str, 'ToolStatus'] = {}
    
    async def update_status(self, name: str, status: 'ToolStatus') -> None:
        """Update tool status."""
        self._statuses[name] = status
    
    async def get_status(self, name: str) -> Optional['ToolStatus']:
        """Get status of a specific tool."""
        return self._statuses.get(name)
    
    async def get_all_statuses(self) -> Dict[str, 'ToolStatus']:
        """Get all tool statuses."""
        return self._statuses.copy()


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
# APPLICATION STATE INTERFACE & IMPLEMENTATION
# ============================================================================

class AgentStateInterface(ABC):
    """
    Abstract interface for agent state management.
    
    This interface enables horizontal scaling by abstracting the storage layer.
    Implementations can use in-memory storage (default), Redis, or databases.
    """
    
    @abstractmethod
    async def get_chat_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get chat history."""
        pass
    
    @abstractmethod
    async def add_chat_message(self, message: Dict[str, Any]) -> None:
        """Add a chat message."""
        pass
    
    @abstractmethod
    async def clear_chat_history(self) -> None:
        """Clear chat history."""
        pass
    
    @abstractmethod
    async def update_tool_status(self, name: str, status: str, 
                                  progress: Optional[float] = None, 
                                  output: Optional[str] = None) -> None:
        """Update tool status."""
        pass
    
    @abstractmethod
    async def get_tool_statuses(self) -> Dict[str, ToolStatus]:
        """Get all tool statuses."""
        pass


class AppState(AgentStateInterface):
    """
    Application state manager with repository pattern.
    
    Uses Set for WebSocket tracking (O(1) operations) and repository
    pattern for chat/tool storage to enable easy swapping to Redis/DB.
    
    Attributes:
        active_websockets: Set of connected WebSocket clients (O(1) add/remove)
        chat_repository: Repository for chat history storage
        tool_repository: Repository for tool status storage
    """
    
    def __init__(self):
        """Initialize application state with repositories."""
        # Use Set for O(1) WebSocket operations
        self.active_websockets: Set[WebSocket] = set()
        self._websocket_lock = asyncio.Lock()  # Thread-safe WebSocket management
        
        # Operation mode and mission
        self.current_mode: OperationMode = OperationMode.PENETRATION_TESTING
        self.mission_config: Optional[MissionConfig] = None
        
        # Repository pattern for scalable storage
        self._chat_repository = InMemoryChatHistoryRepository()
        self._tool_repository = InMemoryToolStatusRepository()
        
        # Swarm decisions (could also be moved to repository)
        self.swarm_decisions: List[SwarmDecision] = []
        
        # MCP server configurations
        self.mcp_servers: Dict[str, MCPServerConfig] = {}
        
        # Agent components
        self.agent_initialized: bool = False
        self.ai_core = None
        self.conversation = None
        self.learning_engine = None
        self.mcp_client = None
    
    # ---- Chat History (Repository Pattern) ----
    
    async def get_chat_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get chat history from repository."""
        return await self._chat_repository.get_messages(limit)
    
    async def add_chat_message(self, message: Dict[str, Any]) -> None:
        """Add a chat message to repository."""
        await self._chat_repository.add_message(message)
    
    async def clear_chat_history(self) -> None:
        """Clear chat history in repository."""
        await self._chat_repository.clear()
    
    # ---- Tool Status (Repository Pattern) ----
    
    async def update_tool_status(self, name: str, status: str, 
                                  progress: Optional[float] = None, 
                                  output: Optional[str] = None) -> None:
        """Update tool status in repository."""
        tool_status = ToolStatus(
            name=name,
            status=status,
            progress=progress,
            output=output
        )
        await self._tool_repository.update_status(name, tool_status)
    
    async def get_tool_statuses(self) -> Dict[str, ToolStatus]:
        """Get all tool statuses from repository."""
        return await self._tool_repository.get_all_statuses()
    
    # ---- Backward Compatibility Properties ----
    
    @property
    def chat_history(self) -> List[Dict[str, Any]]:
        """Backward compatible sync access to chat history."""
        return self._chat_repository._messages
    
    @property
    def tool_statuses(self) -> Dict[str, ToolStatus]:
        """Backward compatible sync access to tool statuses."""
        return self._tool_repository._statuses
    
    # ---- WebSocket Management (O(1) with Set) ----
    
    async def add_websocket(self, ws: WebSocket) -> None:
        """Add a WebSocket connection (O(1) operation)."""
        async with self._websocket_lock:
            self.active_websockets.add(ws)
    
    async def remove_websocket(self, ws: WebSocket) -> None:
        """Remove a WebSocket connection (O(1) operation)."""
        async with self._websocket_lock:
            self.active_websockets.discard(ws)
    
    async def broadcast_message(self, message: Dict[str, Any]) -> None:
        """
        Broadcast message to all connected WebSocket clients.
        
        Handles disconnected clients robustly to prevent zombie connections.
        """
        disconnected: Set[WebSocket] = set()
        
        # Create a copy of the set to iterate over
        async with self._websocket_lock:
            websockets_copy = self.active_websockets.copy()
        
        for ws in websockets_copy:
            try:
                await ws.send_json(message)
            except Exception as e:
                logger.debug(f"WebSocket send failed, marking for removal: {e}")
                disconnected.add(ws)
        
        # Clean up disconnected websockets
        if disconnected:
            async with self._websocket_lock:
                self.active_websockets -= disconnected
            logger.info(f"🧹 Cleaned up {len(disconnected)} disconnected WebSocket(s)")
    
    # ---- Sync helper for backward compatibility ----
    
    def update_tool_status_sync(self, name: str, status: str, 
                                 progress: Optional[float] = None, 
                                 output: Optional[str] = None) -> None:
        """Synchronous tool status update for backward compatibility."""
        tool_status = ToolStatus(
            name=name,
            status=status,
            progress=progress,
            output=output
        )
        self._tool_repository._statuses[name] = tool_status
    
    # ---- Agent Initialization ----
        
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


# Global application state instance
app_state = AppState()


# ============================================================================
# DEPENDENCY INJECTION
# ============================================================================

async def get_app_state() -> AppState:
    """
    FastAPI dependency that provides the application state.
    
    This enables dependency injection for the app state, making it easier
    to swap implementations for testing or horizontal scaling.
    
    Usage:
        @app.get("/api/status")
        async def get_status(state: AppState = Depends(get_app_state)):
            return {"initialized": state.agent_initialized}
    """
    return app_state


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

# CORS origins from environment
# Default allows localhost and Codespaces patterns; use "*" for open development
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")

# CORS middleware for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,  # Configure via CORS_ORIGINS env var for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# REST API ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint - serve UI if built, else return health"""
    index_path = FRONTEND_DIST / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return {
        "status": "online",
        "name": "Aegis AI v9.0 Nexus",
        "version": "9.0.0",
        "agent_initialized": app_state.agent_initialized
    }


@app.get("/health")
async def health():
    """Health check for monitors and CLI"""
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
    """
    Upload a file for analysis with security validation.
    
    Security measures:
    - Extension whitelist validation
    - Magic byte (file signature) verification to prevent masquerading
    - Path traversal protection
    - Filename sanitization
    
    Args:
        file: The uploaded file
        
    Returns:
        JSON with upload status, filename, path, and size
        
    Raises:
        HTTPException: 400 for invalid file type or masquerading
        HTTPException: 500 for server errors
    """
    try:
        # Validate file type - security-focused list
        # Analysis files (source code, docs, configs)
        safe_extensions = {
            '.txt', '.json', '.xml', '.html', '.css', '.js', '.py',
            '.php', '.java', '.c', '.cpp', '.h', '.md', '.yaml', '.yml',
            '.log', '.csv', '.sql', '.sh', '.rb', '.go', '.rs', '.ts',
            '.tsx', '.jsx', '.vue', '.scss', '.less'
        }
        # Image files for visual analysis
        image_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.webp'}
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
                detail="Invalid filename: path traversal detected"
            )
        
        # Read file content for verification
        content = await file.read()
        
        # SECURITY: Magic byte (file signature) verification
        # This prevents malicious file masquerading (e.g., executable disguised as .txt)
        is_valid, error_or_type = verify_file_signature(content, file_ext)
        
        if not is_valid:
            logger.warning(f"🚨 File signature mismatch rejected: {file.filename} - {error_or_type}")
            raise HTTPException(
                status_code=400,
                detail=f"File signature verification failed: {error_or_type}"
            )
        
        # Log if we detected a specific type
        if error_or_type:
            logger.debug(f"File signature verified: {file.filename} is valid {error_or_type}")
        
        # Save file with sanitized name
        file_id = str(uuid.uuid4())[:8]
        # Only keep alphanumeric, dots, underscores and hyphens in filename
        safe_basename = re.sub(r'[^a-zA-Z0-9._-]', '_', Path(file.filename).name)
        safe_filename = f"{file_id}_{safe_basename}"
        file_path = UPLOADS_DIR / safe_filename
        
        with open(file_path, "wb") as f:
            f.write(content)
        
        logger.info(f"📁 File uploaded (verified): {safe_filename} ({len(content)} bytes)")
        
        return {
            "status": "uploaded",
            "filename": safe_filename,
            "path": str(file_path),
            "size": len(content),
            "verified": True
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


# ---- CTF Mode Endpoints ----

@app.post("/api/ctf/configure")
async def configure_ctf(ctf_name: str, flag_format: Optional[str] = None, team_name: Optional[str] = None):
    """Configure CTF mode settings"""
    try:
        from utils.ctf_mode_manager import get_ctf_manager
        
        ctf_manager = get_ctf_manager()
        ctf_manager.set_ctf_config(ctf_name, flag_format, team_name)
        
        return {
            "status": "configured",
            "ctf_name": ctf_name,
            "flag_format": flag_format,
            "team_name": team_name
        }
    except Exception as e:
        logger.error(f"CTF configuration error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/ctf/challenge")
async def add_ctf_challenge(
    challenge_id: str,
    name: str,
    description: str = "",
    domain: Optional[str] = None,
    points: int = 0,
    files: Optional[List[str]] = None,
    url: Optional[str] = None
):
    """Add a CTF challenge"""
    try:
        from utils.ctf_mode_manager import get_ctf_manager, CTFDomain
        
        ctf_manager = get_ctf_manager()
        
        # Convert domain string to enum if provided
        domain_enum = None
        if domain:
            try:
                domain_enum = CTFDomain(domain.lower())
            except ValueError:
                pass
        
        challenge = await ctf_manager.add_challenge(
            challenge_id=challenge_id,
            name=name,
            description=description,
            domain=domain_enum,
            points=points,
            files=files,
            url=url
        )
        
        return {
            "status": "added",
            "challenge": {
                "id": challenge.id,
                "name": challenge.name,
                "domain": challenge.domain.value,
                "points": challenge.points
            }
        }
    except Exception as e:
        logger.error(f"Add challenge error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/ctf/stats")
async def get_ctf_stats():
    """Get CTF progress statistics"""
    try:
        from utils.ctf_mode_manager import get_ctf_manager
        
        ctf_manager = get_ctf_manager()
        return ctf_manager.get_ctf_stats()
    except Exception as e:
        logger.error(f"CTF stats error: {e}", exc_info=True)
        return {"error": "Failed to retrieve CTF statistics"}


@app.get("/api/ctf/tools/{challenge_id}")
async def get_ctf_recommended_tools(challenge_id: str):
    """Get recommended tools for a CTF challenge"""
    try:
        from utils.ctf_mode_manager import get_ctf_manager
        
        ctf_manager = get_ctf_manager()
        tools = ctf_manager.get_recommended_tools(challenge_id)
        
        return {
            "challenge_id": challenge_id,
            "recommended_tools": tools
        }
    except Exception as e:
        logger.error(f"Get recommended tools error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ---- Dynamic Tool Generation Endpoints ----

@app.get("/api/tools/generated")
async def list_generated_tools():
    """List dynamically generated tools"""
    try:
        from utils.dynamic_tool_generator import get_tool_generator
        
        generator = get_tool_generator()
        return {
            "tools": generator.get_available_tools()
        }
    except Exception as e:
        logger.error(f"List generated tools error: {e}", exc_info=True)
        return {"tools": [], "error": "Failed to list generated tools"}


@app.post("/api/tools/generate")
async def generate_custom_tool(
    task_description: str,
    input_schema: Optional[Dict[str, Any]] = None
):
    """Generate a custom tool dynamically"""
    try:
        from utils.dynamic_tool_generator import get_tool_generator
        
        generator = get_tool_generator(app_state.ai_core)
        tool = await generator.generate_tool(
            task_description=task_description,
            input_schema=input_schema
        )
        
        return {
            "status": "generated",
            "tool": {
                "name": tool.name,
                "description": tool.description,
                "category": tool.category,
                "version": tool.version
            }
        }
    except Exception as e:
        logger.error(f"Generate tool error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ---- Parallel Execution Endpoints ----

@app.post("/api/parallel/targets")
async def add_parallel_targets(targets: List[str]):
    """Add multiple targets for parallel scanning"""
    try:
        from utils.parallel_executor import get_multi_target_manager
        
        manager = get_multi_target_manager()
        
        for target in targets:
            await manager.add_target(target)
        
        return {
            "status": "added",
            "targets_count": len(targets),
            "progress": manager.get_all_progress()
        }
    except Exception as e:
        logger.error(f"Add parallel targets error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/parallel/progress")
async def get_parallel_progress():
    """Get progress of parallel scanning"""
    try:
        from utils.parallel_executor import get_multi_target_manager
        
        manager = get_multi_target_manager()
        return manager.get_all_progress()
    except Exception as e:
        logger.error(f"Get parallel progress error: {e}", exc_info=True)
        return {"error": "Failed to get parallel progress"}


# ============================================================================
# WEBSOCKET ENDPOINTS
# ============================================================================

@app.websocket("/ws/chat")
async def websocket_chat(websocket: WebSocket):
    """
    WebSocket endpoint for real-time chat with robust connection handling.
    
    Uses Set-based storage for O(1) connection management and handles
    disconnections gracefully to prevent zombie connections.
    """
    await websocket.accept()
    
    # Add to Set (O(1) operation)
    await app_state.add_websocket(websocket)
    
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
        logger.info("🔌 WebSocket client disconnected gracefully")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        # Remove from Set (O(1) operation) - handles missing entries gracefully
        await app_state.remove_websocket(websocket)
        logger.debug(f"WebSocket cleanup complete ({len(app_state.active_websockets)} remaining)")


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
    
    # Check if user is trying to start the mission
    content_lower = content.strip().lower().strip("'\"")
    if content_lower == "start" and app_state.mission_config:
        # User wants to start - trigger autonomous scan
        await start_autonomous_scan(websocket)
        return
    
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
    
    target = app_state.mission_config.target
    rules = app_state.mission_config.rules
    mode = app_state.current_mode.value
    
    # Notify clients scan is starting
    await app_state.broadcast_message({
        "type": "scan_started",
        "target": target,
        "mode": mode
    })
    
    # Send initial message
    start_msg = f"🔍 Starting autonomous reconnaissance on **{target}**...\n\n**Mode:** {mode.replace('_', ' ').title()}\n**Rules:** {rules}"
    await app_state.broadcast_message({
        "type": "chat",
        "role": "assistant",
        "content": start_msg,
        "timestamp": time.time()
    })
    app_state.chat_history.append({
        "role": "assistant",
        "content": start_msg,
        "timestamp": time.time()
    })
    
    # Set domain context based on mode
    if hasattr(app_state.ai_core, 'orchestrator'):
        mode_to_context = {
            "penetration_testing": "Web",
            "ctf_mode": "CTF",
            "red_teaming": "Binary",
            "audit": "Web"
        }
        domain_context = mode_to_context.get(mode, "Web")
        app_state.ai_core.orchestrator.set_domain_context(domain_context)
        if hasattr(app_state.ai_core, 'blackboard'):
            app_state.ai_core.blackboard.set_domain_context(domain_context)
    
    # Run autonomous scan loop
    try:
        await run_autonomous_loop(websocket, target, rules, mode)
    except Exception as e:
        logger.error(f"Autonomous scan error: {e}", exc_info=True)
        await app_state.broadcast_message({
            "type": "chat",
            "role": "assistant",
            "content": f"❌ Scan encountered an error: {str(e)}",
            "timestamp": time.time()
        })


async def run_autonomous_loop(websocket: WebSocket, target: str, rules: str, mode: str, max_iterations: int = 20):
    """Run the autonomous scanning loop"""
    from agents.scanner import AegisScanner
    
    # Initialize scanner with AI core
    scanner = AegisScanner(app_state.ai_core)
    
    agent_memory = []
    iteration = 0
    
    # Add mode-specific instructions to rules
    mode_instructions = {
        "penetration_testing": "Focus on web application vulnerabilities. Use standard penetration testing methodology.",
        "ctf_mode": "This is a CTF challenge. Look for flags, hidden files, and creative exploitation paths. Use crypto, forensics, and pwn tools as needed.",
        "red_teaming": "Simulate advanced adversary. Focus on stealth, persistence, and lateral movement opportunities.",
        "audit": "Comprehensive security audit. Document all findings thoroughly with evidence."
    }
    enhanced_rules = f"{rules}\n\nMODE: {mode_instructions.get(mode, '')}"
    
    while iteration < max_iterations:
        iteration += 1
        
        # Broadcast tool status - thinking
        await app_state.broadcast_message({
            "type": "tool_status",
            "tool": {"name": "AI Planning", "status": "running", "progress": None}
        })
        app_state.update_tool_status_sync("AI Planning", "running")
        
        # Get next action from AI
        try:
            action = await app_state.ai_core.get_next_action_async(enhanced_rules, agent_memory)
        except Exception as e:
            logger.error(f"Error getting next action: {e}")
            app_state.update_tool_status_sync("AI Planning", "failed")
            break
        
        app_state.update_tool_status_sync("AI Planning", "completed")
        
        if not action:
            break
        
        tool_name = action.get("tool", "")
        
        # Check for completion signals
        if tool_name in ["complete", "done", "finish", "report"]:
            # Generate final report
            report = action.get("message", action.get("summary", "Mission completed."))
            await app_state.broadcast_message({
                "type": "chat",
                "role": "assistant",
                "content": f"✅ **Mission Complete**\n\n{report}",
                "timestamp": time.time()
            })
            break
        
        if tool_name == "system":
            # System message from AI
            message = action.get("message", "")
            await app_state.broadcast_message({
                "type": "chat",
                "role": "assistant",
                "content": f"💭 {message}",
                "timestamp": time.time()
            })
            agent_memory.append({"type": "thought", "content": message})
            continue
        
        # Broadcast tool execution
        await app_state.broadcast_message({
            "type": "tool_status",
            "tool": {"name": tool_name, "status": "running", "progress": None}
        })
        app_state.update_tool_status_sync(tool_name, "running")
        
        # Send progress message
        args_str = json.dumps(action.get("args", {}), indent=2) if action.get("args") else ""
        await app_state.broadcast_message({
            "type": "chat",
            "role": "assistant",
            "content": f"🔧 Executing **{tool_name}**...\n```json\n{args_str}\n```",
            "timestamp": time.time()
        })
        
        # Execute the tool
        try:
            result = await scanner.execute_action(action)
            app_state.update_tool_status_sync(tool_name, "completed")
            
            # Broadcast result
            result_preview = str(result)[:500] + "..." if len(str(result)) > 500 else str(result)
            await app_state.broadcast_message({
                "type": "chat",
                "role": "assistant", 
                "content": f"📋 **{tool_name}** result:\n```\n{result_preview}\n```",
                "timestamp": time.time()
            })
            
            # Add to agent memory
            agent_memory.append({
                "type": "observation",
                "tool": tool_name,
                "result": result
            })
            
        except Exception as e:
            logger.error(f"Tool execution error: {e}")
            app_state.update_tool_status_sync(tool_name, "failed")
            
            await app_state.broadcast_message({
                "type": "chat",
                "role": "assistant",
                "content": f"⚠️ **{tool_name}** failed: {str(e)}",
                "timestamp": time.time()
            })
            
            agent_memory.append({
                "type": "error",
                "tool": tool_name,
                "error": str(e)
            })
        
        # Small delay between iterations
        await asyncio.sleep(1)
    
    if iteration >= max_iterations:
        await app_state.broadcast_message({
            "type": "chat",
            "role": "assistant",
            "content": f"⚠️ Reached maximum iterations ({max_iterations}). Stopping scan.",
            "timestamp": time.time()
        })


# ============================================================================
# STATIC FILES & FRONTEND SERVING
# ============================================================================

# Serve frontend static files if they exist
if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")
    
    # Cache resolved paths for performance (avoid filesystem calls on every request)
    _FRONTEND_BASE = FRONTEND_DIST.resolve()
    _INDEX_FILE = _FRONTEND_BASE / "index.html"
    
    @app.get("/{path:path}")
    async def serve_frontend(path: str):
        """Serve React frontend with path traversal protection"""
        # Use cached resolved paths for performance
        frontend_base = _FRONTEND_BASE
        index_file = _INDEX_FILE
        
        # Security: Reject obviously malicious paths early
        if ".." in path or path.startswith("/") or "\\" in path:
            return FileResponse(index_file)
        
        # Security: Reject any path with null bytes or other dangerous characters
        if "\x00" in path:
            return FileResponse(index_file)
        
        # Resolve and validate path is within frontend directory
        try:
            # Construct and resolve the requested file path
            requested_path = (frontend_base / path).resolve()
            
            # Security: Use is_relative_to for proper containment check
            # This is the correct way to verify path containment
            if not requested_path.is_relative_to(frontend_base):
                return FileResponse(index_file)
            
            # Only serve if file exists and is a regular file (not directory/symlink to outside)
            if requested_path.exists() and requested_path.is_file():
                # Additional check: ensure it's not a symlink pointing outside
                if requested_path.is_symlink():
                    try:
                        real_path = requested_path.resolve()
                        if not real_path.is_relative_to(frontend_base):
                            return FileResponse(index_file)
                    except (OSError, ValueError):
                        # If we can't resolve the symlink, reject it
                        return FileResponse(index_file)
                return FileResponse(requested_path)
        except (ValueError, OSError):
            pass
        
        return FileResponse(index_file)


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
