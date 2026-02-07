# aegis/state.py
"""
State Management for Aegis AI.

Extracted from server.py MonoGod. Contains:
- Repository pattern interfaces for chat/tool storage
- In-memory implementations (swap for Redis/DB easily)
- Pydantic models for data transfer
- AppState class for application-wide state
"""

import asyncio
import time
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field

# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class OperationMode(str, Enum):
    """Operation modes for the Aegis agent"""
    PENETRATION_TESTING = "penetration_testing"
    CTF_MODE = "ctf_mode"
    RED_TEAMING = "red_teaming"
    AUDIT = "audit"


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
# REPOSITORY INTERFACES
# ============================================================================

class ChatHistoryRepository(ABC):
    """Abstract interface for chat history storage."""
    
    @abstractmethod
    async def add_message(self, message: Dict[str, Any]) -> None:
        pass
    
    @abstractmethod
    async def get_messages(self, limit: int = 100) -> List[Dict[str, Any]]:
        pass
    
    @abstractmethod
    async def clear(self) -> None:
        pass


class ToolStatusRepository(ABC):
    """Abstract interface for tool status storage."""
    
    @abstractmethod
    async def update_status(self, name: str, status: ToolStatus) -> None:
        pass
    
    @abstractmethod
    async def get_status(self, name: str) -> Optional[ToolStatus]:
        pass
    
    @abstractmethod
    async def get_all_statuses(self) -> Dict[str, ToolStatus]:
        pass


# ============================================================================
# IN-MEMORY IMPLEMENTATIONS
# ============================================================================

class InMemoryChatHistoryRepository(ChatHistoryRepository):
    """In-memory chat history. Swap for Redis/DB for horizontal scaling."""
    
    def __init__(self, max_messages: int = 1000):
        self._messages: List[Dict[str, Any]] = []
        self._max_messages = max_messages
    
    async def add_message(self, message: Dict[str, Any]) -> None:
        self._messages.append(message)
        if len(self._messages) > self._max_messages:
            self._messages = self._messages[-self._max_messages:]
    
    async def get_messages(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._messages[-limit:]
    
    async def clear(self) -> None:
        self._messages = []


class InMemoryToolStatusRepository(ToolStatusRepository):
    """In-memory tool status. Swap for Redis/DB for horizontal scaling."""
    
    def __init__(self):
        self._statuses: Dict[str, ToolStatus] = {}
    
    async def update_status(self, name: str, status: ToolStatus) -> None:
        self._statuses[name] = status
    
    async def get_status(self, name: str) -> Optional[ToolStatus]:
        return self._statuses.get(name)
    
    async def get_all_statuses(self) -> Dict[str, ToolStatus]:
        return self._statuses.copy()


# ============================================================================
# APPLICATION STATE
# ============================================================================

class AppState:
    """
    Central application state with repository pattern.
    Manages WebSocket connections, chat, tools, and agent lifecycle.
    """
    
    def __init__(self):
        # WebSocket management (O(1) Set operations)
        self.active_websockets: Set = set()
        self._websocket_lock = asyncio.Lock()
        
        # Operation mode and mission
        self.current_mode: OperationMode = OperationMode.PENETRATION_TESTING
        self.mission_config: Optional[MissionConfig] = None
        
        # Repository pattern for scalable storage
        self._chat_repository = InMemoryChatHistoryRepository()
        self._tool_repository = InMemoryToolStatusRepository()
        
        # Swarm decisions
        self.swarm_decisions: List[SwarmDecision] = []
        
        # Agent components (initialized lazily)
        self.agent_initialized: bool = False
        self.agent = None  # Will hold the main Agent instance
    
    # ---- Chat History ----
    
    async def get_chat_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        return await self._chat_repository.get_messages(limit)
    
    async def add_chat_message(self, message: Dict[str, Any]) -> None:
        await self._chat_repository.add_message(message)
    
    async def clear_chat_history(self) -> None:
        await self._chat_repository.clear()
    
    @property
    def chat_history(self) -> List[Dict[str, Any]]:
        """Backward compatible sync access."""
        return self._chat_repository._messages
    
    # ---- Tool Status ----
    
    async def update_tool_status(self, name: str, status: str, 
                                  progress: Optional[float] = None, 
                                  output: Optional[str] = None) -> None:
        tool_status = ToolStatus(name=name, status=status, progress=progress, output=output)
        await self._tool_repository.update_status(name, tool_status)
    
    async def get_tool_statuses(self) -> Dict[str, ToolStatus]:
        return await self._tool_repository.get_all_statuses()
    
    @property
    def tool_statuses(self) -> Dict[str, ToolStatus]:
        """Backward compatible sync access."""
        return self._tool_repository._statuses
    
    # ---- WebSocket Management ----
    
    async def add_websocket(self, ws) -> None:
        async with self._websocket_lock:
            self.active_websockets.add(ws)
    
    async def remove_websocket(self, ws) -> None:
        async with self._websocket_lock:
            self.active_websockets.discard(ws)
    
    async def broadcast_message(self, message: Dict[str, Any]) -> None:
        """Broadcast to all connected WebSocket clients."""
        disconnected = set()
        
        async with self._websocket_lock:
            websockets_copy = self.active_websockets.copy()
        
        for ws in websockets_copy:
            try:
                await ws.send_json(message)
            except Exception:
                disconnected.add(ws)
        
        if disconnected:
            async with self._websocket_lock:
                self.active_websockets -= disconnected


# Singleton
_app_state = None

def get_app_state() -> AppState:
    global _app_state
    if _app_state is None:
        _app_state = AppState()
    return _app_state
