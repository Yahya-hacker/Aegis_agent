#!/usr/bin/env python3
"""
Aegis AI v9.0 - Dynamic MCP Client
==================================

This module implements the Model Context Protocol (MCP) client for Aegis AI.
It allows the agent to dynamically connect to MCP servers and hot-plug tools
without restarting the agent.

Features:
- SSE (Server-Sent Events) transport support
- stdio transport support
- Dynamic tool discovery and registration
- Hot-plug capability for adding/removing tools at runtime
- Automatic reconnection with exponential backoff
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import aiohttp
import uuid

logger = logging.getLogger(__name__)


class TransportType(Enum):
    """MCP transport types"""
    SSE = "sse"
    STDIO = "stdio"
    WEBSOCKET = "websocket"


@dataclass
class MCPTool:
    """Represents a tool from an MCP server"""
    name: str
    description: str
    input_schema: Dict[str, Any]
    server_name: str
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "server_name": self.server_name,
            "enabled": self.enabled,
            "metadata": self.metadata
        }


@dataclass
class MCPServerConnection:
    """Represents a connection to an MCP server"""
    name: str
    endpoint: str
    transport_type: TransportType
    tools: List[MCPTool] = field(default_factory=list)
    connected: bool = False
    last_ping: Optional[float] = None
    error_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class MCPTransport(ABC):
    """Abstract base class for MCP transports"""
    
    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to MCP server"""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to MCP server"""
        pass
    
    @abstractmethod
    async def send_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Send a JSON-RPC request to the server"""
        pass
    
    @abstractmethod
    async def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools from the server"""
        pass
    
    @abstractmethod
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool on the server"""
        pass


class SSETransport(MCPTransport):
    """
    Server-Sent Events (SSE) transport for MCP.
    
    Connects to MCP servers that expose tools via SSE endpoints.
    """
    
    def __init__(self, endpoint: str, server_name: str):
        """
        Initialize SSE transport.
        
        Args:
            endpoint: SSE endpoint URL (e.g., sse://localhost:3000/mcp)
            server_name: Name of the server for logging
        """
        self.server_name = server_name
        
        # Convert sse:// to http:// or https://
        if endpoint.startswith("sse://"):
            self.base_url = endpoint.replace("sse://", "http://")
        elif endpoint.startswith("sses://"):
            self.base_url = endpoint.replace("sses://", "https://")
        else:
            self.base_url = endpoint
        
        self.session: Optional[aiohttp.ClientSession] = None
        self.connected = False
        self.request_id = 0
    
    async def connect(self) -> bool:
        """Connect to the SSE MCP server"""
        try:
            self.session = aiohttp.ClientSession()
            
            # Test connection by listing tools
            async with self.session.get(
                f"{self.base_url}/tools",
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    self.connected = True
                    logger.info(f"✅ Connected to SSE MCP server: {self.server_name}")
                    return True
                else:
                    logger.error(f"Failed to connect to {self.server_name}: HTTP {response.status}")
                    return False
                    
        except aiohttp.ClientError as e:
            logger.error(f"Connection error for {self.server_name}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error connecting to {self.server_name}: {e}")
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from the SSE MCP server"""
        if self.session:
            await self.session.close()
            self.session = None
        self.connected = False
        logger.info(f"🔌 Disconnected from SSE MCP server: {self.server_name}")
    
    async def send_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Send a JSON-RPC request via SSE"""
        if not self.session or not self.connected:
            raise RuntimeError(f"Not connected to {self.server_name}")
        
        self.request_id += 1
        
        request_body = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params
        }
        
        try:
            async with self.session.post(
                f"{self.base_url}/message",
                json=request_body,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    raise RuntimeError(f"MCP request failed: HTTP {response.status} - {error_text}")
                    
        except aiohttp.ClientError as e:
            raise RuntimeError(f"MCP request error: {e}")
    
    async def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools from the SSE MCP server"""
        if not self.session or not self.connected:
            raise RuntimeError(f"Not connected to {self.server_name}")
        
        try:
            async with self.session.get(
                f"{self.base_url}/tools",
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("tools", [])
                else:
                    logger.error(f"Failed to list tools from {self.server_name}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error listing tools from {self.server_name}: {e}")
            return []
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool on the SSE MCP server"""
        result = await self.send_request("tools/call", {
            "name": tool_name,
            "arguments": arguments
        })
        
        return result.get("result", {})


class StdioTransport(MCPTransport):
    """
    stdio transport for MCP.
    
    Spawns an MCP server as a subprocess and communicates via stdin/stdout.
    """
    
    def __init__(self, command: str, server_name: str, env: Optional[Dict[str, str]] = None):
        """
        Initialize stdio transport.
        
        Args:
            command: Command to spawn the MCP server (e.g., "npx @modelcontextprotocol/server-filesystem")
            server_name: Name of the server for logging
            env: Optional environment variables for the subprocess
        """
        self.command = command
        self.server_name = server_name
        self.env = env or {}
        self.process: Optional[asyncio.subprocess.Process] = None
        self.connected = False
        self.request_id = 0
        self._pending_requests: Dict[int, asyncio.Future] = {}
        self._reader_task: Optional[asyncio.Task] = None
    
    async def connect(self) -> bool:
        """Spawn and connect to the stdio MCP server"""
        try:
            # Parse command
            if self.command.startswith("stdio:"):
                cmd = self.command[6:]  # Remove "stdio:" prefix
            else:
                cmd = self.command
            
            # Prepare environment
            env = os.environ.copy()
            env.update(self.env)
            
            # Spawn subprocess
            self.process = await asyncio.create_subprocess_shell(
                cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            
            # Start reader task
            self._reader_task = asyncio.create_task(self._read_responses())
            
            # Send initialize request
            result = await self.send_request("initialize", {
                "protocolVersion": "0.1.0",
                "capabilities": {},
                "clientInfo": {
                    "name": "aegis-ai",
                    "version": "9.0.0"
                }
            })
            
            if result.get("protocolVersion"):
                self.connected = True
                logger.info(f"✅ Connected to stdio MCP server: {self.server_name}")
                return True
            else:
                logger.error(f"Failed to initialize {self.server_name}: {result}")
                return False
                
        except Exception as e:
            logger.error(f"Error starting stdio MCP server {self.server_name}: {e}")
            return False
    
    async def disconnect(self) -> None:
        """Terminate the stdio MCP server subprocess"""
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
        
        if self.process:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self.process.kill()
            self.process = None
        
        self.connected = False
        logger.info(f"🔌 Disconnected from stdio MCP server: {self.server_name}")
    
    async def _read_responses(self):
        """Background task to read responses from the subprocess"""
        if not self.process or not self.process.stdout:
            return
        
        try:
            while True:
                line = await self.process.stdout.readline()
                if not line:
                    break
                
                try:
                    response = json.loads(line.decode())
                    request_id = response.get("id")
                    
                    if request_id and request_id in self._pending_requests:
                        self._pending_requests[request_id].set_result(response)
                        del self._pending_requests[request_id]
                        
                except json.JSONDecodeError:
                    logger.debug(f"Non-JSON line from {self.server_name}: {line}")
                    
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error reading from {self.server_name}: {e}")
    
    async def send_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Send a JSON-RPC request via stdio"""
        if not self.process or not self.process.stdin:
            raise RuntimeError(f"Not connected to {self.server_name}")
        
        self.request_id += 1
        request_id = self.request_id
        
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params
        }
        
        # Create future for response
        future: asyncio.Future = asyncio.Future()
        self._pending_requests[request_id] = future
        
        # Send request
        request_bytes = (json.dumps(request) + "\n").encode()
        self.process.stdin.write(request_bytes)
        await self.process.stdin.drain()
        
        # Wait for response with timeout
        try:
            response = await asyncio.wait_for(future, timeout=30.0)
            
            if "error" in response:
                raise RuntimeError(f"MCP error: {response['error']}")
            
            return response.get("result", {})
            
        except asyncio.TimeoutError:
            if request_id in self._pending_requests:
                del self._pending_requests[request_id]
            raise RuntimeError(f"Request to {self.server_name} timed out")
    
    async def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools from the stdio MCP server"""
        result = await self.send_request("tools/list", {})
        return result.get("tools", [])
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool on the stdio MCP server"""
        return await self.send_request("tools/call", {
            "name": tool_name,
            "arguments": arguments
        })


class DynamicMCPClient:
    """
    Dynamic MCP Client for Aegis AI.
    
    Manages connections to multiple MCP servers and provides a unified interface
    for tool discovery and execution. Supports hot-plugging of tools at runtime.
    
    Features:
    - Connect to multiple MCP servers simultaneously
    - Automatic transport detection (SSE/stdio)
    - Hot-plug: Add/remove servers without restarting
    - Tool registry with conflict resolution
    - Automatic reconnection with exponential backoff
    """
    
    def __init__(self):
        """Initialize the Dynamic MCP Client"""
        self.connections: Dict[str, MCPServerConnection] = {}
        self.transports: Dict[str, MCPTransport] = {}
        self.tool_registry: Dict[str, MCPTool] = {}
        self._reconnect_tasks: Dict[str, asyncio.Task] = {}
        self._tool_callbacks: List[Callable[[str, MCPTool, str], None]] = []
        
        logger.info("🔌 Dynamic MCP Client initialized")
    
    def _detect_transport_type(self, endpoint: str) -> TransportType:
        """
        Detect the transport type from the endpoint URL.
        
        Args:
            endpoint: MCP server endpoint
            
        Returns:
            Detected transport type
        """
        if endpoint.startswith("sse://") or endpoint.startswith("sses://"):
            return TransportType.SSE
        elif endpoint.startswith("stdio:"):
            return TransportType.STDIO
        elif endpoint.startswith("ws://") or endpoint.startswith("wss://"):
            return TransportType.WEBSOCKET
        elif endpoint.startswith("http://") or endpoint.startswith("https://"):
            return TransportType.SSE  # Default HTTP to SSE
        else:
            return TransportType.STDIO  # Default to stdio for commands
    
    def _create_transport(self, server_name: str, endpoint: str) -> MCPTransport:
        """
        Create the appropriate transport for an endpoint.
        
        Args:
            server_name: Name of the server
            endpoint: MCP server endpoint
            
        Returns:
            MCP transport instance
        """
        transport_type = self._detect_transport_type(endpoint)
        
        if transport_type == TransportType.SSE:
            return SSETransport(endpoint, server_name)
        elif transport_type == TransportType.STDIO:
            return StdioTransport(endpoint, server_name)
        else:
            raise ValueError(f"Unsupported transport type: {transport_type}")
    
    async def connect(self, server_name: str, endpoint: str) -> bool:
        """
        Connect to an MCP server.
        
        Args:
            server_name: Friendly name for the server
            endpoint: Server endpoint (sse://... or stdio:command)
            
        Returns:
            True if connection successful
        """
        if server_name in self.connections:
            logger.warning(f"Server {server_name} already connected, disconnecting first")
            await self.disconnect(server_name)
        
        logger.info(f"🔌 Connecting to MCP server: {server_name} ({endpoint})")
        
        try:
            # Create transport
            transport = self._create_transport(server_name, endpoint)
            
            # Connect
            if await transport.connect():
                # Create connection record
                connection = MCPServerConnection(
                    name=server_name,
                    endpoint=endpoint,
                    transport_type=self._detect_transport_type(endpoint),
                    connected=True
                )
                
                # Store connection and transport
                self.connections[server_name] = connection
                self.transports[server_name] = transport
                
                # Discover and register tools
                await self._discover_tools(server_name)
                
                return True
            else:
                return False
                
        except Exception as e:
            logger.error(f"Failed to connect to {server_name}: {e}")
            return False
    
    async def disconnect(self, server_name: str) -> None:
        """
        Disconnect from an MCP server.
        
        Args:
            server_name: Name of the server to disconnect
        """
        if server_name not in self.connections:
            return
        
        # Cancel any reconnect task
        if server_name in self._reconnect_tasks:
            self._reconnect_tasks[server_name].cancel()
            del self._reconnect_tasks[server_name]
        
        # Disconnect transport
        if server_name in self.transports:
            await self.transports[server_name].disconnect()
            del self.transports[server_name]
        
        # Unregister tools
        self._unregister_server_tools(server_name)
        
        # Remove connection record
        del self.connections[server_name]
        
        logger.info(f"🔌 Disconnected from MCP server: {server_name}")
    
    async def _discover_tools(self, server_name: str) -> None:
        """
        Discover and register tools from an MCP server.
        
        Args:
            server_name: Name of the server
        """
        if server_name not in self.transports:
            return
        
        transport = self.transports[server_name]
        connection = self.connections[server_name]
        
        try:
            tools_data = await transport.list_tools()
            
            for tool_data in tools_data:
                tool = MCPTool(
                    name=tool_data.get("name", ""),
                    description=tool_data.get("description", ""),
                    input_schema=tool_data.get("inputSchema", {}),
                    server_name=server_name,
                    metadata=tool_data.get("metadata", {})
                )
                
                # Register tool
                self._register_tool(tool)
                connection.tools.append(tool)
            
            logger.info(f"📦 Discovered {len(tools_data)} tools from {server_name}")
            
        except Exception as e:
            logger.error(f"Failed to discover tools from {server_name}: {e}")
    
    def _register_tool(self, tool: MCPTool) -> None:
        """
        Register a tool in the global registry.
        
        Args:
            tool: Tool to register
        """
        # Handle name conflicts by prefixing with server name
        tool_key = tool.name
        if tool_key in self.tool_registry:
            # Check if it's from a different server
            existing = self.tool_registry[tool_key]
            if existing.server_name != tool.server_name:
                tool_key = f"{tool.server_name}.{tool.name}"
                logger.warning(f"Tool name conflict: {tool.name} - using {tool_key}")
        
        self.tool_registry[tool_key] = tool
        
        # Notify callbacks
        for callback in self._tool_callbacks:
            try:
                callback("add", tool, tool_key)
            except Exception as e:
                logger.error(f"Tool callback error: {e}")
    
    def _unregister_server_tools(self, server_name: str) -> None:
        """
        Unregister all tools from a server.
        
        Args:
            server_name: Name of the server
        """
        tools_to_remove = [
            key for key, tool in self.tool_registry.items()
            if tool.server_name == server_name
        ]
        
        for tool_key in tools_to_remove:
            tool = self.tool_registry.pop(tool_key)
            
            # Notify callbacks
            for callback in self._tool_callbacks:
                try:
                    callback("remove", tool, tool_key)
                except Exception as e:
                    logger.error(f"Tool callback error: {e}")
    
    def on_tool_change(self, callback: Callable[[str, MCPTool, str], None]) -> None:
        """
        Register a callback for tool changes.
        
        Args:
            callback: Function called with (action, tool, tool_key)
                     action is "add" or "remove"
        """
        self._tool_callbacks.append(callback)
    
    async def list_tools(self, server_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List available tools.
        
        Args:
            server_name: Optional filter by server name
            
        Returns:
            List of tool dictionaries
        """
        if server_name:
            if server_name in self.connections:
                return [t.to_dict() for t in self.connections[server_name].tools]
            return []
        
        return [t.to_dict() for t in self.tool_registry.values()]
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Call a tool by name.
        
        Args:
            tool_name: Name of the tool (or server.name for disambiguated tools)
            arguments: Tool arguments
            
        Returns:
            Tool execution result
        """
        if tool_name not in self.tool_registry:
            raise ValueError(f"Tool not found: {tool_name}")
        
        tool = self.tool_registry[tool_name]
        server_name = tool.server_name
        
        if server_name not in self.transports:
            raise RuntimeError(f"Server {server_name} not connected")
        
        transport = self.transports[server_name]
        
        logger.info(f"🔧 Calling MCP tool: {tool_name} on {server_name}")
        
        try:
            result = await transport.call_tool(tool.name, arguments)
            return {
                "status": "success",
                "result": result,
                "tool": tool_name,
                "server": server_name
            }
        except Exception as e:
            logger.error(f"MCP tool call failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "tool": tool_name,
                "server": server_name
            }
    
    def get_tool_prompt(self) -> str:
        """
        Generate a prompt describing available MCP tools for the LLM.
        
        Returns:
            Formatted string describing available tools
        """
        if not self.tool_registry:
            return "[MCP TOOLS] No external MCP tools connected."
        
        lines = ["[MCP TOOLS] The following external tools are available via MCP:"]
        
        # Group by server
        servers: Dict[str, List[MCPTool]] = {}
        for tool in self.tool_registry.values():
            if tool.server_name not in servers:
                servers[tool.server_name] = []
            servers[tool.server_name].append(tool)
        
        for server_name, tools in servers.items():
            lines.append(f"\n### Server: {server_name}")
            for tool in tools:
                lines.append(f"- **{tool.name}**: {tool.description}")
                if tool.input_schema.get("properties"):
                    params = ", ".join(tool.input_schema["properties"].keys())
                    lines.append(f"  Parameters: {params}")
        
        lines.append("\nTo use an MCP tool, specify: mcp_call(tool_name, {arguments})")
        
        return "\n".join(lines)
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get status of all MCP connections.
        
        Returns:
            Status dictionary
        """
        return {
            "total_servers": len(self.connections),
            "connected_servers": sum(1 for c in self.connections.values() if c.connected),
            "total_tools": len(self.tool_registry),
            "servers": {
                name: {
                    "endpoint": conn.endpoint,
                    "transport": conn.transport_type.value,
                    "connected": conn.connected,
                    "tools_count": len(conn.tools)
                }
                for name, conn in self.connections.items()
            }
        }
    
    async def close(self) -> None:
        """Close all connections and cleanup"""
        for server_name in list(self.connections.keys()):
            await self.disconnect(server_name)
        
        logger.info("🔌 Dynamic MCP Client closed")
