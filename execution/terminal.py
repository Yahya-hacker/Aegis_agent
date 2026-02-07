"""
Aegis Agent - Terminal Executor
===============================

Robust subprocess execution with WebSocket streaming.
Handles STDOUT/STDERR, interactive prompts, and long-running processes.
"""

import asyncio
import logging
import os
import pty
import signal
import struct
import fcntl
import termios
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple
import uuid
import re

logger = logging.getLogger(__name__)


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


@dataclass
class ExecutionResult:
    """Result of a terminal command execution."""
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    killed: bool = False


@dataclass 
class ProcessHandle:
    """Handle for a long-running process."""
    process_id: str
    command: str
    pid: int
    started_at: datetime
    _process: asyncio.subprocess.Process = field(repr=False)


class TerminalExecutor:
    """
    Production-grade terminal command executor.
    
    Features:
    - Async subprocess execution
    - STDOUT/STDERR streaming via callback
    - Interactive prompt handling
    - Timeout and kill support
    - PTY support for tools requiring terminal
    """
    
    def __init__(
        self,
        max_output_bytes: int = 50 * 1024 * 1024,  # 50MB
        default_timeout: int = 300,
        stream_callback: Optional[Callable[[str, str], None]] = None
    ):
        self.max_output_bytes = max_output_bytes
        self.default_timeout = default_timeout
        self.stream_callback = stream_callback
        self.active_processes: Dict[str, ProcessHandle] = {}
    
    async def run(
        self,
        command: str,
        timeout: int = None,
        cwd: str = None,
        env: Dict[str, str] = None,
        stream: bool = True
    ) -> ExecutionResult:
        """
        Execute a command and return the result.
        
        Args:
            command: Shell command to execute
            timeout: Timeout in seconds (default: 300)
            cwd: Working directory
            env: Environment variables
            stream: If True, stream output via callback
            
        Returns:
            ExecutionResult with output and status
        """
        timeout = timeout or self.default_timeout
        start_time = asyncio.get_event_loop().time()
        
        logger.debug(f"🖥️ Executing: {command}")
        
        # Merge environment
        full_env = os.environ.copy()
        if env:
            full_env.update(env)
        
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=full_env
            )
            
            stdout_chunks = []
            stderr_chunks = []
            total_bytes = 0
            
            async def read_stream(stream, chunks: List[bytes], name: str):
                nonlocal total_bytes
                while True:
                    try:
                        chunk = await asyncio.wait_for(stream.read(4096), timeout=1.0)
                        if not chunk:
                            break
                        
                        total_bytes += len(chunk)
                        if total_bytes > self.max_output_bytes:
                            process.kill()
                            raise RuntimeError("Output exceeded maximum size")
                        
                        chunks.append(chunk)
                        
                        # Stream callback
                        if stream and self.stream_callback:
                            text = chunk.decode("utf-8", errors="replace")
                            clean_text = strip_ansi(text)
                            if clean_text:
                                self.stream_callback(name, clean_text)
                            
                    except asyncio.TimeoutError:
                        if process.returncode is not None:
                            break
                        continue
            
            try:
                await asyncio.wait_for(
                    asyncio.gather(
                        read_stream(process.stdout, stdout_chunks, "stdout"),
                        read_stream(process.stderr, stderr_chunks, "stderr")
                    ),
                    timeout=timeout
                )
                await asyncio.wait_for(process.wait(), timeout=5.0)
                timed_out = False
                
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                timed_out = True
                logger.warning(f"⏰ Command timed out: {command[:50]}...")
            
            duration_ms = int((asyncio.get_event_loop().time() - start_time) * 1000)
            
            return ExecutionResult(
                command=command,
                exit_code=process.returncode or -1,
                stdout=b"".join(stdout_chunks).decode("utf-8", errors="replace"),
                stderr=b"".join(stderr_chunks).decode("utf-8", errors="replace"),
                duration_ms=duration_ms,
                timed_out=timed_out
            )
            
        except Exception as e:
            duration_ms = int((asyncio.get_event_loop().time() - start_time) * 1000)
            logger.error(f"❌ Execution error: {e}")
            return ExecutionResult(
                command=command,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                duration_ms=duration_ms
            )
    
    async def run_interactive(
        self,
        command: str,
        inputs: List[Tuple[str, str]],  # List of (expect_pattern, send_input)
        timeout: int = None
    ) -> ExecutionResult:
        """
        Execute a command with interactive input handling.
        
        Args:
            command: Shell command
            inputs: List of (pattern_to_expect, input_to_send) tuples
            timeout: Total timeout
            
        Returns:
            ExecutionResult
        """
        timeout = timeout or self.default_timeout
        start_time = asyncio.get_event_loop().time()
        
        logger.debug(f"🖥️ Interactive: {command}")
        
        # Use PTY for interactive commands
        master_fd, slave_fd = pty.openpty()
        
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                preexec_fn=os.setsid
            )
            
            os.close(slave_fd)
            
            output_buffer = ""
            input_index = 0
            
            async def read_output():
                nonlocal output_buffer
                loop = asyncio.get_event_loop()
                while True:
                    try:
                        data = await loop.run_in_executor(
                            None, lambda: os.read(master_fd, 4096)
                        )
                        if not data:
                            break
                        text = data.decode("utf-8", errors="replace")
                        output_buffer += text
                        
                        if self.stream_callback:
                            clean_text = strip_ansi(text)
                            if clean_text:
                                self.stream_callback("stdout", clean_text)
                            
                    except OSError:
                        break
            
            async def handle_inputs():
                nonlocal input_index
                loop = asyncio.get_event_loop()
                
                for pattern, response in inputs:
                    # Wait for pattern
                    for _ in range(timeout * 10):  # Check every 100ms
                        if pattern.lower() in output_buffer.lower():
                            # Send response
                            await loop.run_in_executor(
                                None, 
                                lambda: os.write(master_fd, (response + "\n").encode())
                            )
                            input_index += 1
                            await asyncio.sleep(0.5)
                            break
                        await asyncio.sleep(0.1)
            
            try:
                await asyncio.wait_for(
                    asyncio.gather(read_output(), handle_inputs()),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                pass
            
            os.close(master_fd)
            
            try:
                process.kill()
            except ProcessLookupError:
                pass
            
            await process.wait()
            duration_ms = int((asyncio.get_event_loop().time() - start_time) * 1000)
            
            return ExecutionResult(
                command=command,
                exit_code=process.returncode or 0,
                stdout=output_buffer,
                stderr="",
                duration_ms=duration_ms
            )
            
        except Exception as e:
            duration_ms = int((asyncio.get_event_loop().time() - start_time) * 1000)
            return ExecutionResult(
                command=command,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                duration_ms=duration_ms
            )
    
    async def spawn_long_running(
        self,
        command: str,
        cwd: str = None
    ) -> ProcessHandle:
        """
        Spawn a long-running process without waiting.
        
        Args:
            command: Command to run
            cwd: Working directory
            
        Returns:
            ProcessHandle for later management
        """
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd
        )
        
        process_id = str(uuid.uuid4())[:8]
        handle = ProcessHandle(
            process_id=process_id,
            command=command,
            pid=process.pid,
            started_at=datetime.now(),
            _process=process
        )
        
        self.active_processes[process_id] = handle
        logger.info(f"🚀 Spawned process {process_id}: {command[:50]}...")
        
        return handle
    
    def kill(self, process_id: str) -> bool:
        """Kill a long-running process by ID."""
        handle = self.active_processes.get(process_id)
        if not handle:
            return False
        
        try:
            handle._process.kill()
            del self.active_processes[process_id]
            logger.info(f"💀 Killed process {process_id}")
            return True
        except ProcessLookupError:
            del self.active_processes[process_id]
            return True
        except Exception as e:
            logger.error(f"❌ Failed to kill {process_id}: {e}")
            return False
    
    def list_processes(self) -> List[Dict[str, Any]]:
        """List all active processes."""
        return [
            {
                "process_id": h.process_id,
                "command": h.command,
                "pid": h.pid,
                "started_at": h.started_at.isoformat()
            }
            for h in self.active_processes.values()
        ]


# Singleton
_executor: Optional[TerminalExecutor] = None


def get_executor() -> TerminalExecutor:
    """Get global terminal executor."""
    global _executor
    if _executor is None:
        _executor = TerminalExecutor()
    return _executor


def set_stream_callback(callback: Callable[[str, str], None]):
    """Set the global stream callback for WebSocket streaming."""
    executor = get_executor()
    executor.stream_callback = callback
