# utils/async_task_manager.py
# --- Async Task Manager for Background Tool Execution ---
#
# This module solves the "Sequential Execution Constraint" problem where the agent
# would "sleep" while waiting for slow tools like port scans or directory brute-force.
#
# The AsyncTaskManager allows the agent to:
# 1. Dispatch long-running tools to run in the background
# 2. Check their status later
# 3. Continue with other tasks (visual recon, planning) while scans run

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """Possible statuses for background tasks"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class BackgroundTask:
    """Represents a background task with its state and result"""
    task_id: str
    name: str
    tool_name: str
    args: Dict[str, Any]
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    _asyncio_task: Optional[asyncio.Task] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary for serialization"""
        return {
            "task_id": self.task_id,
            "name": self.name,
            "tool_name": self.tool_name,
            "args": self.args,
            "status": self.status.value,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": (
                (self.completed_at - self.started_at).total_seconds()
                if self.completed_at and self.started_at
                else None
            )
        }


class AsyncTaskManager:
    """
    Manages background task execution for long-running tools.
    
    This allows the agent to:
    - Dispatch slow tools (port scans, directory bruteforce) to run in background
    - Continue with other tasks while waiting
    - Check task status and retrieve results when ready
    
    Example usage:
        task_manager = AsyncTaskManager()
        
        # Dispatch a background scan
        task_id = await task_manager.dispatch_task(
            name="Full Port Scan",
            tool_name="nmap_scan",
            args={"target": "example.com", "ports": "1-65535"},
            executor_func=scanner.execute_action
        )
        
        # Later, check status
        status = task_manager.get_task_status(task_id)
        if status.status == TaskStatus.COMPLETED:
            result = status.result
    """
    
    def __init__(self, max_concurrent_tasks: int = 5):
        """
        Initialize the task manager.
        
        Args:
            max_concurrent_tasks: Maximum number of tasks that can run simultaneously
        """
        self._tasks: Dict[str, BackgroundTask] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent_tasks)
        self._lock = asyncio.Lock()
        logger.info(f"🔄 AsyncTaskManager initialized (max concurrent: {max_concurrent_tasks})")
    
    def _generate_task_id(self) -> str:
        """Generate a unique task ID"""
        return f"task_{uuid.uuid4().hex[:8]}"
    
    async def dispatch_task(
        self,
        name: str,
        tool_name: str,
        args: Dict[str, Any],
        executor_func: Callable[[Dict[str, Any]], Coroutine[Any, Any, Dict[str, Any]]]
    ) -> str:
        """
        Dispatch a task to run in the background.
        
        Args:
            name: Human-readable task name (e.g., "Full Port Scan on example.com")
            tool_name: Name of the tool to execute
            args: Arguments to pass to the tool
            executor_func: Async function that executes tools (e.g., scanner.execute_action)
        
        Returns:
            Task ID for tracking
        """
        task_id = self._generate_task_id()
        
        task = BackgroundTask(
            task_id=task_id,
            name=name,
            tool_name=tool_name,
            args=args,
            status=TaskStatus.PENDING
        )
        
        async with self._lock:
            self._tasks[task_id] = task
        
        # Create the background coroutine
        asyncio_task = asyncio.create_task(
            self._run_task(task, executor_func)
        )
        task._asyncio_task = asyncio_task
        
        logger.info(f"📋 Dispatched background task: {name} (ID: {task_id})")
        
        return task_id
    
    async def _run_task(
        self,
        task: BackgroundTask,
        executor_func: Callable[[Dict[str, Any]], Coroutine[Any, Any, Dict[str, Any]]]
    ) -> None:
        """
        Internal method to run a task with semaphore control.
        
        Args:
            task: The task to run
            executor_func: Function to execute the tool
        """
        async with self._semaphore:
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now()
            logger.info(f"🚀 Starting background task: {task.name} (ID: {task.task_id})")
            
            try:
                # Build the action dict expected by execute_action
                action = {
                    "tool": task.tool_name,
                    "args": task.args
                }
                
                # Execute the tool
                result = await executor_func(action)
                
                task.result = result
                task.status = TaskStatus.COMPLETED
                task.completed_at = datetime.now()
                
                duration = (task.completed_at - task.started_at).total_seconds()
                logger.info(f"✅ Background task completed: {task.name} (ID: {task.task_id}, duration: {duration:.1f}s)")
                
            except asyncio.CancelledError:
                task.status = TaskStatus.CANCELLED
                task.completed_at = datetime.now()
                logger.warning(f"⚠️ Background task cancelled: {task.name} (ID: {task.task_id})")
                raise
                
            except Exception as e:
                task.error = str(e)
                task.status = TaskStatus.FAILED
                task.completed_at = datetime.now()
                logger.error(f"❌ Background task failed: {task.name} (ID: {task.task_id}): {e}")
    
    def get_task_status(self, task_id: str) -> Optional[BackgroundTask]:
        """
        Get the status and result of a task.
        
        Args:
            task_id: The task ID returned from dispatch_task
        
        Returns:
            BackgroundTask object or None if not found
        """
        return self._tasks.get(task_id)
    
    def get_all_tasks(self, status_filter: Optional[TaskStatus] = None) -> List[BackgroundTask]:
        """
        Get all tasks, optionally filtered by status.
        
        Args:
            status_filter: Optional status to filter by
        
        Returns:
            List of BackgroundTask objects
        """
        tasks = list(self._tasks.values())
        if status_filter:
            tasks = [t for t in tasks if t.status == status_filter]
        return tasks
    
    def get_pending_results(self) -> List[BackgroundTask]:
        """
        Get all completed tasks that have not been retrieved yet.
        
        Returns:
            List of completed BackgroundTask objects
        """
        return self.get_all_tasks(TaskStatus.COMPLETED)
    
    def get_running_tasks(self) -> List[BackgroundTask]:
        """
        Get all currently running tasks.
        
        Returns:
            List of running BackgroundTask objects
        """
        return self.get_all_tasks(TaskStatus.RUNNING)
    
    async def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a running task.
        
        Args:
            task_id: The task ID to cancel
        
        Returns:
            True if cancelled, False if task not found or already completed
        """
        task = self._tasks.get(task_id)
        if not task:
            return False
        
        if task.status not in [TaskStatus.PENDING, TaskStatus.RUNNING]:
            return False
        
        if task._asyncio_task and not task._asyncio_task.done():
            task._asyncio_task.cancel()
            logger.info(f"🛑 Cancelled task: {task.name} (ID: {task_id})")
            return True
        
        return False
    
    async def wait_for_task(self, task_id: str, timeout: float = None) -> Optional[BackgroundTask]:
        """
        Wait for a specific task to complete.
        
        Args:
            task_id: The task ID to wait for
            timeout: Optional timeout in seconds
        
        Returns:
            BackgroundTask object or None if not found/timeout
        """
        task = self._tasks.get(task_id)
        if not task or not task._asyncio_task:
            return None
        
        try:
            await asyncio.wait_for(task._asyncio_task, timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(f"⏱️ Timeout waiting for task: {task.name} (ID: {task_id})")
            return task
        except asyncio.CancelledError:
            pass
        
        return task
    
    async def wait_for_all(self, timeout: float = None) -> List[BackgroundTask]:
        """
        Wait for all pending/running tasks to complete.
        
        Args:
            timeout: Optional timeout in seconds
        
        Returns:
            List of all BackgroundTask objects
        """
        pending_tasks = [
            t._asyncio_task
            for t in self._tasks.values()
            if t._asyncio_task and not t._asyncio_task.done()
        ]
        
        if pending_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*pending_tasks, return_exceptions=True),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.warning(f"⏱️ Timeout waiting for all tasks")
        
        return list(self._tasks.values())
    
    def clear_completed(self) -> int:
        """
        Remove all completed/failed/cancelled tasks from memory.
        
        Returns:
            Number of tasks removed
        """
        to_remove = [
            task_id
            for task_id, task in self._tasks.items()
            if task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]
        ]
        
        for task_id in to_remove:
            del self._tasks[task_id]
        
        logger.info(f"🧹 Cleared {len(to_remove)} completed tasks")
        return len(to_remove)
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all task statuses.
        
        Returns:
            Dictionary with task counts by status
        """
        summary = {
            "total": len(self._tasks),
            "pending": 0,
            "running": 0,
            "completed": 0,
            "failed": 0,
            "cancelled": 0,
            "tasks": []
        }
        
        for task in self._tasks.values():
            summary[task.status.value] += 1
            summary["tasks"].append({
                "id": task.task_id,
                "name": task.name,
                "status": task.status.value,
                "tool": task.tool_name
            })
        
        return summary


# Singleton instance
_task_manager: Optional[AsyncTaskManager] = None


def get_task_manager() -> AsyncTaskManager:
    """Get the singleton task manager instance"""
    global _task_manager
    if _task_manager is None:
        _task_manager = AsyncTaskManager()
    return _task_manager
