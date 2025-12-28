"""
Parallel Execution Engine for Aegis Agent
Enables concurrent execution of multiple tasks, tools, and operations
Version 1.0 - High-Performance Parallel Processing
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Callable, Coroutine
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class TaskPriority(Enum):
    """Task priority levels"""
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4


class TaskStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ParallelTask:
    """Represents a task to be executed in parallel"""
    task_id: str
    name: str
    coroutine: Coroutine
    priority: TaskPriority = TaskPriority.NORMAL
    timeout: Optional[float] = None
    dependencies: List[str] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    result: Any = None
    error: Optional[Exception] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    
    @property
    def execution_time(self) -> Optional[float]:
        """Calculate execution time"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None


class ParallelExecutionEngine:
    """
    High-performance parallel execution engine for concurrent operations.
    
    Features:
    - Concurrent task execution with configurable limits
    - Task prioritization and scheduling
    - Dependency management
    - Timeout handling
    - Error isolation and recovery
    - Performance monitoring and metrics
    """
    
    def __init__(self, max_concurrent_tasks: int = 10, default_timeout: float = 120.0):
        """
        Initialize the parallel execution engine.
        
        Args:
            max_concurrent_tasks: Maximum number of concurrent tasks (default: 10)
            default_timeout: Default timeout for tasks in seconds (default: 120)
        """
        self.max_concurrent_tasks = max_concurrent_tasks
        self.default_timeout = default_timeout
        self.tasks: Dict[str, ParallelTask] = {}
        self.semaphore = asyncio.Semaphore(max_concurrent_tasks)
        self.metrics = {
            "total_tasks": 0,
            "completed_tasks": 0,
            "failed_tasks": 0,
            "cancelled_tasks": 0,
            "total_execution_time": 0.0
        }
        
        logger.info(f"✅ Parallel Execution Engine initialized (max_concurrent: {max_concurrent_tasks})")
    
    async def submit_task(
        self,
        task_id: str,
        name: str,
        coroutine: Coroutine,
        priority: TaskPriority = TaskPriority.NORMAL,
        timeout: Optional[float] = None,
        dependencies: Optional[List[str]] = None
    ) -> str:
        """
        Submit a task for parallel execution.
        
        Args:
            task_id: Unique identifier for the task
            name: Human-readable task name
            coroutine: The async coroutine to execute
            priority: Task priority level
            timeout: Task-specific timeout (uses default if None)
            dependencies: List of task IDs that must complete before this task
            
        Returns:
            Task ID
        """
        if task_id in self.tasks:
            logger.warning(f"Task {task_id} already exists, replacing")
        
        task = ParallelTask(
            task_id=task_id,
            name=name,
            coroutine=coroutine,
            priority=priority,
            timeout=timeout or self.default_timeout,
            dependencies=dependencies or []
        )
        
        self.tasks[task_id] = task
        self.metrics["total_tasks"] += 1
        
        logger.info(f"📝 Task submitted: {name} (ID: {task_id}, Priority: {priority.name})")
        
        return task_id
    
    async def execute_all(
        self,
        wait_for_completion: bool = True,
        cancel_on_error: bool = False
    ) -> Dict[str, Any]:
        """
        Execute all submitted tasks in parallel.
        
        Args:
            wait_for_completion: Wait for all tasks to complete
            cancel_on_error: Cancel remaining tasks if any task fails
            
        Returns:
            Execution results and metrics
        """
        logger.info(f"🚀 Starting parallel execution of {len(self.tasks)} tasks")
        
        # Sort tasks by priority
        sorted_tasks = sorted(
            self.tasks.values(),
            key=lambda t: (t.priority.value, t.task_id)
        )
        
        # Create execution tasks
        execution_futures = []
        
        for task in sorted_tasks:
            future = asyncio.create_task(self._execute_task_with_deps(task, cancel_on_error))
            execution_futures.append(future)
        
        if wait_for_completion:
            # Wait for all tasks
            await asyncio.gather(*execution_futures, return_exceptions=True)
        
        # Compile results
        results = self._compile_results()
        
        logger.info(f"✅ Parallel execution completed: {results['summary']}")
        
        return results
    
    async def _execute_task_with_deps(
        self,
        task: ParallelTask,
        cancel_on_error: bool
    ) -> Any:
        """Execute a task after waiting for its dependencies"""
        try:
            # Wait for dependencies
            if task.dependencies:
                await self._wait_for_dependencies(task)
            
            # Execute the task
            return await self._execute_task(task)
            
        except Exception as e:
            logger.error(f"Failed to execute task {task.name}: {e}", exc_info=True)
            task.status = TaskStatus.FAILED
            task.error = e
            self.metrics["failed_tasks"] += 1
            
            if cancel_on_error:
                await self._cancel_remaining_tasks()
            
            return None
    
    async def _wait_for_dependencies(self, task: ParallelTask):
        """Wait for task dependencies to complete"""
        logger.debug(f"⏳ Task {task.name} waiting for dependencies: {task.dependencies}")
        
        while True:
            all_complete = True
            
            for dep_id in task.dependencies:
                if dep_id not in self.tasks:
                    logger.error(f"Dependency {dep_id} not found for task {task.name}")
                    raise ValueError(f"Dependency {dep_id} not found")
                
                dep_task = self.tasks[dep_id]
                
                if dep_task.status == TaskStatus.FAILED:
                    raise RuntimeError(f"Dependency {dep_id} failed")
                
                if dep_task.status not in [TaskStatus.COMPLETED, TaskStatus.CANCELLED]:
                    all_complete = False
                    break
            
            if all_complete:
                break
            
            # Wait a bit before checking again
            await asyncio.sleep(0.1)
        
        logger.debug(f"✅ All dependencies met for task {task.name}")
    
    async def _execute_task(self, task: ParallelTask) -> Any:
        """Execute a single task with resource limiting"""
        async with self.semaphore:
            try:
                task.status = TaskStatus.RUNNING
                task.start_time = asyncio.get_event_loop().time()
                
                logger.info(f"▶️  Executing: {task.name} (Priority: {task.priority.name})")
                
                # Execute with timeout
                result = await asyncio.wait_for(task.coroutine, timeout=task.timeout)
                
                task.result = result
                task.status = TaskStatus.COMPLETED
                task.end_time = asyncio.get_event_loop().time()
                
                self.metrics["completed_tasks"] += 1
                if task.execution_time:
                    self.metrics["total_execution_time"] += task.execution_time
                
                logger.info(f"✅ Completed: {task.name} ({task.execution_time:.2f}s)")
                
                return result
                
            except asyncio.TimeoutError:
                task.status = TaskStatus.FAILED
                task.error = TimeoutError(f"Task {task.name} timed out after {task.timeout}s")
                task.end_time = asyncio.get_event_loop().time()
                
                logger.error(f"⏱️  Timeout: {task.name}")
                self.metrics["failed_tasks"] += 1
                
                return None
                
            except Exception as e:
                task.status = TaskStatus.FAILED
                task.error = e
                task.end_time = asyncio.get_event_loop().time()
                
                logger.error(f"❌ Failed: {task.name} - {str(e)}")
                self.metrics["failed_tasks"] += 1
                
                return None
    
    async def _cancel_remaining_tasks(self):
        """Cancel all pending tasks"""
        for task in self.tasks.values():
            if task.status == TaskStatus.PENDING:
                task.status = TaskStatus.CANCELLED
                self.metrics["cancelled_tasks"] += 1
        
        logger.warning("⚠️  Cancelled remaining tasks due to error")
    
    def _compile_results(self) -> Dict[str, Any]:
        """Compile execution results and metrics"""
        completed = [t for t in self.tasks.values() if t.status == TaskStatus.COMPLETED]
        failed = [t for t in self.tasks.values() if t.status == TaskStatus.FAILED]
        cancelled = [t for t in self.tasks.values() if t.status == TaskStatus.CANCELLED]
        
        avg_execution_time = (
            self.metrics["total_execution_time"] / self.metrics["completed_tasks"]
            if self.metrics["completed_tasks"] > 0
            else 0.0
        )
        
        return {
            "summary": f"{len(completed)} completed, {len(failed)} failed, {len(cancelled)} cancelled",
            "metrics": {
                "total_tasks": self.metrics["total_tasks"],
                "completed": len(completed),
                "failed": len(failed),
                "cancelled": len(cancelled),
                "success_rate": f"{(len(completed) / self.metrics['total_tasks'] * 100):.1f}%",
                "avg_execution_time": f"{avg_execution_time:.2f}s",
                "total_execution_time": f"{self.metrics['total_execution_time']:.2f}s"
            },
            "completed_tasks": [
                {
                    "id": t.task_id,
                    "name": t.name,
                    "execution_time": f"{t.execution_time:.2f}s" if t.execution_time else "N/A",
                    "result": t.result
                }
                for t in completed
            ],
            "failed_tasks": [
                {
                    "id": t.task_id,
                    "name": t.name,
                    "error": str(t.error)
                }
                for t in failed
            ]
        }
    
    async def execute_batch(
        self,
        tasks: List[Callable[..., Coroutine]],
        task_names: Optional[List[str]] = None,
        priority: TaskPriority = TaskPriority.NORMAL
    ) -> List[Any]:
        """
        Execute a batch of tasks in parallel (convenience method).
        
        Args:
            tasks: List of coroutines to execute
            task_names: Optional list of task names
            priority: Priority for all tasks in the batch
            
        Returns:
            List of results
        """
        if task_names and len(task_names) != len(tasks):
            raise ValueError("task_names length must match tasks length")
        
        # Submit all tasks
        for i, task_coro in enumerate(tasks):
            task_name = task_names[i] if task_names else f"BatchTask_{i}"
            task_id = f"batch_{datetime.now().timestamp()}_{i}"
            await self.submit_task(task_id, task_name, task_coro, priority)
        
        # Execute all
        results = await self.execute_all()
        
        # Return just the results
        return [t["result"] for t in results["completed_tasks"]]
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific task"""
        if task_id not in self.tasks:
            return None
        
        task = self.tasks[task_id]
        
        return {
            "task_id": task.task_id,
            "name": task.name,
            "status": task.status.value,
            "priority": task.priority.name,
            "execution_time": f"{task.execution_time:.2f}s" if task.execution_time else None,
            "error": str(task.error) if task.error else None,
            "result_available": task.result is not None
        }
    
    def clear_completed_tasks(self):
        """Clear completed tasks to free memory"""
        completed_count = 0
        
        for task_id in list(self.tasks.keys()):
            if self.tasks[task_id].status in [TaskStatus.COMPLETED, TaskStatus.CANCELLED]:
                del self.tasks[task_id]
                completed_count += 1
        
        logger.info(f"🧹 Cleared {completed_count} completed tasks")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current execution metrics"""
        return dict(self.metrics)


# Global instance
_parallel_engine: Optional[ParallelExecutionEngine] = None


def get_parallel_engine(max_concurrent: int = 10) -> ParallelExecutionEngine:
    """Get or create global parallel execution engine instance"""
    global _parallel_engine
    
    if _parallel_engine is None:
        _parallel_engine = ParallelExecutionEngine(max_concurrent_tasks=max_concurrent)
    
    return _parallel_engine


async def run_parallel(
    tasks: List[Coroutine],
    max_concurrent: int = 10,
    timeout: float = 120.0
) -> List[Any]:
    """
    Convenience function to run tasks in parallel.
    
    Args:
        tasks: List of coroutines to execute
        max_concurrent: Maximum concurrent tasks
        timeout: Default timeout for each task (default: 120 seconds)
        
    Returns:
        List of results
    """
    engine = ParallelExecutionEngine(max_concurrent_tasks=max_concurrent, default_timeout=timeout)
    
    for i, task_coro in enumerate(tasks):
        await engine.submit_task(
            task_id=f"task_{i}",
            name=f"Task {i}",
            coroutine=task_coro
        )
    
    results = await engine.execute_all()
    return [t["result"] for t in results["completed_tasks"]]
