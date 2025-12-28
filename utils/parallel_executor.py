"""
Parallel Executor for Aegis AI v9.1
====================================

This module provides infrastructure for executing multiple tools, tasks,
and targets in parallel to maximize efficiency and minimize scan time.

Features:
- Concurrent tool execution with rate limiting
- Multi-target parallel scanning
- Task prioritization and scheduling
- Resource-aware execution throttling
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


class TaskPriority(Enum):
    """Priority levels for task execution"""
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    BACKGROUND = 5


class TaskStatus(Enum):
    """Status of a task"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ParallelTask:
    """Represents a task to be executed in parallel"""
    id: str
    name: str
    coroutine: Callable
    args: Dict[str, Any] = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[Any] = None
    error: Optional[str] = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    target: Optional[str] = None
    category: str = "general"
    
    @property
    def duration(self) -> Optional[float]:
        """Calculate task duration"""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None


@dataclass
class ExecutionMetrics:
    """Metrics for parallel execution"""
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    active_tasks: int = 0
    total_duration: float = 0.0
    avg_task_duration: float = 0.0
    tasks_per_second: float = 0.0


class ParallelExecutor:
    """
    Manages parallel execution of tasks with resource awareness.
    
    Features:
    - Configurable concurrency limits
    - Task prioritization
    - Resource-aware throttling
    - Progress tracking
    - Error aggregation
    """
    
    def __init__(
        self,
        max_concurrent: int = 10,
        rate_limit_per_second: float = 5.0,
        max_retries: int = 2
    ):
        """
        Initialize the Parallel Executor.
        
        Args:
            max_concurrent: Maximum number of concurrent tasks
            rate_limit_per_second: Maximum tasks to start per second
            max_retries: Maximum retries for failed tasks
        """
        self.max_concurrent = max_concurrent
        self.rate_limit_per_second = rate_limit_per_second
        self.max_retries = max_retries
        
        # Concurrency control
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.rate_limiter_lock = asyncio.Lock()
        self.last_task_time = 0.0
        
        # Task management
        self.pending_tasks: List[ParallelTask] = []
        self.running_tasks: Dict[str, ParallelTask] = {}
        self.completed_tasks: List[ParallelTask] = []
        
        # Metrics
        self.metrics = ExecutionMetrics()
        self.start_time = None
        
        # Event handlers
        self.on_task_start: Optional[Callable] = None
        self.on_task_complete: Optional[Callable] = None
        self.on_task_error: Optional[Callable] = None
        
        # Target-specific tracking
        self.target_tasks: Dict[str, List[str]] = defaultdict(list)
        
        logger.info(f"⚡ ParallelExecutor initialized (max_concurrent={max_concurrent})")
    
    async def add_task(
        self,
        task_id: str,
        name: str,
        coroutine: Callable,
        args: Optional[Dict[str, Any]] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        target: Optional[str] = None,
        category: str = "general"
    ) -> ParallelTask:
        """
        Add a task to the execution queue.
        
        Args:
            task_id: Unique identifier for the task
            name: Human-readable task name
            coroutine: Async function to execute
            args: Arguments for the coroutine
            priority: Task priority level
            target: Target this task is related to (for grouping)
            category: Task category for filtering
            
        Returns:
            The created ParallelTask
        """
        task = ParallelTask(
            id=task_id,
            name=name,
            coroutine=coroutine,
            args=args or {},
            priority=priority,
            target=target,
            category=category
        )
        
        self.pending_tasks.append(task)
        
        # Track by target
        if target:
            self.target_tasks[target].append(task_id)
        
        # Sort by priority
        self.pending_tasks.sort(key=lambda t: t.priority.value)
        
        self.metrics.total_tasks += 1
        
        logger.debug(f"📝 Task added: {name} (priority={priority.name})")
        return task
    
    async def execute_all(
        self,
        timeout: Optional[float] = None,
        stop_on_error: bool = False
    ) -> List[ParallelTask]:
        """
        Execute all pending tasks in parallel.
        
        Args:
            timeout: Maximum time to wait for all tasks
            stop_on_error: Stop all tasks if any fails
            
        Returns:
            List of completed tasks
        """
        if not self.pending_tasks:
            logger.info("No tasks to execute")
            return []
        
        self.start_time = time.time()
        logger.info(f"🚀 Starting parallel execution of {len(self.pending_tasks)} tasks")
        
        # Create task group
        async def run_with_timeout():
            tasks = []
            
            while self.pending_tasks or self.running_tasks:
                # Start new tasks up to concurrency limit
                while self.pending_tasks and len(self.running_tasks) < self.max_concurrent:
                    task = self.pending_tasks.pop(0)
                    asyncio_task = asyncio.create_task(
                        self._execute_task(task, stop_on_error)
                    )
                    tasks.append(asyncio_task)
                
                # Wait for at least one task to complete
                if tasks:
                    done, pending = await asyncio.wait(
                        tasks,
                        timeout=1.0,
                        return_when=asyncio.FIRST_COMPLETED
                    )
                    tasks = list(pending)
                else:
                    await asyncio.sleep(0.1)
        
        try:
            if timeout:
                await asyncio.wait_for(run_with_timeout(), timeout=timeout)
            else:
                await run_with_timeout()
        except asyncio.TimeoutError:
            logger.warning(f"⏱️ Execution timeout after {timeout}s")
            # Cancel remaining tasks
            for task in self.pending_tasks:
                task.status = TaskStatus.CANCELLED
                self.completed_tasks.append(task)
            self.pending_tasks.clear()
        
        # Calculate final metrics
        self._update_metrics()
        
        logger.info(
            f"✅ Execution complete: {self.metrics.completed_tasks} succeeded, "
            f"{self.metrics.failed_tasks} failed, "
            f"avg duration: {self.metrics.avg_task_duration:.2f}s"
        )
        
        return self.completed_tasks
    
    async def execute_for_targets(
        self,
        targets: List[str],
        task_generator: Callable[[str], List[ParallelTask]],
        timeout_per_target: Optional[float] = None
    ) -> Dict[str, List[ParallelTask]]:
        """
        Execute tasks for multiple targets in parallel.
        
        Args:
            targets: List of target URLs/IPs
            task_generator: Function that generates tasks for each target
            timeout_per_target: Timeout per target
            
        Returns:
            Dictionary mapping targets to their completed tasks
        """
        logger.info(f"🎯 Starting multi-target execution for {len(targets)} targets")
        
        # Generate tasks for all targets
        for target in targets:
            tasks = task_generator(target)
            for task in tasks:
                await self.add_task(
                    task_id=task.id,
                    name=task.name,
                    coroutine=task.coroutine,
                    args=task.args,
                    priority=task.priority,
                    target=target,
                    category=task.category
                )
        
        # Execute all tasks
        await self.execute_all(timeout=timeout_per_target * len(targets) if timeout_per_target else None)
        
        # Group results by target
        results: Dict[str, List[ParallelTask]] = defaultdict(list)
        for task in self.completed_tasks:
            if task.target:
                results[task.target].append(task)
            else:
                results['_general'].append(task)
        
        return dict(results)
    
    async def _execute_task(
        self,
        task: ParallelTask,
        stop_on_error: bool = False
    ) -> ParallelTask:
        """
        Execute a single task with rate limiting and error handling.
        
        Args:
            task: Task to execute
            stop_on_error: Raise exception if task fails
            
        Returns:
            The completed task
        """
        # Rate limiting
        await self._apply_rate_limit()
        
        # Acquire semaphore for concurrency control
        async with self.semaphore:
            task.status = TaskStatus.RUNNING
            task.started_at = time.time()
            self.running_tasks[task.id] = task
            self.metrics.active_tasks += 1
            
            # Notify start
            if self.on_task_start:
                await self._call_handler(self.on_task_start, task)
            
            logger.debug(f"▶️ Starting task: {task.name}")
            
            retry_count = 0
            while retry_count <= self.max_retries:
                try:
                    # Execute the coroutine
                    if asyncio.iscoroutinefunction(task.coroutine):
                        result = await task.coroutine(**task.args)
                    else:
                        result = task.coroutine(**task.args)
                    
                    task.result = result
                    task.status = TaskStatus.COMPLETED
                    self.metrics.completed_tasks += 1
                    
                    logger.debug(f"✅ Task completed: {task.name}")
                    
                    # Notify complete
                    if self.on_task_complete:
                        await self._call_handler(self.on_task_complete, task)
                    
                    break
                    
                except Exception as e:
                    retry_count += 1
                    
                    if retry_count > self.max_retries:
                        task.error = str(e)
                        task.status = TaskStatus.FAILED
                        self.metrics.failed_tasks += 1
                        
                        logger.warning(f"❌ Task failed: {task.name} - {e}")
                        
                        # Notify error
                        if self.on_task_error:
                            await self._call_handler(self.on_task_error, task, e)
                        
                        if stop_on_error:
                            raise
                    else:
                        logger.debug(f"🔄 Retrying task: {task.name} (attempt {retry_count})")
                        await asyncio.sleep(0.5 * retry_count)  # Backoff
            
            task.completed_at = time.time()
            
            # Cleanup
            del self.running_tasks[task.id]
            self.metrics.active_tasks -= 1
            self.completed_tasks.append(task)
            
            return task
    
    async def _apply_rate_limit(self) -> None:
        """Apply rate limiting between task starts"""
        async with self.rate_limiter_lock:
            current_time = time.time()
            min_interval = 1.0 / self.rate_limit_per_second
            time_since_last = current_time - self.last_task_time
            
            if time_since_last < min_interval:
                wait_time = min_interval - time_since_last
                await asyncio.sleep(wait_time)
            
            self.last_task_time = time.time()
    
    async def _call_handler(
        self,
        handler: Callable,
        *args
    ) -> None:
        """Call an event handler safely"""
        try:
            if asyncio.iscoroutinefunction(handler):
                await handler(*args)
            else:
                handler(*args)
        except Exception as e:
            logger.error(f"Event handler error: {e}")
    
    def _update_metrics(self) -> None:
        """Update execution metrics"""
        if self.start_time:
            self.metrics.total_duration = time.time() - self.start_time
        
        completed_with_duration = [
            t for t in self.completed_tasks
            if t.duration is not None
        ]
        
        if completed_with_duration:
            total_task_duration = sum(t.duration for t in completed_with_duration)
            self.metrics.avg_task_duration = (
                total_task_duration / len(completed_with_duration)
            )
        
        if self.metrics.total_duration > 0:
            self.metrics.tasks_per_second = (
                (self.metrics.completed_tasks + self.metrics.failed_tasks)
                / self.metrics.total_duration
            )
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current execution metrics"""
        self._update_metrics()
        return {
            'total_tasks': self.metrics.total_tasks,
            'completed': self.metrics.completed_tasks,
            'failed': self.metrics.failed_tasks,
            'active': self.metrics.active_tasks,
            'pending': len(self.pending_tasks),
            'total_duration': round(self.metrics.total_duration, 2),
            'avg_task_duration': round(self.metrics.avg_task_duration, 2),
            'tasks_per_second': round(self.metrics.tasks_per_second, 2)
        }
    
    def get_target_progress(self, target: str) -> Dict[str, Any]:
        """Get progress for a specific target"""
        task_ids = self.target_tasks.get(target, [])
        
        completed = sum(
            1 for task in self.completed_tasks
            if task.id in task_ids and task.status == TaskStatus.COMPLETED
        )
        failed = sum(
            1 for task in self.completed_tasks
            if task.id in task_ids and task.status == TaskStatus.FAILED
        )
        running = sum(
            1 for task_id in task_ids
            if task_id in self.running_tasks
        )
        pending = len(task_ids) - completed - failed - running
        
        return {
            'target': target,
            'total': len(task_ids),
            'completed': completed,
            'failed': failed,
            'running': running,
            'pending': pending,
            'progress': (
                (completed + failed) / len(task_ids) * 100
                if task_ids else 100
            )
        }
    
    def reset(self) -> None:
        """Reset the executor for a new execution"""
        self.pending_tasks.clear()
        self.running_tasks.clear()
        self.completed_tasks.clear()
        self.target_tasks.clear()
        self.metrics = ExecutionMetrics()
        self.start_time = None
        self.last_task_time = 0.0


class MultiTargetManager:
    """
    Manages scanning of multiple targets simultaneously.
    
    Features:
    - Concurrent target processing
    - Per-target progress tracking
    - Result aggregation
    - Priority-based scheduling
    """
    
    def __init__(
        self,
        max_concurrent_targets: int = 5,
        tasks_per_target: int = 10
    ):
        """
        Initialize the Multi-Target Manager.
        
        Args:
            max_concurrent_targets: Maximum targets to scan simultaneously
            tasks_per_target: Maximum concurrent tasks per target
        """
        self.max_concurrent_targets = max_concurrent_targets
        self.tasks_per_target = tasks_per_target
        
        # Target state
        self.targets: Dict[str, Dict[str, Any]] = {}
        self.active_targets: Set[str] = set()
        self.completed_targets: Set[str] = set()
        
        # Results
        self.results: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        
        logger.info(f"🎯 MultiTargetManager initialized")
    
    async def add_target(
        self,
        target: str,
        priority: TaskPriority = TaskPriority.NORMAL,
        config: Optional[Dict[str, Any]] = None
    ) -> None:
        """Add a target for scanning"""
        self.targets[target] = {
            'priority': priority,
            'config': config or {},
            'status': 'pending',
            'added_at': datetime.now().isoformat(),
            'started_at': None,
            'completed_at': None,
            'tasks_completed': 0,
            'tasks_failed': 0,
            'findings': []
        }
        logger.info(f"🎯 Target added: {target}")
    
    async def scan_all_targets(
        self,
        scanner,
        task_generator: Callable
    ) -> Dict[str, Any]:
        """
        Scan all targets in parallel.
        
        Args:
            scanner: AegisScanner instance
            task_generator: Function to generate scan tasks for each target
            
        Returns:
            Aggregated results from all targets
        """
        pending_targets = [
            t for t in self.targets.keys()
            if t not in self.completed_targets
        ]
        
        if not pending_targets:
            return {'status': 'no_targets', 'results': {}}
        
        logger.info(f"🚀 Starting scan of {len(pending_targets)} targets")
        
        # Create semaphore for concurrent targets
        target_semaphore = asyncio.Semaphore(self.max_concurrent_targets)
        
        async def scan_target(target: str) -> Dict[str, Any]:
            async with target_semaphore:
                self.active_targets.add(target)
                self.targets[target]['status'] = 'scanning'
                self.targets[target]['started_at'] = datetime.now().isoformat()
                
                logger.info(f"🔍 Scanning target: {target}")
                
                try:
                    # Generate and execute tasks for this target
                    tasks = task_generator(target)
                    
                    # Create executor for this target
                    executor = ParallelExecutor(
                        max_concurrent=self.tasks_per_target,
                        rate_limit_per_second=2.0
                    )
                    
                    for task in tasks:
                        await executor.add_task(
                            task_id=f"{target}_{task['name']}",
                            name=task['name'],
                            coroutine=task['func'],
                            args=task.get('args', {}),
                            target=target
                        )
                    
                    completed = await executor.execute_all()
                    
                    # Aggregate results
                    target_results = []
                    for task in completed:
                        if task.status == TaskStatus.COMPLETED:
                            target_results.append({
                                'task': task.name,
                                'result': task.result,
                                'duration': task.duration
                            })
                            self.targets[target]['tasks_completed'] += 1
                        else:
                            self.targets[target]['tasks_failed'] += 1
                    
                    self.results[target] = target_results
                    self.targets[target]['status'] = 'completed'
                    self.targets[target]['completed_at'] = datetime.now().isoformat()
                    
                    logger.info(f"✅ Target scan completed: {target}")
                    
                    return {
                        'target': target,
                        'status': 'success',
                        'results': target_results,
                        'metrics': executor.get_metrics()
                    }
                    
                except Exception as e:
                    logger.error(f"❌ Target scan failed: {target} - {e}")
                    self.targets[target]['status'] = 'failed'
                    self.targets[target]['error'] = str(e)
                    
                    return {
                        'target': target,
                        'status': 'error',
                        'error': str(e)
                    }
                finally:
                    self.active_targets.discard(target)
                    self.completed_targets.add(target)
        
        # Scan all targets in parallel
        results = await asyncio.gather(
            *[scan_target(t) for t in pending_targets],
            return_exceptions=True
        )
        
        # Aggregate final results
        return {
            'status': 'completed',
            'total_targets': len(pending_targets),
            'successful': sum(1 for r in results if isinstance(r, dict) and r.get('status') == 'success'),
            'failed': sum(1 for r in results if isinstance(r, dict) and r.get('status') == 'error'),
            'results': {
                r['target']: r for r in results if isinstance(r, dict)
            }
        }
    
    def get_all_progress(self) -> Dict[str, Any]:
        """Get progress for all targets"""
        return {
            'total_targets': len(self.targets),
            'active': len(self.active_targets),
            'completed': len(self.completed_targets),
            'pending': len(self.targets) - len(self.completed_targets) - len(self.active_targets),
            'targets': {
                target: {
                    'status': info['status'],
                    'tasks_completed': info['tasks_completed'],
                    'tasks_failed': info['tasks_failed'],
                }
                for target, info in self.targets.items()
            }
        }


# Global instances
_executor_instance: Optional[ParallelExecutor] = None
_multi_target_instance: Optional[MultiTargetManager] = None


def get_parallel_executor(
    max_concurrent: int = 10,
    rate_limit: float = 5.0
) -> ParallelExecutor:
    """Get the global ParallelExecutor instance"""
    global _executor_instance
    if _executor_instance is None:
        _executor_instance = ParallelExecutor(
            max_concurrent=max_concurrent,
            rate_limit_per_second=rate_limit
        )
    return _executor_instance


def get_multi_target_manager(
    max_targets: int = 5
) -> MultiTargetManager:
    """Get the global MultiTargetManager instance"""
    global _multi_target_instance
    if _multi_target_instance is None:
        _multi_target_instance = MultiTargetManager(
            max_concurrent_targets=max_targets
        )
    return _multi_target_instance
