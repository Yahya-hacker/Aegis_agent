#!/usr/bin/env python3
"""
Performance Optimization Module
================================

Provides utilities for:
- Profiling code execution
- Identifying slow code paths
- Caching mechanism for expensive operations
- Parallel execution for independent tasks
- Token usage optimization
"""

import asyncio
import logging
import time
import functools
import hashlib
import json
from typing import Dict, List, Any, Optional, Callable, TypeVar, ParamSpec
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
import pickle

logger = logging.getLogger(__name__)

T = TypeVar('T')
P = ParamSpec('P')


@dataclass
class PerformanceMetric:
    """Performance metric for a function or operation"""
    name: str
    call_count: int = 0
    total_time: float = 0.0
    avg_time: float = 0.0
    min_time: float = float('inf')
    max_time: float = 0.0
    last_called: Optional[datetime] = None


class PerformanceProfiler:
    """
    Performance profiler for tracking execution times.
    
    Usage:
        profiler = PerformanceProfiler()
        
        @profiler.profile
        async def my_function():
            # ... code ...
        
        # Get metrics
        metrics = profiler.get_metrics()
    """
    
    def __init__(self):
        """Initialize profiler"""
        self.metrics: Dict[str, PerformanceMetric] = {}
        self.enabled = True
    
    def profile(self, func: Callable[P, T]) -> Callable[P, T]:
        """
        Decorator to profile a function.
        
        Args:
            func: Function to profile
            
        Returns:
            Wrapped function with profiling
        """
        @functools.wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            if not self.enabled:
                return await func(*args, **kwargs)
            
            start_time = time.perf_counter()
            
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                end_time = time.perf_counter()
                elapsed = end_time - start_time
                
                self._record_metric(func.__name__, elapsed)
        
        @functools.wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            if not self.enabled:
                return func(*args, **kwargs)
            
            start_time = time.perf_counter()
            
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                end_time = time.perf_counter()
                elapsed = end_time - start_time
                
                self._record_metric(func.__name__, elapsed)
        
        # Return appropriate wrapper based on whether function is async
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    def _record_metric(self, name: str, elapsed: float) -> None:
        """Record a performance metric"""
        if name not in self.metrics:
            self.metrics[name] = PerformanceMetric(name=name)
        
        metric = self.metrics[name]
        metric.call_count += 1
        metric.total_time += elapsed
        metric.avg_time = metric.total_time / metric.call_count
        metric.min_time = min(metric.min_time, elapsed)
        metric.max_time = max(metric.max_time, elapsed)
        metric.last_called = datetime.now()
    
    def get_metrics(self) -> Dict[str, PerformanceMetric]:
        """Get all metrics"""
        return self.metrics.copy()
    
    def get_top_slow_functions(self, n: int = 10) -> List[PerformanceMetric]:
        """Get top N slowest functions by average time"""
        sorted_metrics = sorted(
            self.metrics.values(),
            key=lambda m: m.avg_time,
            reverse=True
        )
        return sorted_metrics[:n]
    
    def print_report(self) -> None:
        """Print performance report"""
        print("\n" + "="*80)
        print("PERFORMANCE REPORT")
        print("="*80)
        
        for metric in self.get_top_slow_functions(20):
            print(f"\n{metric.name}:")
            print(f"  Calls: {metric.call_count}")
            print(f"  Total: {metric.total_time:.3f}s")
            print(f"  Avg: {metric.avg_time:.3f}s")
            print(f"  Min: {metric.min_time:.3f}s")
            print(f"  Max: {metric.max_time:.3f}s")
        
        print("\n" + "="*80)


class CacheManager:
    """
    Cache manager for expensive operations.
    
    Supports:
    - In-memory caching
    - Disk-based caching
    - TTL (time-to-live) expiration
    - Cache invalidation
    """
    
    def __init__(self, cache_dir: Optional[Path] = None, default_ttl: int = 3600):
        """
        Initialize cache manager.
        
        Args:
            cache_dir: Directory for disk cache (None for memory-only)
            default_ttl: Default TTL in seconds
        """
        self.cache_dir = cache_dir
        self.default_ttl = default_ttl
        self.memory_cache: Dict[str, tuple] = {}  # key -> (value, expiry)
        
        if cache_dir:
            cache_dir.mkdir(exist_ok=True)
    
    def _make_key(self, func_name: str, args: tuple, kwargs: dict) -> str:
        """Generate cache key from function name and arguments"""
        key_data = {
            "func": func_name,
            "args": str(args),
            "kwargs": str(sorted(kwargs.items()))
        }
        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_str.encode()).hexdigest()
    
    def cached(self, ttl: Optional[int] = None, disk: bool = False):
        """
        Decorator for caching function results.
        
        Args:
            ttl: Time to live in seconds (None = use default)
            disk: Whether to use disk cache
            
        Returns:
            Decorator function
        """
        def decorator(func: Callable[P, T]) -> Callable[P, T]:
            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                cache_key = self._make_key(func.__name__, args, kwargs)
                cache_ttl = ttl if ttl is not None else self.default_ttl
                
                # Check cache
                cached_value = self._get_from_cache(cache_key, disk)
                if cached_value is not None:
                    logger.debug(f"Cache hit for {func.__name__}")
                    return cached_value
                
                # Execute function
                logger.debug(f"Cache miss for {func.__name__}")
                result = await func(*args, **kwargs)
                
                # Store in cache
                self._put_in_cache(cache_key, result, cache_ttl, disk)
                
                return result
            
            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                cache_key = self._make_key(func.__name__, args, kwargs)
                cache_ttl = ttl if ttl is not None else self.default_ttl
                
                # Check cache
                cached_value = self._get_from_cache(cache_key, disk)
                if cached_value is not None:
                    logger.debug(f"Cache hit for {func.__name__}")
                    return cached_value
                
                # Execute function
                logger.debug(f"Cache miss for {func.__name__}")
                result = func(*args, **kwargs)
                
                # Store in cache
                self._put_in_cache(cache_key, result, cache_ttl, disk)
                
                return result
            
            if asyncio.iscoroutinefunction(func):
                return async_wrapper
            else:
                return sync_wrapper
        
        return decorator
    
    def _get_from_cache(self, key: str, disk: bool) -> Optional[Any]:
        """Get value from cache"""
        # Try memory cache first
        if key in self.memory_cache:
            value, expiry = self.memory_cache[key]
            if datetime.now() < expiry:
                return value
            else:
                del self.memory_cache[key]
        
        # Try disk cache (with safe JSON parsing first)
        if disk and self.cache_dir:
            cache_file = self.cache_dir / f"{key}.cache"
            if cache_file.exists():
                try:
                    # Try JSON first (safer)
                    try:
                        with open(cache_file, 'r') as f:
                            cache_data = json.load(f)
                        
                        expiry = datetime.fromisoformat(cache_data["expiry"])
                        if datetime.now() < expiry:
                            return cache_data["value"]
                        else:
                            cache_file.unlink()
                    except (json.JSONDecodeError, KeyError, ValueError):
                        # Fallback to pickle (less safe)
                        with open(cache_file, 'rb') as f:
                            value, expiry = pickle.load(f)
                        
                        if datetime.now() < expiry:
                            return value
                        else:
                            cache_file.unlink()
                except Exception as e:
                    logger.warning(f"Error reading cache file: {e}")
        
        return None
    
    def _put_in_cache(self, key: str, value: Any, ttl: int, disk: bool) -> None:
        """Put value in cache"""
        expiry = datetime.now() + timedelta(seconds=ttl)
        
        # Store in memory
        self.memory_cache[key] = (value, expiry)
        
        # Store on disk using JSON where possible (safer than pickle)
        if disk and self.cache_dir:
            cache_file = self.cache_dir / f"{key}.cache"
            try:
                # Try JSON serialization first (safer)
                try:
                    cache_data = {
                        "value": value,
                        "expiry": expiry.isoformat()
                    }
                    with open(cache_file, 'w') as f:
                        json.dump(cache_data, f)
                except (TypeError, ValueError):
                    # Fallback to pickle for complex objects
                    # Note: pickle can execute arbitrary code - use with caution
                    logger.warning("Using pickle for cache storage (security risk)")
                    with open(cache_file, 'wb') as f:
                        pickle.dump((value, expiry), f)
            except Exception as e:
                logger.warning(f"Error writing cache file: {e}")
    
    def clear(self) -> None:
        """Clear all caches"""
        self.memory_cache.clear()
        
        if self.cache_dir:
            for cache_file in self.cache_dir.glob("*.cache"):
                try:
                    cache_file.unlink()
                except Exception as e:
                    logger.warning(f"Error deleting cache file: {e}")


class ParallelExecutor:
    """
    Executes independent tasks in parallel to improve performance.
    
    Usage:
        executor = ParallelExecutor(max_workers=5)
        
        results = await executor.execute_parallel([
            task1(),
            task2(),
            task3()
        ])
    """
    
    def __init__(self, max_workers: int = 10):
        """
        Initialize parallel executor.
        
        Args:
            max_workers: Maximum number of concurrent tasks
        """
        self.max_workers = max_workers
        self.semaphore = asyncio.Semaphore(max_workers)
    
    async def execute_parallel(self, tasks: List[asyncio.Task]) -> List[Any]:
        """
        Execute tasks in parallel with concurrency limit.
        
        Args:
            tasks: List of async tasks
            
        Returns:
            List of results
        """
        async def limited_task(task):
            async with self.semaphore:
                return await task
        
        results = await asyncio.gather(*[limited_task(task) for task in tasks])
        return results


class TokenOptimizer:
    """
    Optimizes LLM token usage to reduce costs.
    
    Strategies:
    - Truncate long inputs
    - Summarize repetitive content
    - Use smaller models for simple tasks
    - Batch similar requests
    """
    
    def __init__(self, max_tokens: int = 4000):
        """
        Initialize token optimizer.
        
        Args:
            max_tokens: Maximum tokens per request
        """
        self.max_tokens = max_tokens
    
    def truncate_text(self, text: str, max_length: Optional[int] = None) -> str:
        """
        Truncate text to fit within token limit.
        
        Args:
            text: Text to truncate
            max_length: Max characters (None = use default based on tokens)
            
        Returns:
            Truncated text
        """
        if max_length is None:
            # Rough estimate: 1 token ≈ 4 characters
            max_length = self.max_tokens * 4
        
        if len(text) <= max_length:
            return text
        
        # Truncate and add ellipsis
        return text[:max_length - 3] + "..."
    
    def extract_relevant_sections(self, text: str, keywords: List[str], 
                                  context_chars: int = 500) -> str:
        """
        Extract only relevant sections containing keywords.
        
        Args:
            text: Full text
            keywords: Keywords to look for
            context_chars: Characters of context around keywords
            
        Returns:
            Extracted relevant text
        """
        if not keywords:
            return self.truncate_text(text)
        
        sections = []
        text_lower = text.lower()
        
        for keyword in keywords:
            keyword_lower = keyword.lower()
            pos = 0
            
            while True:
                pos = text_lower.find(keyword_lower, pos)
                if pos == -1:
                    break
                
                # Extract context around keyword
                start = max(0, pos - context_chars // 2)
                end = min(len(text), pos + len(keyword) + context_chars // 2)
                
                section = text[start:end]
                if start > 0:
                    section = "..." + section
                if end < len(text):
                    section = section + "..."
                
                sections.append(section)
                pos += len(keyword)
        
        if not sections:
            # No keywords found, return truncated text
            return self.truncate_text(text)
        
        # Join unique sections
        combined = "\n\n".join(set(sections))
        return self.truncate_text(combined)


# Global instances
_profiler = PerformanceProfiler()
_cache_manager = CacheManager(cache_dir=Path("data/cache"), default_ttl=3600)
_parallel_executor = ParallelExecutor(max_workers=10)
_token_optimizer = TokenOptimizer(max_tokens=4000)


def get_profiler() -> PerformanceProfiler:
    """Get global profiler instance"""
    return _profiler


def get_cache_manager() -> CacheManager:
    """Get global cache manager instance"""
    return _cache_manager


def get_parallel_executor() -> ParallelExecutor:
    """Get global parallel executor instance"""
    return _parallel_executor


def get_token_optimizer() -> TokenOptimizer:
    """Get global token optimizer instance"""
    return _token_optimizer


# Convenience decorators
def profile(func: Callable[P, T]) -> Callable[P, T]:
    """Profile function execution"""
    return _profiler.profile(func)


def cached(ttl: Optional[int] = None, disk: bool = False):
    """Cache function results"""
    return _cache_manager.cached(ttl=ttl, disk=disk)


# Example usage
async def example_optimization():
    """Example of optimization features"""
    
    # Profiling
    profiler = get_profiler()
    
    @profiler.profile
    async def slow_function():
        await asyncio.sleep(1)
        return "result"
    
    await slow_function()
    profiler.print_report()
    
    # Caching
    cache = get_cache_manager()
    
    @cache.cached(ttl=60)
    async def expensive_computation(x: int) -> int:
        await asyncio.sleep(2)
        return x * 2
    
    result1 = await expensive_computation(5)  # Slow (cache miss)
    result2 = await expensive_computation(5)  # Fast (cache hit)
    
    # Parallel execution
    executor = get_parallel_executor()
    
    tasks = [
        asyncio.create_task(slow_function()),
        asyncio.create_task(slow_function()),
        asyncio.create_task(slow_function())
    ]
    
    results = await executor.execute_parallel(tasks)
    
    # Token optimization
    optimizer = get_token_optimizer()
    
    long_text = "a" * 100000
    truncated = optimizer.truncate_text(long_text)
    print(f"Truncated from {len(long_text)} to {len(truncated)} chars")


if __name__ == "__main__":
    asyncio.run(example_optimization())
