#!/usr/bin/env python3
"""
Performance Optimization Module
================================

Provides utilities for:
- Profiling code execution
- Identifying slow code paths
- Caching mechanism for expensive operations (JSON-based, secure)
- Parallel execution for independent tasks
- Token usage optimization

Security Note:
    This module uses JSON serialization exclusively. Pickle is NOT used
    due to its vulnerability to arbitrary code execution attacks.
    For complex objects, a custom JSON encoder handles datetime objects
    and provides safe serialization.
"""

import asyncio
import logging
import time
import functools
import hashlib
import json
from typing import Dict, List, Any, Optional, Callable, TypeVar, ParamSpec, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path

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


class SecureJSONEncoder(json.JSONEncoder):
    """
    Secure JSON encoder that handles datetime objects and other common types.
    
    This encoder is used instead of pickle to prevent arbitrary code execution
    vulnerabilities that come with deserializing untrusted pickle data.
    
    Supported types beyond standard JSON:
    - datetime objects (ISO format)
    - date objects (ISO format)
    - timedelta objects (total seconds)
    - Path objects (string representation)
    - bytes (base64 encoded with marker)
    - sets (converted to lists with marker)
    - dataclasses (converted to dict)
    """
    
    def default(self, obj: Any) -> Any:
        """
        Encode non-standard types to JSON-safe representations.
        
        Args:
            obj: Object to encode
            
        Returns:
            JSON-serializable representation
        """
        if isinstance(obj, datetime):
            return {"__type__": "datetime", "value": obj.isoformat()}
        elif hasattr(obj, 'isoformat'):  # date-like objects
            return {"__type__": "date", "value": obj.isoformat()}
        elif isinstance(obj, timedelta):
            return {"__type__": "timedelta", "value": obj.total_seconds()}
        elif isinstance(obj, Path):
            return {"__type__": "path", "value": str(obj)}
        elif isinstance(obj, bytes):
            import base64
            return {"__type__": "bytes", "value": base64.b64encode(obj).decode('ascii')}
        elif isinstance(obj, set):
            return {"__type__": "set", "value": list(obj)}
        elif isinstance(obj, frozenset):
            return {"__type__": "frozenset", "value": list(obj)}
        elif hasattr(obj, '__dataclass_fields__'):
            return {"__type__": "dataclass", "class": type(obj).__name__, "value": asdict(obj)}
        
        # Let the base class raise TypeError for truly unsupported types
        return super().default(obj)


def secure_json_decoder(obj: Dict[str, Any]) -> Any:
    """
    Decode JSON objects with type markers back to Python objects.
    
    This function is used as an object_hook for json.load/loads to
    reconstruct special types that were encoded by SecureJSONEncoder.
    
    Args:
        obj: Dictionary that may contain type markers
        
    Returns:
        Decoded Python object
    """
    if "__type__" not in obj:
        return obj
    
    type_marker = obj["__type__"]
    value = obj.get("value")
    
    if type_marker == "datetime":
        return datetime.fromisoformat(value)
    elif type_marker == "date":
        from datetime import date
        return date.fromisoformat(value)
    elif type_marker == "timedelta":
        return timedelta(seconds=value)
    elif type_marker == "path":
        return Path(value)
    elif type_marker == "bytes":
        import base64
        return base64.b64decode(value.encode('ascii'))
    elif type_marker == "set":
        return set(value)
    elif type_marker == "frozenset":
        return frozenset(value)
    elif type_marker == "dataclass":
        # For dataclasses, return as dict (can't reconstruct without class reference)
        return value
    
    return obj


class CacheManager:
    """
    Secure cache manager for expensive operations.
    
    Supports:
    - In-memory caching
    - Disk-based caching (JSON only - no pickle for security)
    - TTL (time-to-live) expiration
    - Cache invalidation
    
    Security:
        This implementation uses JSON exclusively for disk caching.
        Pickle is NOT used due to its vulnerability to arbitrary code
        execution attacks when deserializing untrusted data.
        
        For complex objects that cannot be JSON-serialized, the cache
        will store only in memory or raise an error for disk caching.
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
            cache_dir.mkdir(exist_ok=True, parents=True)
    
    def _make_key(self, func_name: str, args: tuple, kwargs: dict) -> str:
        """
        Generate cache key from function name and arguments.
        
        Args:
            func_name: Name of the cached function
            args: Positional arguments
            kwargs: Keyword arguments
            
        Returns:
            SHA256 hash of the key data
        """
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
        """
        Get value from cache (memory first, then disk).
        
        Args:
            key: Cache key
            disk: Whether to check disk cache
            
        Returns:
            Cached value or None if not found/expired
        """
        # Try memory cache first
        if key in self.memory_cache:
            value, expiry = self.memory_cache[key]
            if datetime.now() < expiry:
                return value
            else:
                del self.memory_cache[key]
        
        # Try disk cache (JSON only - no pickle for security)
        if disk and self.cache_dir:
            cache_file = self.cache_dir / f"{key}.json"
            # Also check legacy .cache files (but only parse JSON, not pickle)
            legacy_cache_file = self.cache_dir / f"{key}.cache"
            
            for file_path in [cache_file, legacy_cache_file]:
                if file_path.exists():
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            cache_data = json.load(f, object_hook=secure_json_decoder)
                        
                        # Handle both old and new format
                        if isinstance(cache_data, dict) and "expiry" in cache_data:
                            expiry_value = cache_data["expiry"]
                            if isinstance(expiry_value, str):
                                expiry = datetime.fromisoformat(expiry_value)
                            elif isinstance(expiry_value, datetime):
                                expiry = expiry_value
                            else:
                                logger.warning(f"Invalid expiry format in cache: {type(expiry_value)}")
                                file_path.unlink(missing_ok=True)
                                continue
                            
                            if datetime.now() < expiry:
                                # Store in memory for faster future access
                                self.memory_cache[key] = (cache_data["value"], expiry)
                                return cache_data["value"]
                            else:
                                # Cache expired, delete file
                                file_path.unlink(missing_ok=True)
                        
                    except json.JSONDecodeError as e:
                        # Invalid JSON - could be old pickle file, delete it
                        logger.warning(f"Invalid JSON cache file (possibly legacy pickle), removing: {e}")
                        try:
                            file_path.unlink(missing_ok=True)
                        except Exception:
                            pass
                    except Exception as e:
                        logger.warning(f"Error reading cache file {file_path}: {e}")
        
        return None
    
    def _put_in_cache(self, key: str, value: Any, ttl: int, disk: bool) -> None:
        """
        Put value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
            disk: Whether to also store on disk
            
        Note:
            Disk caching uses JSON only. If the value cannot be serialized
            to JSON (even with the custom encoder), only memory caching is used.
        """
        expiry = datetime.now() + timedelta(seconds=ttl)
        
        # Store in memory
        self.memory_cache[key] = (value, expiry)
        
        # Store on disk using JSON only (secure - no pickle)
        if disk and self.cache_dir:
            cache_file = self.cache_dir / f"{key}.json"
            try:
                cache_data = {
                    "value": value,
                    "expiry": expiry.isoformat(),
                    "created": datetime.now().isoformat(),
                    "ttl": ttl
                }
                with open(cache_file, 'w', encoding='utf-8') as f:
                    json.dump(cache_data, f, cls=SecureJSONEncoder, indent=2)
                    
            except (TypeError, ValueError) as e:
                # Cannot serialize to JSON - only keep in memory
                # This is safer than using pickle which has code execution risks
                logger.warning(
                    f"Cannot serialize value to JSON for disk cache (key={key[:16]}...): {e}. "
                    f"Value will only be cached in memory."
                )
            except Exception as e:
                logger.warning(f"Error writing cache file: {e}")
    
    def clear(self) -> None:
        """Clear all caches (memory and disk)."""
        self.memory_cache.clear()
        
        if self.cache_dir:
            # Clear both .json (new format) and .cache (legacy format) files
            for pattern in ["*.json", "*.cache"]:
                for cache_file in self.cache_dir.glob(pattern):
                    try:
                        cache_file.unlink()
                    except Exception as e:
                        logger.warning(f"Error deleting cache file {cache_file}: {e}")


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
