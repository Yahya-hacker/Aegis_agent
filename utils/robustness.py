#!/usr/bin/env python3
"""
AEGIS OMEGA PROTOCOL - Robustness and Bottleneck Prevention
============================================================

This module provides safeguards, error handling, and bottleneck prevention
for the SOTA features:

1. Timeout and retry mechanisms
2. Graceful degradation when services are unavailable
3. Circuit breaker patterns
4. Rate limiting and backpressure
5. Error recovery strategies

Anticipates and prevents common problems that could cause the agent to get stuck.
"""

import asyncio
import logging
import time
import functools
from typing import Any, Callable, Dict, List, Optional, TypeVar, Awaitable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

T = TypeVar('T')


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject immediately
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker"""
    failure_threshold: int = 5  # Failures before opening
    recovery_timeout: float = 30.0  # Seconds before trying again
    half_open_max_calls: int = 3  # Test calls in half-open state


class CircuitBreaker:
    """
    Circuit breaker pattern to prevent cascading failures.
    
    If a service fails repeatedly, the circuit opens and rejects
    calls immediately instead of waiting for timeouts.
    """
    
    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[float] = None
        self.half_open_calls = 0
    
    def can_execute(self) -> bool:
        """Check if we can execute a call"""
        if self.state == CircuitState.CLOSED:
            return True
        
        if self.state == CircuitState.OPEN:
            # Check if recovery timeout has passed
            if self.last_failure_time:
                elapsed = time.time() - self.last_failure_time
                if elapsed >= self.config.recovery_timeout:
                    logger.info(f"🔄 Circuit {self.name}: Transitioning to HALF_OPEN")
                    self.state = CircuitState.HALF_OPEN
                    self.half_open_calls = 0
                    return True
            return False
        
        if self.state == CircuitState.HALF_OPEN:
            return self.half_open_calls < self.config.half_open_max_calls
        
        return False
    
    def record_success(self) -> None:
        """Record a successful call"""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.half_open_max_calls:
                logger.info(f"✅ Circuit {self.name}: Recovered, closing circuit")
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.success_count = 0
        else:
            self.failure_count = max(0, self.failure_count - 1)
    
    def record_failure(self) -> None:
        """Record a failed call"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.state == CircuitState.HALF_OPEN:
            logger.warning(f"⚠️ Circuit {self.name}: Failure in HALF_OPEN, reopening")
            self.state = CircuitState.OPEN
            self.half_open_calls = 0
        elif self.failure_count >= self.config.failure_threshold:
            logger.warning(f"🔴 Circuit {self.name}: Threshold reached, opening circuit")
            self.state = CircuitState.OPEN
    
    def get_status(self) -> Dict[str, Any]:
        """Get circuit status"""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "last_failure": self.last_failure_time
        }


class RetryPolicy:
    """
    Retry policy with exponential backoff and jitter.
    
    Prevents retry storms and gives services time to recover.
    """
    
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        exponential_base: float = 2.0,
        jitter: float = 0.1
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter
    
    def get_delay(self, attempt: int) -> float:
        """Calculate delay for a given attempt"""
        import random
        
        delay = self.base_delay * (self.exponential_base ** attempt)
        delay = min(delay, self.max_delay)
        
        # Add jitter
        jitter_range = delay * self.jitter
        delay += random.uniform(-jitter_range, jitter_range)
        
        return max(0, delay)
    
    def should_retry(self, attempt: int, exception: Exception) -> bool:
        """Determine if we should retry based on attempt and exception type"""
        if attempt >= self.max_retries:
            return False
        
        # Retry on transient errors
        transient_errors = (
            asyncio.TimeoutError,
            ConnectionError,
            OSError,
        )
        
        # Check for HTTP-like transient errors
        error_str = str(exception).lower()
        transient_messages = [
            "timeout",
            "connection",
            "temporary",
            "503",
            "502",
            "429",
            "rate limit",
        ]
        
        if isinstance(exception, transient_errors):
            return True
        
        for msg in transient_messages:
            if msg in error_str:
                return True
        
        return False


def with_retry(
    policy: Optional[RetryPolicy] = None,
    circuit_breaker: Optional[CircuitBreaker] = None
) -> Callable:
    """
    Decorator for async functions with retry and circuit breaker.
    
    Args:
        policy: Retry policy to use
        circuit_breaker: Optional circuit breaker
        
    Returns:
        Decorated function
    """
    if policy is None:
        policy = RetryPolicy()
    
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            # Check circuit breaker
            if circuit_breaker and not circuit_breaker.can_execute():
                raise CircuitOpenError(
                    f"Circuit {circuit_breaker.name} is open, rejecting call"
                )
            
            last_exception = None
            
            for attempt in range(policy.max_retries + 1):
                try:
                    if circuit_breaker:
                        circuit_breaker.half_open_calls += 1
                    
                    result = await func(*args, **kwargs)
                    
                    if circuit_breaker:
                        circuit_breaker.record_success()
                    
                    return result
                    
                except Exception as e:
                    last_exception = e
                    
                    if circuit_breaker:
                        circuit_breaker.record_failure()
                    
                    if policy.should_retry(attempt, e):
                        delay = policy.get_delay(attempt)
                        logger.warning(
                            f"Retry {attempt + 1}/{policy.max_retries} for "
                            f"{func.__name__} after {delay:.2f}s: {e}"
                        )
                        await asyncio.sleep(delay)
                    else:
                        break
            
            # All retries exhausted
            raise last_exception
        
        return wrapper
    return decorator


class CircuitOpenError(Exception):
    """Raised when circuit breaker is open"""
    pass


@dataclass
class RateLimiter:
    """
    Token bucket rate limiter for preventing request floods.
    """
    rate: float  # Tokens per second
    capacity: float  # Maximum tokens
    tokens: float = field(default=None)
    last_update: float = field(default=None)
    
    def __post_init__(self):
        if self.tokens is None:
            self.tokens = self.capacity
        if self.last_update is None:
            self.last_update = time.time()
    
    def acquire(self, tokens: float = 1.0) -> bool:
        """Try to acquire tokens, returns True if successful"""
        self._refill()
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False
    
    async def wait_for_token(self, tokens: float = 1.0) -> None:
        """Wait until tokens are available"""
        while not self.acquire(tokens):
            wait_time = (tokens - self.tokens) / self.rate
            await asyncio.sleep(min(wait_time, 1.0))
    
    def _refill(self) -> None:
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_update = now


class TimeoutManager:
    """
    Manages timeouts for different operation types.
    
    Prevents operations from hanging indefinitely.
    """
    
    # Default timeouts for different operations (in seconds)
    DEFAULT_TIMEOUTS = {
        "http_request": 30,
        "git_clone": 120,
        "code_analysis": 60,
        "llm_call": 120,
        "file_operation": 30,
        "database_query": 15,
        "network_scan": 300,
        "vulnerability_scan": 600,
    }
    
    def __init__(self, custom_timeouts: Optional[Dict[str, int]] = None):
        self.timeouts = {**self.DEFAULT_TIMEOUTS}
        if custom_timeouts:
            self.timeouts.update(custom_timeouts)
    
    def get_timeout(self, operation_type: str) -> int:
        """Get timeout for operation type"""
        return self.timeouts.get(operation_type, 60)  # Default 60s
    
    async def with_timeout(
        self,
        operation_type: str,
        coro: Awaitable[T],
        fallback: Optional[T] = None
    ) -> T:
        """
        Execute coroutine with timeout and optional fallback.
        
        Args:
            operation_type: Type of operation for timeout lookup
            coro: Coroutine to execute
            fallback: Value to return on timeout (raises if None)
            
        Returns:
            Result of coroutine or fallback value
        """
        timeout = self.get_timeout(operation_type)
        
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            if fallback is not None:
                logger.warning(
                    f"Operation {operation_type} timed out after {timeout}s, "
                    f"using fallback"
                )
                return fallback
            raise


class BottleneckDetector:
    """
    Detects bottlenecks and stuck states in the agent.
    
    Monitors operation duration and identifies when the agent
    might be stuck in an infinite loop or waiting too long.
    """
    
    def __init__(
        self,
        stuck_threshold: float = 300.0,  # 5 minutes
        loop_detection_window: int = 10
    ):
        self.stuck_threshold = stuck_threshold
        self.loop_detection_window = loop_detection_window
        
        self.operation_start_time: Optional[float] = None
        self.current_operation: Optional[str] = None
        self.operation_history: List[Dict[str, Any]] = []
    
    def start_operation(self, operation: str) -> None:
        """Mark start of an operation"""
        self.operation_start_time = time.time()
        self.current_operation = operation
        
        self.operation_history.append({
            "operation": operation,
            "start_time": self.operation_start_time,
            "end_time": None,
            "duration": None
        })
        
        # Trim history
        if len(self.operation_history) > 100:
            self.operation_history = self.operation_history[-50:]
    
    def end_operation(self) -> float:
        """Mark end of current operation, returns duration"""
        if self.operation_start_time is None:
            return 0.0
        
        duration = time.time() - self.operation_start_time
        
        if self.operation_history:
            self.operation_history[-1]["end_time"] = time.time()
            self.operation_history[-1]["duration"] = duration
        
        self.operation_start_time = None
        self.current_operation = None
        
        return duration
    
    def is_stuck(self) -> bool:
        """Check if current operation is taking too long"""
        if self.operation_start_time is None:
            return False
        
        duration = time.time() - self.operation_start_time
        return duration > self.stuck_threshold
    
    def detect_loop(self) -> Optional[str]:
        """
        Detect if the agent is stuck in a loop.
        
        Returns:
            Description of detected loop, or None
        """
        if len(self.operation_history) < self.loop_detection_window:
            return None
        
        recent = self.operation_history[-self.loop_detection_window:]
        operations = [op["operation"] for op in recent]
        
        # Check for exact repetition
        if len(set(operations)) == 1:
            return f"Repeating same operation: {operations[0]}"
        
        # Check for pattern (A, B, A, B, ...)
        if len(operations) >= 4:
            half = len(operations) // 2
            first_half = operations[:half]
            second_half = operations[half:half*2]
            if first_half == second_half:
                return f"Pattern repetition detected: {first_half}"
        
        return None
    
    def get_recommendations(self) -> List[str]:
        """Get recommendations for addressing bottlenecks"""
        recommendations = []
        
        if self.is_stuck():
            recommendations.append(
                f"Operation '{self.current_operation}' running for "
                f"{time.time() - self.operation_start_time:.0f}s - consider timeout"
            )
        
        loop = self.detect_loop()
        if loop:
            recommendations.append(
                f"Possible loop detected: {loop} - consider different approach"
            )
        
        # Analyze operation durations
        if self.operation_history:
            slow_ops = [
                op for op in self.operation_history
                if op.get("duration") and op["duration"] > 60
            ]
            if len(slow_ops) > 3:
                recommendations.append(
                    f"{len(slow_ops)} operations took >60s - consider optimization"
                )
        
        return recommendations


class GracefulDegradation:
    """
    Handles graceful degradation when services are unavailable.
    
    Provides fallback behaviors for when components fail.
    """
    
    def __init__(self):
        self.degraded_services: Dict[str, datetime] = {}
        self.fallback_handlers: Dict[str, Callable] = {}
    
    def register_fallback(
        self,
        service_name: str,
        fallback_handler: Callable
    ) -> None:
        """Register a fallback handler for a service"""
        self.fallback_handlers[service_name] = fallback_handler
    
    def mark_degraded(self, service_name: str) -> None:
        """Mark a service as degraded"""
        self.degraded_services[service_name] = datetime.now()
        logger.warning(f"⚠️ Service {service_name} marked as degraded")
    
    def mark_recovered(self, service_name: str) -> None:
        """Mark a service as recovered"""
        if service_name in self.degraded_services:
            del self.degraded_services[service_name]
            logger.info(f"✅ Service {service_name} recovered")
    
    def is_degraded(self, service_name: str) -> bool:
        """Check if a service is degraded"""
        return service_name in self.degraded_services
    
    async def execute_with_fallback(
        self,
        service_name: str,
        primary: Callable[[], Awaitable[T]],
        fallback_value: Optional[T] = None
    ) -> T:
        """
        Execute with automatic fallback on failure.
        
        Args:
            service_name: Name of the service
            primary: Primary function to execute
            fallback_value: Value to return on failure
            
        Returns:
            Result from primary or fallback
        """
        # If already degraded, try fallback first
        if self.is_degraded(service_name):
            if service_name in self.fallback_handlers:
                try:
                    return await self.fallback_handlers[service_name]()
                except Exception as e:
                    logger.error(f"Fallback for {service_name} also failed: {e}")
            
            if fallback_value is not None:
                return fallback_value
        
        try:
            result = await primary()
            self.mark_recovered(service_name)
            return result
        except Exception as e:
            logger.error(f"Service {service_name} failed: {e}")
            self.mark_degraded(service_name)
            
            if service_name in self.fallback_handlers:
                try:
                    return await self.fallback_handlers[service_name]()
                except Exception as fallback_e:
                    logger.error(f"Fallback also failed: {fallback_e}")
            
            if fallback_value is not None:
                return fallback_value
            
            raise
    
    def get_status(self) -> Dict[str, Any]:
        """Get degradation status"""
        return {
            "degraded_services": list(self.degraded_services.keys()),
            "degraded_since": {
                k: v.isoformat()
                for k, v in self.degraded_services.items()
            }
        }


# Global instances for shared use
_timeout_manager = TimeoutManager()
_bottleneck_detector = BottleneckDetector()
_graceful_degradation = GracefulDegradation()

# Circuit breakers for key services
_circuit_breakers: Dict[str, CircuitBreaker] = {
    "hive_mind": CircuitBreaker("hive_mind"),
    "hybrid_analysis": CircuitBreaker("hybrid_analysis"),
    "semantic_auditor": CircuitBreaker("semantic_auditor"),
    "llm_api": CircuitBreaker("llm_api", CircuitBreakerConfig(
        failure_threshold=3,
        recovery_timeout=60.0
    )),
}


def get_circuit_breaker(name: str) -> CircuitBreaker:
    """Get or create a circuit breaker"""
    if name not in _circuit_breakers:
        _circuit_breakers[name] = CircuitBreaker(name)
    return _circuit_breakers[name]


def get_timeout_manager() -> TimeoutManager:
    """Get the global timeout manager"""
    return _timeout_manager


def get_bottleneck_detector() -> BottleneckDetector:
    """Get the global bottleneck detector"""
    return _bottleneck_detector


def get_graceful_degradation() -> GracefulDegradation:
    """Get the global graceful degradation handler"""
    return _graceful_degradation


# Convenience decorators with default settings
retry_with_backoff = with_retry(RetryPolicy(max_retries=3, base_delay=1.0))


def resilient_operation(
    service_name: str,
    timeout_type: str = "http_request"
):
    """
    Decorator combining timeout, retry, and circuit breaker.
    
    Args:
        service_name: Name for circuit breaker
        timeout_type: Type for timeout lookup
    """
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        circuit = get_circuit_breaker(service_name)
        timeout_mgr = get_timeout_manager()
        policy = RetryPolicy(max_retries=3)
        
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            if not circuit.can_execute():
                raise CircuitOpenError(f"Circuit {service_name} is open")
            
            last_exception = None
            
            for attempt in range(policy.max_retries + 1):
                try:
                    timeout = timeout_mgr.get_timeout(timeout_type)
                    result = await asyncio.wait_for(
                        func(*args, **kwargs),
                        timeout=timeout
                    )
                    circuit.record_success()
                    return result
                    
                except Exception as e:
                    last_exception = e
                    circuit.record_failure()
                    
                    if policy.should_retry(attempt, e):
                        delay = policy.get_delay(attempt)
                        await asyncio.sleep(delay)
                    else:
                        break
            
            raise last_exception
        
        return wrapper
    return decorator
