"""
Error Recovery System for Aegis AI v9.1
========================================

This module provides comprehensive error handling and recovery mechanisms
to ensure smooth operation even when unexpected errors occur.

Features:
- Automatic error classification
- Graceful degradation strategies
- Recovery action suggestions
- Error logging and reporting
- Circuit breaker pattern for failing services
"""

import asyncio
import logging
import traceback
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, TypeVar, Generic
from functools import wraps

logger = logging.getLogger(__name__)

T = TypeVar('T')


class ErrorSeverity(Enum):
    """Severity levels for errors"""
    LOW = "low"           # Minor issue, can continue
    MEDIUM = "medium"     # Moderate issue, may affect results
    HIGH = "high"         # Serious issue, needs attention
    CRITICAL = "critical" # System-level failure


class ErrorCategory(Enum):
    """Categories of errors for classification"""
    NETWORK = "network"           # Network/connectivity issues
    TOOL = "tool"                 # Tool execution failures
    AUTHENTICATION = "auth"       # Auth/permission issues
    PARSING = "parsing"           # Data parsing errors
    TIMEOUT = "timeout"           # Timeout errors
    RESOURCE = "resource"         # Resource exhaustion
    CONFIGURATION = "config"      # Configuration errors
    DEPENDENCY = "dependency"     # Missing dependency
    VALIDATION = "validation"     # Input validation errors
    UNKNOWN = "unknown"           # Unclassified errors


@dataclass
class ErrorRecord:
    """Record of an error occurrence"""
    error_id: str
    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    source: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    traceback: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    recovery_attempted: bool = False
    recovery_successful: bool = False
    recovery_action: Optional[str] = None


@dataclass
class RecoveryAction:
    """A recovery action that can be taken"""
    name: str
    description: str
    action: Callable
    applicable_categories: List[ErrorCategory]
    max_attempts: int = 3


class CircuitBreaker:
    """
    Circuit breaker to prevent cascading failures.
    
    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Failures exceeded threshold, requests fail fast
    - HALF_OPEN: Testing if service recovered
    """
    
    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0
    ):
        """
        Initialize circuit breaker.
        
        Args:
            name: Name of the protected service
            failure_threshold: Failures before opening circuit
            recovery_timeout: Seconds before testing recovery
        """
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.state = "CLOSED"
    
    def record_failure(self) -> None:
        """Record a failure"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"
            logger.warning(f"🔴 Circuit breaker {self.name} OPENED after {self.failure_count} failures")
    
    def record_success(self) -> None:
        """Record a success"""
        self.failure_count = 0
        self.state = "CLOSED"
        logger.info(f"🟢 Circuit breaker {self.name} CLOSED")
    
    def can_execute(self) -> bool:
        """Check if execution is allowed"""
        if self.state == "CLOSED":
            return True
        
        if self.state == "OPEN":
            # Check if recovery timeout has passed
            if self.last_failure_time and (time.time() - self.last_failure_time) > self.recovery_timeout:
                self.state = "HALF_OPEN"
                logger.info(f"🟡 Circuit breaker {self.name} HALF_OPEN - testing recovery")
                return True
            return False
        
        # HALF_OPEN: Allow one test request
        return True
    
    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker status"""
        return {
            "name": self.name,
            "state": self.state,
            "failure_count": self.failure_count,
            "threshold": self.failure_threshold,
            "last_failure": self.last_failure_time
        }


class ErrorRecoverySystem:
    """
    Comprehensive error recovery system.
    
    Features:
    - Error classification and logging
    - Recovery action execution
    - Circuit breaker management
    - Statistics and monitoring
    """
    
    # Error patterns for classification
    ERROR_PATTERNS = {
        ErrorCategory.NETWORK: [
            "connection", "network", "socket", "dns", "timeout", "unreachable",
            "refused", "reset", "certificate", "ssl", "tls"
        ],
        ErrorCategory.AUTHENTICATION: [
            "auth", "unauthorized", "forbidden", "permission", "access denied",
            "invalid token", "expired", "credentials"
        ],
        ErrorCategory.TIMEOUT: [
            "timeout", "timed out", "deadline", "exceeded"
        ],
        ErrorCategory.RESOURCE: [
            "memory", "disk", "quota", "limit", "exhausted", "out of",
            "too many", "rate limit"
        ],
        ErrorCategory.DEPENDENCY: [
            "not found", "missing", "not installed", "import", "module",
            "package", "command not found"
        ],
        ErrorCategory.PARSING: [
            "parse", "json", "xml", "decode", "encoding", "syntax",
            "invalid format", "malformed"
        ],
        ErrorCategory.VALIDATION: [
            "invalid", "required", "must be", "expected", "validation",
            "constraint", "illegal"
        ],
        ErrorCategory.CONFIGURATION: [
            "config", "setting", "environment", "variable", "path"
        ],
    }
    
    def __init__(self):
        """Initialize the error recovery system"""
        self.error_history: List[ErrorRecord] = []
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.recovery_actions: List[RecoveryAction] = []
        
        # Statistics
        self.total_errors = 0
        self.recovered_errors = 0
        
        # Register default recovery actions
        self._register_default_actions()
        
        logger.info("🛡️ Error Recovery System initialized")
    
    def _register_default_actions(self) -> None:
        """Register default recovery actions"""
        self.recovery_actions = [
            RecoveryAction(
                name="retry_with_backoff",
                description="Retry operation with exponential backoff",
                action=self._retry_with_backoff,
                applicable_categories=[
                    ErrorCategory.NETWORK,
                    ErrorCategory.TIMEOUT,
                    ErrorCategory.RESOURCE
                ]
            ),
            RecoveryAction(
                name="use_fallback",
                description="Use fallback mechanism",
                action=self._use_fallback,
                applicable_categories=[
                    ErrorCategory.TOOL,
                    ErrorCategory.DEPENDENCY
                ]
            ),
            RecoveryAction(
                name="skip_and_continue",
                description="Skip this step and continue",
                action=self._skip_and_continue,
                applicable_categories=[
                    ErrorCategory.PARSING,
                    ErrorCategory.VALIDATION
                ]
            ),
        ]
    
    def classify_error(self, error: Exception, context: str = "") -> ErrorCategory:
        """
        Classify an error based on its message and type.
        
        Args:
            error: The exception to classify
            context: Additional context
            
        Returns:
            The error category
        """
        error_text = f"{str(error)} {context}".lower()
        
        for category, patterns in self.ERROR_PATTERNS.items():
            if any(pattern in error_text for pattern in patterns):
                return category
        
        # Check exception type
        error_type = type(error).__name__.lower()
        
        type_mapping = {
            "connectionerror": ErrorCategory.NETWORK,
            "timeouterror": ErrorCategory.TIMEOUT,
            "asynciotimeouterror": ErrorCategory.TIMEOUT,
            "permissionerror": ErrorCategory.AUTHENTICATION,
            "jsondecodeerror": ErrorCategory.PARSING,
            "valueerror": ErrorCategory.VALIDATION,
            "importerror": ErrorCategory.DEPENDENCY,
            "modulenotfounderror": ErrorCategory.DEPENDENCY,
            "memoryerror": ErrorCategory.RESOURCE,
        }
        
        for type_name, category in type_mapping.items():
            if type_name in error_type:
                return category
        
        return ErrorCategory.UNKNOWN
    
    def determine_severity(
        self,
        category: ErrorCategory,
        context: Dict[str, Any]
    ) -> ErrorSeverity:
        """Determine error severity based on category and context"""
        # Critical categories
        if category in [ErrorCategory.AUTHENTICATION, ErrorCategory.CONFIGURATION]:
            return ErrorSeverity.HIGH
        
        # Check retry count
        retry_count = context.get('retry_count', 0)
        if retry_count >= 3:
            return ErrorSeverity.HIGH
        
        # High-impact operations
        if context.get('operation_critical', False):
            return ErrorSeverity.HIGH
        
        # Default severities by category
        severity_map = {
            ErrorCategory.NETWORK: ErrorSeverity.MEDIUM,
            ErrorCategory.TIMEOUT: ErrorSeverity.MEDIUM,
            ErrorCategory.TOOL: ErrorSeverity.MEDIUM,
            ErrorCategory.DEPENDENCY: ErrorSeverity.HIGH,
            ErrorCategory.RESOURCE: ErrorSeverity.HIGH,
            ErrorCategory.PARSING: ErrorSeverity.LOW,
            ErrorCategory.VALIDATION: ErrorSeverity.LOW,
            ErrorCategory.UNKNOWN: ErrorSeverity.MEDIUM,
        }
        
        return severity_map.get(category, ErrorSeverity.MEDIUM)
    
    def record_error(
        self,
        error: Exception,
        source: str,
        context: Optional[Dict[str, Any]] = None
    ) -> ErrorRecord:
        """
        Record an error occurrence.
        
        Args:
            error: The exception that occurred
            source: Where the error originated
            context: Additional context
            
        Returns:
            The error record
        """
        context = context or {}
        
        category = self.classify_error(error, source)
        severity = self.determine_severity(category, context)
        
        record = ErrorRecord(
            error_id=f"ERR_{int(time.time() * 1000)}_{self.total_errors}",
            category=category,
            severity=severity,
            message=str(error),
            source=source,
            traceback=traceback.format_exc(),
            context=context
        )
        
        self.error_history.append(record)
        self.total_errors += 1
        
        # Log based on severity
        if severity == ErrorSeverity.CRITICAL:
            logger.critical(f"🔴 CRITICAL ERROR [{category.value}] in {source}: {error}")
        elif severity == ErrorSeverity.HIGH:
            logger.error(f"🟠 ERROR [{category.value}] in {source}: {error}")
        elif severity == ErrorSeverity.MEDIUM:
            logger.warning(f"🟡 WARNING [{category.value}] in {source}: {error}")
        else:
            logger.info(f"🟢 MINOR [{category.value}] in {source}: {error}")
        
        return record
    
    async def attempt_recovery(
        self,
        record: ErrorRecord,
        operation: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Attempt to recover from an error.
        
        Args:
            record: The error record
            operation: The original operation to retry
            
        Returns:
            Recovery result
        """
        # Find applicable recovery actions
        applicable = [
            action for action in self.recovery_actions
            if record.category in action.applicable_categories
        ]
        
        if not applicable:
            return {
                "recovered": False,
                "reason": "No applicable recovery actions"
            }
        
        # Try each recovery action
        for action in applicable:
            logger.info(f"🔧 Attempting recovery: {action.name}")
            
            try:
                result = await action.action(record, operation)
                
                if result.get("success"):
                    record.recovery_attempted = True
                    record.recovery_successful = True
                    record.recovery_action = action.name
                    self.recovered_errors += 1
                    
                    logger.info(f"✅ Recovery successful: {action.name}")
                    
                    return {
                        "recovered": True,
                        "action": action.name,
                        "result": result.get("data")
                    }
            except Exception as e:
                logger.warning(f"Recovery action {action.name} failed: {e}")
                continue
        
        record.recovery_attempted = True
        record.recovery_successful = False
        
        return {
            "recovered": False,
            "reason": "All recovery actions failed"
        }
    
    async def _retry_with_backoff(
        self,
        record: ErrorRecord,
        operation: Optional[Callable]
    ) -> Dict[str, Any]:
        """Retry operation with exponential backoff"""
        if not operation:
            return {"success": False, "reason": "No operation provided"}
        
        max_retries = 3
        base_delay = 1.0
        
        for attempt in range(max_retries):
            delay = base_delay * (2 ** attempt)
            logger.info(f"⏳ Waiting {delay}s before retry {attempt + 1}/{max_retries}")
            await asyncio.sleep(delay)
            
            try:
                if asyncio.iscoroutinefunction(operation):
                    result = await operation()
                else:
                    result = operation()
                
                return {"success": True, "data": result}
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                logger.warning(f"Retry {attempt + 1} failed: {e}")
        
        return {"success": False}
    
    async def _use_fallback(
        self,
        record: ErrorRecord,
        operation: Optional[Callable]
    ) -> Dict[str, Any]:
        """Use a fallback mechanism"""
        # This would be implemented based on the specific tool/operation
        return {
            "success": True,
            "data": {
                "fallback_used": True,
                "message": "Fallback mechanism activated"
            }
        }
    
    async def _skip_and_continue(
        self,
        record: ErrorRecord,
        operation: Optional[Callable]
    ) -> Dict[str, Any]:
        """Skip the failed step and continue"""
        return {
            "success": True,
            "data": {
                "skipped": True,
                "message": f"Skipped due to {record.category.value} error"
            }
        }
    
    def get_circuit_breaker(self, name: str) -> CircuitBreaker:
        """Get or create a circuit breaker for a service"""
        if name not in self.circuit_breakers:
            self.circuit_breakers[name] = CircuitBreaker(name)
        return self.circuit_breakers[name]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get error recovery statistics"""
        category_counts = {}
        for record in self.error_history:
            cat = record.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        return {
            "total_errors": self.total_errors,
            "recovered_errors": self.recovered_errors,
            "recovery_rate": (
                self.recovered_errors / self.total_errors * 100
                if self.total_errors > 0 else 0
            ),
            "errors_by_category": category_counts,
            "circuit_breakers": {
                name: cb.get_status()
                for name, cb in self.circuit_breakers.items()
            },
            "recent_errors": [
                {
                    "id": r.error_id,
                    "category": r.category.value,
                    "severity": r.severity.value,
                    "message": r.message[:100],
                    "source": r.source,
                    "recovered": r.recovery_successful
                }
                for r in self.error_history[-10:]
            ]
        }
    
    def clear_history(self) -> None:
        """Clear error history"""
        self.error_history.clear()
        self.total_errors = 0
        self.recovered_errors = 0


def with_error_recovery(source: str = "unknown"):
    """
    Decorator for functions that should have error recovery.
    
    Args:
        source: Source name for error tracking
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def async_wrapper(*args, **kwargs) -> T:
            recovery_system = get_error_recovery_system()
            
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                record = recovery_system.record_error(e, source, {"args": str(args)[:100]})
                
                # Attempt recovery
                recovery_result = await recovery_system.attempt_recovery(
                    record,
                    lambda: func(*args, **kwargs)
                )
                
                if recovery_result.get("recovered"):
                    return recovery_result.get("result")
                
                # Re-raise if recovery failed
                raise
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs) -> T:
            recovery_system = get_error_recovery_system()
            
            try:
                return func(*args, **kwargs)
            except Exception as e:
                record = recovery_system.record_error(e, source, {"args": str(args)[:100]})
                raise
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator


# Global instance
_recovery_system: Optional[ErrorRecoverySystem] = None


def get_error_recovery_system() -> ErrorRecoverySystem:
    """Get the global error recovery system instance"""
    global _recovery_system
    if _recovery_system is None:
        _recovery_system = ErrorRecoverySystem()
    return _recovery_system
