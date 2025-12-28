"""
Enhanced Error Recovery and Self-Healing Module for Aegis Agent
Provides sophisticated error handling, recovery strategies, and self-healing capabilities
Version 1.0 - Resilient Error Management
"""

import asyncio
import logging
import traceback
from typing import Dict, List, Any, Optional, Callable, Coroutine
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = 1  # Recoverable, no impact
    MEDIUM = 2  # Recoverable with retry
    HIGH = 3  # Requires intervention
    CRITICAL = 4  # System failure


class RecoveryStrategy(Enum):
    """Error recovery strategies"""
    RETRY = "retry"
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    FALLBACK = "fallback"
    SKIP = "skip"
    ABORT = "abort"
    SELF_HEAL = "self_heal"


@dataclass
class ErrorContext:
    """Context information for an error"""
    error_id: str
    timestamp: datetime
    error_type: str
    error_message: str
    severity: ErrorSeverity
    stack_trace: str
    context_data: Dict[str, Any] = field(default_factory=dict)
    recovery_attempts: int = 0
    recovered: bool = False
    recovery_strategy: Optional[RecoveryStrategy] = None


class EnhancedErrorRecovery:
    """
    Enhanced error recovery system with self-healing capabilities.
    
    Features:
    - Automatic error classification and severity assessment
    - Multiple recovery strategies (retry, fallback, self-heal)
    - Error pattern detection and learning
    - Graceful degradation
    - Detailed error reporting and metrics
    """
    
    def __init__(self, max_retries: int = 3, backoff_factor: float = 2.0):
        """
        Initialize the error recovery system.
        
        Args:
            max_retries: Maximum number of retry attempts
            backoff_factor: Exponential backoff multiplier
        """
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.error_history: List[ErrorContext] = []
        self.error_patterns: Dict[str, List[ErrorContext]] = {}
        self.recovery_strategies: Dict[str, RecoveryStrategy] = {}
        self.metrics = {
            "total_errors": 0,
            "recovered_errors": 0,
            "failed_recoveries": 0,
            "self_healed": 0
        }
        
        logger.info("✅ Enhanced Error Recovery system initialized")
    
    async def execute_with_recovery(
        self,
        coroutine: Coroutine,
        operation_name: str,
        fallback: Optional[Callable] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute a coroutine with automatic error recovery.
        
        Args:
            coroutine: The async operation to execute
            operation_name: Human-readable name for the operation
            fallback: Optional fallback function to call if all retries fail
            context: Optional context data for error reporting
            
        Returns:
            Result dictionary with 'success', 'data', and optional 'error' keys
        """
        attempt = 0
        last_error = None
        
        while attempt < self.max_retries:
            try:
                result = await coroutine
                
                # Success - check if we recovered from previous errors
                if attempt > 0:
                    logger.info(f"✅ Recovered after {attempt} attempts: {operation_name}")
                    self.metrics["recovered_errors"] += 1
                
                return {
                    "success": True,
                    "data": result,
                    "attempts": attempt + 1
                }
                
            except Exception as e:
                attempt += 1
                last_error = e
                
                # Create error context
                error_ctx = self._create_error_context(
                    error=e,
                    operation=operation_name,
                    context=context or {},
                    attempt=attempt
                )
                
                # Log the error
                logger.warning(
                    f"⚠️ Attempt {attempt}/{self.max_retries} failed for {operation_name}: {str(e)}"
                )
                
                # Determine recovery strategy
                strategy = await self._determine_recovery_strategy(error_ctx)
                error_ctx.recovery_strategy = strategy
                
                if strategy == RecoveryStrategy.ABORT:
                    logger.error(f"❌ Aborting {operation_name} - unrecoverable error")
                    break
                
                elif strategy == RecoveryStrategy.SKIP:
                    logger.info(f"⏭️ Skipping {operation_name}")
                    return {
                        "success": False,
                        "error": str(e),
                        "skipped": True,
                        "attempts": attempt
                    }
                
                elif strategy == RecoveryStrategy.SELF_HEAL:
                    # Try to self-heal
                    healed = await self._attempt_self_heal(error_ctx)
                    if healed:
                        logger.info(f"🔧 Self-healed error in {operation_name}")
                        self.metrics["self_healed"] += 1
                        # Retry after healing
                        continue
                
                elif strategy == RecoveryStrategy.RETRY_WITH_BACKOFF:
                    # Wait with exponential backoff
                    if attempt < self.max_retries:
                        wait_time = self.backoff_factor ** (attempt - 1)
                        logger.info(f"⏳ Waiting {wait_time:.1f}s before retry...")
                        await asyncio.sleep(wait_time)
                
                # Record error
                self._record_error(error_ctx)
        
        # All retries failed
        self.metrics["failed_recoveries"] += 1
        
        # Try fallback if available
        if fallback:
            logger.info(f"🔄 Attempting fallback for {operation_name}")
            try:
                fallback_result = await fallback() if asyncio.iscoroutinefunction(fallback) else fallback()
                return {
                    "success": True,
                    "data": fallback_result,
                    "fallback_used": True,
                    "attempts": attempt
                }
            except Exception as fallback_error:
                logger.error(f"❌ Fallback also failed: {fallback_error}")
        
        # Return failure
        return {
            "success": False,
            "error": str(last_error),
            "error_type": type(last_error).__name__,
            "attempts": attempt
        }
    
    def _create_error_context(
        self,
        error: Exception,
        operation: str,
        context: Dict[str, Any],
        attempt: int
    ) -> ErrorContext:
        """Create error context from exception"""
        
        error_id = f"err_{datetime.now().timestamp()}_{attempt}"
        
        # Classify severity
        severity = self._classify_severity(error)
        
        return ErrorContext(
            error_id=error_id,
            timestamp=datetime.now(),
            error_type=type(error).__name__,
            error_message=str(error),
            severity=severity,
            stack_trace=traceback.format_exc(),
            context_data={
                "operation": operation,
                "attempt": attempt,
                **context
            },
            recovery_attempts=attempt
        )
    
    def _classify_severity(self, error: Exception) -> ErrorSeverity:
        """Classify error severity"""
        
        # Critical errors
        if isinstance(error, (MemoryError, SystemError, KeyboardInterrupt)):
            return ErrorSeverity.CRITICAL
        
        # High severity errors
        if isinstance(error, (RuntimeError, ValueError, TypeError)):
            return ErrorSeverity.HIGH
        
        # Medium severity errors
        if isinstance(error, (ConnectionError, TimeoutError, IOError)):
            return ErrorSeverity.MEDIUM
        
        # Low severity errors
        return ErrorSeverity.LOW
    
    async def _determine_recovery_strategy(self, error_ctx: ErrorContext) -> RecoveryStrategy:
        """Determine the best recovery strategy for an error"""
        
        # Check error patterns
        error_type = error_ctx.error_type
        
        if error_type in self.recovery_strategies:
            return self.recovery_strategies[error_type]
        
        # Default strategies based on severity
        if error_ctx.severity == ErrorSeverity.CRITICAL:
            return RecoveryStrategy.ABORT
        
        elif error_ctx.severity == ErrorSeverity.HIGH:
            # Try self-healing first, then retry
            return RecoveryStrategy.SELF_HEAL
        
        elif error_ctx.severity == ErrorSeverity.MEDIUM:
            # Retry with backoff
            return RecoveryStrategy.RETRY_WITH_BACKOFF
        
        else:
            # Simple retry for low severity
            return RecoveryStrategy.RETRY
    
    async def _attempt_self_heal(self, error_ctx: ErrorContext) -> bool:
        """
        Attempt to self-heal from an error.
        
        Implements specific healing strategies for common error types.
        """
        error_type = error_ctx.error_type
        error_msg = error_ctx.error_message.lower()
        
        # Module not found - try to install
        if "ModuleNotFoundError" in error_type or "no module named" in error_msg:
            module_name = self._extract_module_name(error_ctx.error_message)
            if module_name:
                logger.info(f"🔧 Attempting to install missing module: {module_name}")
                return await self._install_missing_module(module_name)
        
        # Connection errors - wait and retry
        if "ConnectionError" in error_type or "connection" in error_msg:
            logger.info("🔧 Connection error - waiting before retry")
            await asyncio.sleep(5)
            return True
        
        # File not found - try to create directory
        if "FileNotFoundError" in error_type:
            file_path = self._extract_file_path(error_ctx.error_message)
            if file_path:
                logger.info(f"🔧 Creating missing directory for: {file_path}")
                return self._create_parent_directories(file_path)
        
        # Timeout - adjust timeout settings
        if "TimeoutError" in error_type or "timeout" in error_msg:
            logger.info("🔧 Timeout detected - will retry with increased timeout")
            # This would need to be handled by the caller
            return True
        
        return False
    
    def _extract_module_name(self, error_msg: str) -> Optional[str]:
        """Extract module name from ModuleNotFoundError message"""
        import re
        match = re.search(r"No module named '([^']+)'", error_msg)
        if match:
            return match.group(1)
        return None
    
    async def _install_missing_module(self, module_name: str) -> bool:
        """Attempt to install a missing Python module"""
        try:
            import subprocess
            
            logger.info(f"📦 Installing {module_name}...")
            
            # Try to install with pip
            process = await asyncio.create_subprocess_exec(
                "pip", "install", module_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                logger.info(f"✅ Successfully installed {module_name}")
                return True
            else:
                logger.error(f"❌ Failed to install {module_name}: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error installing module: {e}")
            return False
    
    def _extract_file_path(self, error_msg: str) -> Optional[str]:
        """Extract file path from FileNotFoundError message"""
        import re
        match = re.search(r"'([^']+)'", error_msg)
        if match:
            return match.group(1)
        return None
    
    def _create_parent_directories(self, file_path: str) -> bool:
        """Create parent directories for a file path"""
        try:
            from pathlib import Path
            path = Path(file_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            logger.info(f"✅ Created directory: {path.parent}")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to create directory: {e}")
            return False
    
    def _record_error(self, error_ctx: ErrorContext):
        """Record error in history and patterns"""
        
        self.metrics["total_errors"] += 1
        self.error_history.append(error_ctx)
        
        # Group by error type for pattern detection
        error_type = error_ctx.error_type
        if error_type not in self.error_patterns:
            self.error_patterns[error_type] = []
        
        self.error_patterns[error_type].append(error_ctx)
        
        # Learn from patterns (if same error occurs frequently, adjust strategy)
        if len(self.error_patterns[error_type]) >= 3:
            # This error is recurring - mark for different strategy
            if error_type not in self.recovery_strategies:
                self.recovery_strategies[error_type] = RecoveryStrategy.FALLBACK
                logger.info(f"📊 Pattern detected for {error_type} - adjusting strategy")
    
    def get_error_report(self) -> Dict[str, Any]:
        """Get comprehensive error report"""
        
        total = self.metrics["total_errors"]
        recovered = self.metrics["recovered_errors"]
        recovery_rate = (recovered / total * 100) if total > 0 else 0
        
        return {
            "metrics": {
                "total_errors": total,
                "recovered": recovered,
                "failed": self.metrics["failed_recoveries"],
                "self_healed": self.metrics["self_healed"],
                "recovery_rate": f"{recovery_rate:.1f}%"
            },
            "patterns": {
                error_type: len(errors)
                for error_type, errors in self.error_patterns.items()
            },
            "recent_errors": [
                {
                    "timestamp": err.timestamp.isoformat(),
                    "type": err.error_type,
                    "message": err.error_message,
                    "severity": err.severity.name,
                    "recovered": err.recovered
                }
                for err in self.error_history[-10:]
            ]
        }
    
    def clear_error_history(self):
        """Clear error history to free memory"""
        cleared = len(self.error_history)
        self.error_history = []
        self.error_patterns = {}
        logger.info(f"🧹 Cleared {cleared} errors from history")


# Global instance
_error_recovery: Optional[EnhancedErrorRecovery] = None


def get_error_recovery() -> EnhancedErrorRecovery:
    """Get or create global error recovery instance"""
    global _error_recovery
    
    if _error_recovery is None:
        _error_recovery = EnhancedErrorRecovery()
    
    return _error_recovery


async def execute_with_recovery(
    coroutine: Coroutine,
    operation_name: str,
    fallback: Optional[Callable] = None,
    context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Convenience function to execute a coroutine with error recovery.
    
    Args:
        coroutine: The async operation to execute
        operation_name: Name of the operation for logging
        fallback: Optional fallback function
        context: Optional context data
        
    Returns:
        Result dictionary
    """
    recovery = get_error_recovery()
    return await recovery.execute_with_recovery(coroutine, operation_name, fallback, context)
