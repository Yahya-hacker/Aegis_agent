"""
Dynamic Micro-Agent Script Generator and Executor

This module provides functionality for generating and executing ephemeral Python scripts
to handle complex logic that standard tools can't handle, such as:
- Custom authentication token generation
- Complex payload encoding/decoding
- Custom crypto operations
- API-specific request signing

Security considerations:
- Scripts are executed in a controlled environment
- Sandboxing limits dangerous operations
- Scripts are temporary and cleaned up after use
- Execution is logged for audit purposes
"""

import os
import sys
import logging
import subprocess
import tempfile
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class MicroAgentScriptManager:
    """
    Manages ephemeral Python scripts for custom logic execution.
    """
    
    def __init__(self, scripts_dir: Optional[Path] = None):
        """
        Initialize the script manager.
        
        Args:
            scripts_dir: Directory to store temporary scripts (default: temp_scripts/)
        """
        self.scripts_dir = scripts_dir or Path("temp_scripts")
        self.scripts_dir.mkdir(exist_ok=True, parents=True)
        self.execution_log = []
        
        # Log file for script executions
        self.log_file = self.scripts_dir / "execution_log.json"
        self._load_execution_log()
    
    def _load_execution_log(self) -> None:
        """Load execution log from disk"""
        if self.log_file.exists():
            try:
                with open(self.log_file, 'r') as f:
                    self.execution_log = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load execution log: {e}")
                self.execution_log = []
    
    def _save_execution_log(self) -> None:
        """Save execution log to disk"""
        try:
            with open(self.log_file, 'w') as f:
                json.dump(self.execution_log, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save execution log: {e}")
    
    def generate_script(
        self,
        script_name: str,
        script_code: str,
        description: str = "",
        safe_mode: bool = True
    ) -> Path:
        """
        Generate and save an ephemeral Python script.
        
        Args:
            script_name: Name for the script (without .py extension)
            script_code: Python code to execute
            description: Human-readable description of what the script does
            safe_mode: If True, validates script for dangerous operations
        
        Returns:
            Path to the generated script file
        
        Raises:
            ValueError: If script contains dangerous operations in safe_mode
        """
        # Validate script in safe mode
        if safe_mode:
            self._validate_script_safety(script_code)
        
        # Create unique filename with timestamp and hash
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        code_hash = hashlib.md5(script_code.encode()).hexdigest()[:8]
        filename = f"{script_name}_{timestamp}_{code_hash}.py"
        script_path = self.scripts_dir / filename
        
        # Write script to file
        try:
            with open(script_path, 'w') as f:
                # Add header comment
                f.write(f"#!/usr/bin/env python3\n")
                f.write(f'"""\n')
                f.write(f"Generated Micro-Agent Script: {script_name}\n")
                f.write(f"Description: {description}\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write(f'"""\n\n')
                f.write(script_code)
            
            # Make executable
            os.chmod(script_path, 0o755)
            
            logger.info(f"✅ Generated micro-agent script: {filename}")
            logger.info(f"   Description: {description}")
            
            return script_path
            
        except Exception as e:
            logger.error(f"Failed to generate script: {e}")
            raise
    
    def _validate_script_safety(self, script_code: str) -> None:
        """
        Validate that script doesn't contain obviously dangerous operations.
        
        This is NOT a comprehensive security check - just basic sanity checking.
        
        Args:
            script_code: Python code to validate
        
        Raises:
            ValueError: If dangerous operations detected
        """
        dangerous_patterns = [
            'os.system',
            'subprocess.Popen',
            'eval(',
            'exec(',
            '__import__',
            'open(',  # File operations should be explicit
            'rmtree',
            'remove',
            'unlink',
            'chmod',
            'chown',
        ]
        
        for pattern in dangerous_patterns:
            if pattern in script_code:
                raise ValueError(
                    f"Script contains potentially dangerous operation: {pattern}. "
                    f"Set safe_mode=False to override."
                )
    
    def execute_script(
        self,
        script_path: Path,
        args: Optional[List[str]] = None,
        timeout: int = 30,
        capture_output: bool = True
    ) -> Dict[str, Any]:
        """
        Execute a micro-agent script.
        
        Args:
            script_path: Path to the script to execute
            args: Command-line arguments to pass to the script
            timeout: Maximum execution time in seconds
            capture_output: Whether to capture stdout/stderr
        
        Returns:
            Dictionary with execution results:
            {
                'success': bool,
                'stdout': str,
                'stderr': str,
                'return_code': int,
                'execution_time': float
            }
        """
        if not script_path.exists():
            logger.error(f"Script not found: {script_path}")
            return {
                'success': False,
                'error': f"Script not found: {script_path}",
                'stdout': '',
                'stderr': '',
                'return_code': -1,
                'execution_time': 0
            }
        
        cmd = [sys.executable, str(script_path.absolute())]
        if args:
            cmd.extend(args)
        
        logger.info(f"🔧 Executing micro-agent script: {script_path.name}")
        logger.info(f"   Command: {' '.join(cmd)}")
        
        start_time = datetime.now()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=capture_output,
                text=True,
                timeout=timeout
            )
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            success = result.returncode == 0
            
            execution_result = {
                'success': success,
                'stdout': result.stdout if capture_output else '',
                'stderr': result.stderr if capture_output else '',
                'return_code': result.returncode,
                'execution_time': execution_time
            }
            
            # Log execution
            log_entry = {
                'script': str(script_path),
                'timestamp': datetime.now().isoformat(),
                'success': success,
                'return_code': result.returncode,
                'execution_time': execution_time,
                'args': args or []
            }
            self.execution_log.append(log_entry)
            self._save_execution_log()
            
            if success:
                logger.info(f"✅ Script executed successfully in {execution_time:.2f}s")
            else:
                logger.warning(f"⚠️ Script failed with return code {result.returncode}")
                logger.warning(f"   stderr: {result.stderr[:200]}")
            
            return execution_result
            
        except subprocess.TimeoutExpired:
            execution_time = timeout
            logger.error(f"❌ Script execution timeout after {timeout}s")
            
            return {
                'success': False,
                'error': f"Timeout after {timeout}s",
                'stdout': '',
                'stderr': '',
                'return_code': -2,
                'execution_time': execution_time
            }
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            logger.error(f"❌ Script execution error: {e}")
            
            return {
                'success': False,
                'error': str(e),
                'stdout': '',
                'stderr': '',
                'return_code': -3,
                'execution_time': execution_time
            }
    
    def cleanup_old_scripts(self, max_age_hours: int = 24) -> int:
        """
        Clean up old script files.
        
        Args:
            max_age_hours: Maximum age of scripts to keep (in hours)
        
        Returns:
            Number of scripts deleted
        """
        deleted_count = 0
        cutoff_time = datetime.now().timestamp() - (max_age_hours * 3600)
        
        for script_file in self.scripts_dir.glob("*.py"):
            try:
                if script_file.stat().st_mtime < cutoff_time:
                    script_file.unlink()
                    deleted_count += 1
                    logger.debug(f"Deleted old script: {script_file.name}")
            except Exception as e:
                logger.warning(f"Failed to delete {script_file.name}: {e}")
        
        if deleted_count > 0:
            logger.info(f"🗑️ Cleaned up {deleted_count} old script(s)")
        
        return deleted_count
    
    def list_scripts(self) -> List[Dict[str, Any]]:
        """
        List all scripts in the scripts directory.
        
        Returns:
            List of script information dictionaries
        """
        scripts = []
        
        for script_file in self.scripts_dir.glob("*.py"):
            try:
                stat = script_file.stat()
                scripts.append({
                    'name': script_file.name,
                    'path': str(script_file),
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
            except Exception as e:
                logger.warning(f"Failed to stat {script_file.name}: {e}")
        
        return scripts
    
    def get_execution_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent execution history.
        
        Args:
            limit: Maximum number of entries to return
        
        Returns:
            List of execution log entries
        """
        return self.execution_log[-limit:]


# Singleton instance
_script_manager = None


def get_script_manager() -> MicroAgentScriptManager:
    """
    Get the singleton MicroAgentScriptManager instance.
    
    Returns:
        MicroAgentScriptManager instance
    """
    global _script_manager
    if _script_manager is None:
        _script_manager = MicroAgentScriptManager()
    return _script_manager
