# utils/output_sanitizer.py
# --- Output Sanitizer for Large Tool Outputs ---
#
# This module solves the "Output Flooding" problem where large tool outputs
# (e.g., 2MB text responses) would crash the LLM call due to context limits.
#
# The OutputSanitizer:
# 1. Detects large outputs that would exceed safe token limits
# 2. Saves full output to a file for reference
# 3. Returns a truncated snippet with file path for the conversation history

import hashlib
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class OutputSanitizer:
    """
    Sanitizes tool output to prevent context overflow in LLM conversations.
    
    When a tool returns very large output, this class:
    1. Saves the full output to a timestamped file
    2. Returns a truncated snippet with key information
    3. Includes a reference to the full output file
    
    This prevents "Output Flooding" where raw multi-megabyte outputs would
    crash the next LLM call due to context limits.
    
    Example:
        sanitizer = OutputSanitizer()
        
        # Large output that would overflow context
        tool_result = {"data": "..." * 1000000}  # 1MB+ 
        
        # Sanitized version safe for conversation
        sanitized = sanitizer.sanitize(
            tool_name="nmap_scan",
            output=tool_result,
            context="Port scan on example.com"
        )
        # Returns: {"data": "[TRUNCATED]...", "full_output_file": "data/outputs/nmap_scan_20240101_123456.json"}
    """
    
    # Default thresholds (can be adjusted based on LLM context window)
    DEFAULT_MAX_OUTPUT_LENGTH = 4000  # Characters before truncation
    DEFAULT_MAX_LIST_ITEMS = 50  # Maximum items in a list before truncation
    DEFAULT_SNIPPET_LENGTH = 500  # Length of the snippet to keep
    
    def __init__(
        self,
        output_dir: str = "data/outputs",
        max_output_length: int = DEFAULT_MAX_OUTPUT_LENGTH,
        max_list_items: int = DEFAULT_MAX_LIST_ITEMS,
        snippet_length: int = DEFAULT_SNIPPET_LENGTH
    ):
        """
        Initialize the output sanitizer.
        
        Args:
            output_dir: Directory to save full outputs
            max_output_length: Maximum character length before truncation
            max_list_items: Maximum list items before truncation
            snippet_length: Length of snippet to keep when truncating
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_output_length = max_output_length
        self.max_list_items = max_list_items
        self.snippet_length = snippet_length
        
        logger.info(f"📝 OutputSanitizer initialized (max_length={max_output_length}, output_dir={output_dir})")
    
    def _generate_filename(self, tool_name: str, context: str = "") -> str:
        """Generate a unique filename for the output file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        context_hash = hashlib.md5(context.encode()).hexdigest()[:8] if context else "default"
        return f"{tool_name}_{timestamp}_{context_hash}.json"
    
    def _estimate_size(self, obj: Any) -> int:
        """Estimate the size of an object when serialized"""
        try:
            return len(json.dumps(obj, default=str))
        except (TypeError, ValueError):
            return len(str(obj))
    
    def _save_full_output(self, tool_name: str, output: Any, context: str = "") -> str:
        """
        Save the full output to a file.
        
        Args:
            tool_name: Name of the tool that generated the output
            output: The full output to save
            context: Optional context about the operation
        
        Returns:
            Path to the saved file
        """
        filename = self._generate_filename(tool_name, context)
        filepath = self.output_dir / filename
        
        save_data = {
            "tool_name": tool_name,
            "context": context,
            "timestamp": datetime.now().isoformat(),
            "output": output
        }
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(save_data, f, indent=2, default=str)
            
            logger.info(f"💾 Saved full output to {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Failed to save output: {e}")
            return ""
    
    def _truncate_string(self, s: str, max_length: int = None) -> Tuple[str, bool]:
        """
        Truncate a string if it exceeds max length.
        
        Returns:
            Tuple of (truncated string, was_truncated)
        """
        max_len = max_length or self.max_output_length
        if len(s) <= max_len:
            return s, False
        
        # Keep beginning and end
        snippet_size = max_len // 2
        truncated = (
            s[:snippet_size] +
            f"\n\n[... TRUNCATED {len(s) - max_len} characters ...]\n\n" +
            s[-snippet_size:]
        )
        return truncated, True
    
    def _truncate_list(self, lst: list, max_items: int = None) -> Tuple[list, bool]:
        """
        Truncate a list if it exceeds max items.
        
        Returns:
            Tuple of (truncated list, was_truncated)
        """
        max_items = max_items or self.max_list_items
        if len(lst) <= max_items:
            return lst, False
        
        # Keep first and last items
        half = max_items // 2
        truncated = (
            lst[:half] +
            [f"[... {len(lst) - max_items} more items ...]"] +
            lst[-half:]
        )
        return truncated, True
    
    def _sanitize_value(self, value: Any, depth: int = 0) -> Tuple[Any, bool]:
        """
        Recursively sanitize a value.
        
        Returns:
            Tuple of (sanitized value, was_truncated)
        """
        # Prevent infinite recursion
        if depth > 10:
            return "[MAX_DEPTH_EXCEEDED]", True
        
        was_truncated = False
        
        if isinstance(value, str):
            result, truncated = self._truncate_string(value)
            return result, truncated
        
        elif isinstance(value, list):
            # First truncate list length
            result, truncated = self._truncate_list(value)
            if truncated:
                was_truncated = True
            
            # Then sanitize each item
            sanitized_list = []
            for item in result:
                if isinstance(item, str) and item.startswith("[..."):
                    # Skip truncation markers
                    sanitized_list.append(item)
                else:
                    sanitized_item, item_truncated = self._sanitize_value(item, depth + 1)
                    sanitized_list.append(sanitized_item)
                    if item_truncated:
                        was_truncated = True
            
            return sanitized_list, was_truncated
        
        elif isinstance(value, dict):
            sanitized_dict = {}
            for k, v in value.items():
                sanitized_v, v_truncated = self._sanitize_value(v, depth + 1)
                sanitized_dict[k] = sanitized_v
                if v_truncated:
                    was_truncated = True
            
            return sanitized_dict, was_truncated
        
        else:
            # For other types (int, float, bool, None), return as-is
            return value, False
    
    def sanitize(
        self,
        tool_name: str,
        output: Any,
        context: str = "",
        force_save: bool = False
    ) -> Dict[str, Any]:
        """
        Sanitize tool output for safe injection into conversation history.
        
        If the output is large:
        1. Saves full output to a file
        2. Returns truncated version with file reference
        
        Args:
            tool_name: Name of the tool that generated the output
            output: The raw tool output
            context: Optional context about the operation
            force_save: Always save to file, even if not truncated
        
        Returns:
            Sanitized output dict with potential file reference
        """
        # Estimate output size
        output_size = self._estimate_size(output)
        
        # Check if sanitization is needed
        needs_sanitization = output_size > self.max_output_length
        
        if not needs_sanitization and not force_save:
            # Output is small enough, return as-is
            logger.debug(f"Output size {output_size} chars is within limits")
            return output if isinstance(output, dict) else {"data": output}
        
        # Output is too large - save full version and sanitize
        logger.warning(f"⚠️ Large output detected ({output_size} chars) from {tool_name}, sanitizing...")
        
        # Save full output to file
        output_file = self._save_full_output(tool_name, output, context)
        
        # Sanitize the output
        sanitized_output, was_truncated = self._sanitize_value(output)
        
        # Wrap in dict if not already
        if not isinstance(sanitized_output, dict):
            sanitized_output = {"data": sanitized_output}
        
        # Add metadata about sanitization
        sanitized_output["_sanitization"] = {
            "was_truncated": was_truncated,
            "original_size": output_size,
            "full_output_file": output_file,
            "message": f"Output was truncated. Full output saved to: {output_file}"
        }
        
        # Add a summary for the LLM
        sanitized_output["_summary"] = self._generate_summary(tool_name, output, output_size)
        
        logger.info(f"✅ Sanitized output: {output_size} -> {self._estimate_size(sanitized_output)} chars")
        
        return sanitized_output
    
    def _generate_summary(self, tool_name: str, output: Any, original_size: int) -> str:
        """Generate a brief summary of the output for the LLM"""
        summary_parts = [
            f"Tool: {tool_name}",
            f"Original size: {original_size} characters"
        ]
        
        # Count key items based on output type
        if isinstance(output, dict):
            if "data" in output:
                data = output["data"]
                if isinstance(data, list):
                    summary_parts.append(f"Contains {len(data)} items")
                elif isinstance(data, dict):
                    summary_parts.append(f"Contains {len(data)} keys")
            summary_parts.append(f"Top-level keys: {list(output.keys())[:10]}")
        elif isinstance(output, list):
            summary_parts.append(f"Contains {len(output)} items")
        elif isinstance(output, str):
            summary_parts.append(f"String of {len(output)} characters")
        
        return " | ".join(summary_parts)
    
    def get_full_output(self, filepath: str) -> Optional[Any]:
        """
        Retrieve the full output from a saved file.
        
        Args:
            filepath: Path to the output file
        
        Returns:
            The full output or None if file not found
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get("output")
        except FileNotFoundError:
            logger.warning(f"Output file not found: {filepath}")
            return None
        except Exception as e:
            logger.error(f"Error reading output file: {e}")
            return None
    
    def cleanup_old_outputs(self, max_age_days: int = 7) -> int:
        """
        Clean up old output files.
        
        Args:
            max_age_days: Maximum age of files to keep
        
        Returns:
            Number of files deleted
        """
        import time
        
        cutoff_time = time.time() - (max_age_days * 24 * 60 * 60)
        deleted_count = 0
        
        for filepath in self.output_dir.glob("*.json"):
            try:
                if filepath.stat().st_mtime < cutoff_time:
                    filepath.unlink()
                    deleted_count += 1
            except Exception as e:
                logger.warning(f"Error deleting {filepath}: {e}")
        
        if deleted_count > 0:
            logger.info(f"🧹 Cleaned up {deleted_count} old output files")
        
        return deleted_count


# Singleton instance
_sanitizer: Optional[OutputSanitizer] = None


def get_output_sanitizer() -> OutputSanitizer:
    """Get the singleton output sanitizer instance"""
    global _sanitizer
    if _sanitizer is None:
        _sanitizer = OutputSanitizer()
    return _sanitizer


def sanitize_tool_output(
    tool_name: str,
    output: Any,
    context: str = ""
) -> Dict[str, Any]:
    """
    Convenience function to sanitize tool output.
    
    Args:
        tool_name: Name of the tool
        output: Raw tool output
        context: Optional context
    
    Returns:
        Sanitized output
    """
    sanitizer = get_output_sanitizer()
    return sanitizer.sanitize(tool_name, output, context)
