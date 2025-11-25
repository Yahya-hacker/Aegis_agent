"""
Keep-Alive Mechanism for Aegis Agent
Prevents terminal from sleeping/closing during long operations
"""

import asyncio
import threading
import time
import sys
import os
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class KeepAlive:
    """
    Keeps the terminal active and prevents sleeping during agent operations
    """
    
    def __init__(self, interval: int = 60):
        """
        Initialize keep-alive mechanism
        
        Args:
            interval: Seconds between keep-alive signals (default: 60)
        """
        self.interval = interval
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._loop_task: Optional[asyncio.Task] = None
        self.start_time = None
        self.heartbeat_count = 0
        
    def start(self):
        """Start the keep-alive mechanism"""
        if self.running:
            logger.warning("Keep-alive is already running")
            return
            
        self.running = True
        self.start_time = time.time()
        self.heartbeat_count = 0
        
        # Start in a separate thread to avoid blocking
        self._thread = threading.Thread(target=self._keep_alive_loop, daemon=True)
        self._thread.start()
        
        logger.info(f"🔋 Keep-alive mechanism started (interval: {self.interval}s)")
        
    def _keep_alive_loop(self):
        """Internal loop that sends keep-alive signals"""
        while self.running:
            try:
                # Send a keep-alive signal
                self._send_signal()
                self.heartbeat_count += 1
                
                # Sleep for the interval
                time.sleep(self.interval)
                
            except Exception as e:
                logger.error(f"Error in keep-alive loop: {e}", exc_info=True)
                time.sleep(self.interval)
    
    def _send_signal(self):
        """Send a keep-alive signal to the terminal"""
        try:
            # Method 1: Write null character to stdout (doesn't print anything visible)
            # This keeps the terminal "active" without cluttering output
            sys.stdout.write('\0')
            sys.stdout.flush()
            
            # Method 2: Update process title if available (Linux/Unix)
            try:
                import setproctitle  # type: ignore
                elapsed = int(time.time() - self.start_time) if self.start_time else 0
                setproctitle.setproctitle(f"aegis_agent [running {elapsed}s]")
            except ImportError:
                pass  # setproctitle not available, that's okay
            
            # Method 3: Touch a marker file to show activity
            marker_file = "/tmp/aegis_agent_active.marker"
            try:
                with open(marker_file, 'w') as f:
                    f.write(f"{time.time()},{self.heartbeat_count}\n")
            except Exception:
                pass  # Ignore errors writing marker file
                
            logger.debug(f"Keep-alive heartbeat #{self.heartbeat_count}")
            
        except Exception as e:
            logger.error(f"Error sending keep-alive signal: {e}")
    
    def stop(self):
        """Stop the keep-alive mechanism"""
        if not self.running:
            return
            
        self.running = False
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        
        elapsed = int(time.time() - self.start_time) if self.start_time else 0
        logger.info(f"🔋 Keep-alive mechanism stopped (ran for {elapsed}s, {self.heartbeat_count} heartbeats)")
        
    def get_status(self) -> dict:
        """Get the current status of keep-alive mechanism"""
        elapsed = int(time.time() - self.start_time) if self.start_time else 0
        return {
            "running": self.running,
            "elapsed_seconds": elapsed,
            "heartbeat_count": self.heartbeat_count,
            "interval": self.interval
        }
    
    def __enter__(self):
        """Context manager support"""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager support"""
        self.stop()
        return False


# Global keep-alive instance for easy access
_global_keep_alive: Optional[KeepAlive] = None


def start_keep_alive(interval: int = 60) -> KeepAlive:
    """
    Start the global keep-alive mechanism
    
    Args:
        interval: Seconds between keep-alive signals
        
    Returns:
        KeepAlive instance
    """
    global _global_keep_alive
    
    if _global_keep_alive is None:
        _global_keep_alive = KeepAlive(interval=interval)
    
    _global_keep_alive.start()
    return _global_keep_alive


def stop_keep_alive():
    """Stop the global keep-alive mechanism"""
    global _global_keep_alive
    
    if _global_keep_alive:
        _global_keep_alive.stop()


def get_keep_alive_status() -> Optional[dict]:
    """Get the status of the global keep-alive mechanism"""
    global _global_keep_alive
    
    if _global_keep_alive:
        return _global_keep_alive.get_status()
    return None
