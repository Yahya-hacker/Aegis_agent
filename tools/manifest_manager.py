"""
Aegis Agent - Manifest Manager
==============================

Self-healing tool manifest with real-time updates.
Maintains kali_tool_manifest.json as the brain's registry.
"""

import asyncio
import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.environment import get_environment

logger = logging.getLogger(__name__)

logger = logging.getLogger(__name__)

MANIFEST_PATH = Path(__file__).parent / "kali_tool_manifest.json"


class AptManager:
    """
    Manages apt-get operations with a lock to prevent parallel execution failures.
    """
    def __init__(self):
        self._lock = asyncio.Lock()
        
    async def install(self, package: str) -> bool:
        """
        Thread-safe installation of a package.
        """
        async with self._lock:
            logger.info(f"📦 AptManager: Acquiring lock for {package}...")
            
            # Update package list first (rarely)
            # implementation delegated to environment.py but managed here for locking
            
            # Construct command
            cmd = f"apt-get install -y {package}"
            
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                logger.info(f"   ✅ AptManager: {package} installed successfully")
                return True
            else:
                error = stderr.decode("utf-8", errors="replace")
                logger.error(f"   ❌ AptManager: Failed to install {package}: {error[:200]}")
                return False

MANIFEST_PATH = Path(__file__).parent / "kali_tool_manifest.json"


class ManifestManager:
    """
    Self-healing tool manifest manager.
    
    Features:
    - Load/save manifest with metadata
    - Discover new tools on system
    - Auto-update tool paths
    - Mark missing tools for installation
    """
    
    def __init__(self, manifest_path: Path = MANIFEST_PATH):
        self.manifest_path = manifest_path
        self.manifest: Dict[str, Any] = {}
        self._loaded = False
    
    def load(self) -> Dict[str, Any]:
        """Load manifest from disk."""
        if self.manifest_path.exists():
            try:
                with open(self.manifest_path, "r") as f:
                    self.manifest = json.load(f)
                self._loaded = True
                logger.info(f"📋 Loaded manifest: {len(self.manifest.get('tools', []))} tools")
            except json.JSONDecodeError as e:
                logger.error(f"❌ Invalid manifest JSON: {e}")
                self.manifest = {"metadata": {}, "tools": []}
        else:
            logger.warning(f"⚠️ Manifest not found: {self.manifest_path}")
            self.manifest = {"metadata": {}, "tools": []}
        
        return self.manifest
    
    def save(self):
        """Save manifest to disk with updated metadata."""
        # Update metadata
        if "metadata" not in self.manifest:
            self.manifest["metadata"] = {}
        
        self.manifest["metadata"]["last_updated"] = datetime.now(timezone.utc).isoformat()
        self.manifest["metadata"]["auto_heal_enabled"] = True
        
        # Count stats
        tools = self.manifest.get("tools", [])
        available = sum(1 for t in tools if t.get("_available", False))
        self.manifest["metadata"]["tools_available"] = available
        self.manifest["metadata"]["tools_total"] = len(tools)
        
        # Write
        with open(self.manifest_path, "w") as f:
            json.dump(self.manifest, f, indent=2)
        
        logger.info(f"💾 Saved manifest: {available}/{len(tools)} tools available")
    
    def get_tools(self) -> List[Dict[str, Any]]:
        """Get all tools from manifest."""
        if not self._loaded:
            self.load()
        return self.manifest.get("tools", [])
    
    def get_tool(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get a specific tool by name."""
        for tool in self.get_tools():
            if tool.get("tool_name") == tool_name:
                return tool
        return None
    
    def get_available_tools(self) -> List[Dict[str, Any]]:
        """Get only tools that are currently available on the system."""
        return [t for t in self.get_tools() if t.get("_available", False)]
    
    def get_tools_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Get tools filtered by category."""
        return [t for t in self.get_tools() if t.get("category") == category]
    
    async def sync_with_system(self):
        """
        Sync manifest with actual system state.
        
        - Discovers which tools are available
        - Updates binary paths
        - Marks missing tools
        """
        logger.info("🔄 Syncing manifest with system...")
        
        if not self._loaded:
            self.load()
        
        env = get_environment()
        
        for tool in self.manifest.get("tools", []):
            binary_name = tool.get("binary_name", "")
            
            # Skip internal/python tools
            if binary_name in ("internal", "python", "playwright"):
                tool["_available"] = True
                tool["_path"] = binary_name
                continue
            
            # Check if binary exists
            path = shutil.which(binary_name)
            if path:
                tool["_available"] = True
                tool["_path"] = path
            else:
                tool["_available"] = False
                tool["_path"] = None
        
        # Save updated manifest
        self.save()
    
    def get_missing_binaries(self) -> List[str]:
        """Get list of missing binary names."""
        missing = []
        for tool in self.get_tools():
            binary = tool.get("binary_name", "")
            if binary not in ("internal", "python", "playwright"):
                if not tool.get("_available", False):
                    if binary not in missing:
                        missing.append(binary)
        return missing
    
    def update_tool_availability(self, tool_name: str, available: bool, path: str = None):
        """Update a tool's availability status."""
        tool = self.get_tool(tool_name)
        if tool:
            tool["_available"] = available
            tool["_path"] = path
            self.save()
    
    def add_tool(self, tool_spec: Dict[str, Any]):
        """Add a new tool to the manifest."""
        if not self._loaded:
            self.load()
        
        # Check if already exists
        existing = self.get_tool(tool_spec.get("tool_name", ""))
        if existing:
            logger.warning(f"Tool already exists: {tool_spec.get('tool_name')}")
            return
        
        self.manifest.setdefault("tools", []).append(tool_spec)
        self.save()
        logger.info(f"➕ Added tool: {tool_spec.get('tool_name')}")
    
    def get_prompt_for_tool(self, tool_name: str) -> Optional[str]:
        """Get the JSON prompt template for a tool."""
        tool = self.get_tool(tool_name)
        if tool:
            return tool.get("json_prompt_template")
        return None
    
    def to_llm_context(self) -> str:
        """
        Generate a context string for LLM describing available tools.
        
        Returns a formatted string that can be included in prompts.
        """
        lines = ["## Available Security Tools\n"]
        
        # Group by category
        categories: Dict[str, List[Dict]] = {}
        for tool in self.get_available_tools():
            cat = tool.get("category", "other")
            categories.setdefault(cat, []).append(tool)
        
        for category, tools in sorted(categories.items()):
            lines.append(f"\n### {category.replace('_', ' ').title()}\n")
            for tool in tools:
                name = tool.get("tool_name", "unknown")
                desc = tool.get("description", "No description")
                intrusive = "⚠️ INTRUSIVE" if tool.get("intrusive") else ""
                lines.append(f"- **{name}**: {desc} {intrusive}")
        
        return "\n".join(lines)


# Singleton
_manager: Optional[ManifestManager] = None
_apt_manager: Optional[AptManager] = None


def get_apt_manager() -> AptManager:
    """Get global apt manager."""
    global _apt_manager
    if _apt_manager is None:
        _apt_manager = AptManager()
    return _apt_manager


def get_manifest() -> ManifestManager:
    """Get global manifest manager."""
    global _manager
    if _manager is None:
        _manager = ManifestManager()
        _manager.load()
    return _manager


async def initialize_manifest():
    """Initialize and sync manifest on startup."""
    manager = get_manifest()
    await manager.sync_with_system()
    return manager
