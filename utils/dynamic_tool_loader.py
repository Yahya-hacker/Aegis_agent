"""
Dynamic Tool Loader for Aegis AI
Loads tools from manifest and builds dynamic prompts
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class DynamicToolLoader:
    """Loads and manages tools from kali_tool_manifest.json"""
    
    def __init__(self, manifest_path: str = "tools/kali_tool_manifest.json"):
        """Initialize the dynamic tool loader"""
        self.manifest_path = Path(manifest_path)
        self.all_tools = []
        self.available_tools = []
        self.unavailable_tools = []
        self.tool_map = {}  # Map tool_name -> tool definition
        self._load_manifest()
    
    def _load_manifest(self):
        """Load tool manifest from JSON file"""
        if not self.manifest_path.exists():
            logger.error(f"Tool manifest not found at {self.manifest_path}")
            raise FileNotFoundError(f"Tool manifest not found: {self.manifest_path}")
        
        try:
            with open(self.manifest_path, 'r') as f:
                data = json.load(f)
                self.all_tools = data.get('tools', [])
            
            logger.info(f"✅ Loaded {len(self.all_tools)} tools from manifest")
            
            # Create tool map
            for tool in self.all_tools:
                self.tool_map[tool['tool_name']] = tool
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse tool manifest: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to load tool manifest: {e}")
            raise
    
    def discover_available_tools(self) -> tuple:
        """
        Discover which tools are available on the system
        
        Returns:
            Tuple of (available_tools, unavailable_tools)
        """
        self.available_tools = []
        self.unavailable_tools = []
        
        for tool in self.all_tools:
            binary_name = tool.get('binary_name')
            tool_name = tool.get('tool_name')
            
            # Special handling for internal/python tools
            if binary_name in ['internal', 'python']:
                self.available_tools.append(tool)
                continue
            
            # Check if binary exists in PATH
            if self._check_binary_exists(binary_name):
                self.available_tools.append(tool)
                logger.info(f"✅ Tool available: {tool_name} ({binary_name})")
            else:
                self.unavailable_tools.append(tool)
                logger.warning(f"⚠️ Tool not available: {tool_name} ({binary_name})")
        
        logger.info(f"📊 Discovery complete: {len(self.available_tools)}/{len(self.all_tools)} tools available")
        
        return self.available_tools, self.unavailable_tools
    
    def _check_binary_exists(self, binary_name: str) -> bool:
        """Check if a binary exists in PATH"""
        try:
            result = subprocess.run(
                f"which {binary_name}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"Error checking binary {binary_name}: {e}")
            return False
    
    def build_dynamic_tool_prompt(self, include_unavailable: bool = False) -> str:
        """
        Build a dynamic tool prompt from available tools
        
        Args:
            include_unavailable: Include unavailable tools with warning (default: False)
            
        Returns:
            Formatted string describing all available tools
        """
        tools_to_include = self.available_tools
        if include_unavailable:
            tools_to_include = self.all_tools
        
        prompt_parts = ["AVAILABLE TOOLS:"]
        
        # Group tools by category
        categories = {}
        for tool in tools_to_include:
            category = tool.get('category', 'other')
            if category not in categories:
                categories[category] = []
            categories[category].append(tool)
        
        # Build prompt for each category
        for category, tools in sorted(categories.items()):
            prompt_parts.append(f"\n{category.upper().replace('_', ' ')}:")
            
            for tool in tools:
                tool_name = tool['tool_name']
                description = tool['description']
                
                # Build args description
                args_schema = tool.get('args_schema', {})
                args_parts = []
                for arg_name, arg_spec in args_schema.items():
                    required = arg_spec.get('required', False)
                    arg_type = arg_spec.get('type', 'string')
                    req_marker = "*" if required else ""
                    args_parts.append(f"{arg_name}{req_marker}: {arg_type}")
                
                args_desc = ", ".join(args_parts) if args_parts else "none"
                
                # Check if tool is available
                is_available = tool in self.available_tools
                availability_marker = "" if is_available else " [UNAVAILABLE]"
                
                # Mark intrusive tools
                intrusive_marker = " ⚠️ INTRUSIVE" if tool.get('intrusive', False) else ""
                
                prompt_parts.append(
                    f"- {tool_name}: {description} (args: {args_desc}){intrusive_marker}{availability_marker}"
                )
        
        return "\n".join(prompt_parts)
    
    def get_tool_info(self, tool_name: str) -> Optional[Dict]:
        """Get information about a specific tool"""
        return self.tool_map.get(tool_name)
    
    def is_tool_intrusive(self, tool_name: str) -> bool:
        """Check if a tool is intrusive"""
        tool = self.get_tool_info(tool_name)
        if tool:
            return tool.get('intrusive', False)
        return False
    
    def get_intrusive_tools(self) -> List[Dict]:
        """Get list of all intrusive tools"""
        return [tool for tool in self.available_tools if tool.get('intrusive', False)]
    
    def get_non_intrusive_tools(self) -> List[Dict]:
        """Get list of all non-intrusive tools"""
        return [tool for tool in self.available_tools if not tool.get('intrusive', False)]
    
    def get_tools_by_category(self, category: str) -> List[Dict]:
        """Get all tools in a specific category"""
        return [tool for tool in self.available_tools if tool.get('category') == category]
    
    def get_statistics(self) -> Dict:
        """Get statistics about loaded tools"""
        return {
            "total_tools": len(self.all_tools),
            "available_tools": len(self.available_tools),
            "unavailable_tools": len(self.unavailable_tools),
            "intrusive_tools": len(self.get_intrusive_tools()),
            "non_intrusive_tools": len(self.get_non_intrusive_tools()),
            "categories": list(set(tool.get('category', 'other') for tool in self.all_tools))
        }


# Singleton instance
_tool_loader_instance = None

def get_tool_loader() -> DynamicToolLoader:
    """Get the singleton tool loader instance"""
    global _tool_loader_instance
    if _tool_loader_instance is None:
        _tool_loader_instance = DynamicToolLoader()
        _tool_loader_instance.discover_available_tools()
    return _tool_loader_instance
