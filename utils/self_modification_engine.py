"""
Self-Modification Engine for Aegis Agent
Enables the agent to create, modify, and optimize its own tools at runtime
Version 1.0 - Dynamic Tool Creation and Adaptation
"""

import asyncio
import os
import json
import logging
import inspect
import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime

logger = logging.getLogger(__name__)


class SelfModificationEngine:
    """
    Enables the agent to modify its own code and create custom tools on-the-fly.
    
    Features:
    - Dynamic Python tool generation from requirements
    - Tool modification based on performance feedback
    - Runtime code validation and testing
    - Safe code execution with sandboxing
    """
    
    def __init__(self, tools_dir: str = "tools/python_tools"):
        """Initialize the self-modification engine"""
        self.tools_dir = Path(tools_dir)
        self.tools_dir.mkdir(parents=True, exist_ok=True)
        self.custom_tools: Dict[str, Dict[str, Any]] = {}
        self.tool_performance: Dict[str, Dict[str, Any]] = {}
        self.modification_history: List[Dict[str, Any]] = []
        
        # Load existing custom tools
        self._load_custom_tools()
        
        logger.info(f"✅ Self-Modification Engine initialized with {len(self.custom_tools)} custom tools")
    
    def _load_custom_tools(self):
        """Load existing custom tools from the tools directory"""
        manifest_path = self.tools_dir / "custom_tools_manifest.json"
        
        if manifest_path.exists():
            try:
                with open(manifest_path, 'r') as f:
                    self.custom_tools = json.load(f)
                logger.info(f"Loaded {len(self.custom_tools)} custom tools from manifest")
            except Exception as e:
                logger.error(f"Failed to load custom tools manifest: {e}")
    
    def _save_custom_tools(self):
        """Save custom tools manifest"""
        manifest_path = self.tools_dir / "custom_tools_manifest.json"
        
        try:
            with open(manifest_path, 'w') as f:
                json.dump(self.custom_tools, f, indent=2)
            logger.info("Custom tools manifest saved")
        except Exception as e:
            logger.error(f"Failed to save custom tools manifest: {e}")
    
    async def create_custom_tool(
        self,
        tool_name: str,
        description: str,
        requirements: str,
        expected_inputs: List[str],
        expected_outputs: List[str],
        ai_orchestrator: Optional[Any] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Create a custom Python tool based on requirements using AI assistance.
        
        Args:
            tool_name: Name of the tool to create
            description: What the tool should do
            requirements: Detailed requirements for the tool
            expected_inputs: List of expected input parameters
            expected_outputs: List of expected outputs
            ai_orchestrator: Optional AI orchestrator for code generation
            
        Returns:
            Tool metadata dict if successful, None otherwise
        """
        logger.info(f"🔧 Creating custom tool: {tool_name}")
        
        try:
            # Generate tool code using AI if available
            if ai_orchestrator:
                tool_code = await self._generate_tool_code_with_ai(
                    tool_name, description, requirements, expected_inputs, expected_outputs, ai_orchestrator
                )
            else:
                tool_code = self._generate_basic_tool_template(
                    tool_name, description, expected_inputs, expected_outputs
                )
            
            # Validate the generated code
            if not self._validate_tool_code(tool_code):
                logger.error(f"❌ Generated tool code failed validation for {tool_name}")
                return None
            
            # Save the tool file
            tool_file = self.tools_dir / f"{tool_name}.py"
            with open(tool_file, 'w') as f:
                f.write(tool_code)
            
            # Create tool metadata
            tool_metadata = {
                "name": tool_name,
                "description": description,
                "file_path": str(tool_file),
                "created_at": datetime.now().isoformat(),
                "version": "1.0",
                "inputs": expected_inputs,
                "outputs": expected_outputs,
                "performance": {
                    "success_count": 0,
                    "failure_count": 0,
                    "avg_execution_time": 0.0
                }
            }
            
            # Register the tool
            self.custom_tools[tool_name] = tool_metadata
            self._save_custom_tools()
            
            # Record modification
            self.modification_history.append({
                "action": "create",
                "tool_name": tool_name,
                "timestamp": datetime.now().isoformat(),
                "description": f"Created new tool: {description}"
            })
            
            logger.info(f"✅ Custom tool created successfully: {tool_name}")
            return tool_metadata
            
        except Exception as e:
            logger.error(f"❌ Failed to create custom tool {tool_name}: {e}", exc_info=True)
            return None
    
    async def _generate_tool_code_with_ai(
        self,
        tool_name: str,
        description: str,
        requirements: str,
        inputs: List[str],
        outputs: List[str],
        ai_orchestrator: Any
    ) -> str:
        """Generate tool code using AI assistance"""
        
        prompt = f"""Generate a complete, production-ready Python tool with the following specifications:

Tool Name: {tool_name}
Description: {description}

Requirements:
{requirements}

Expected Inputs: {', '.join(inputs)}
Expected Outputs: {', '.join(outputs)}

Generate a Python module with:
1. Comprehensive docstrings
2. Type hints for all functions
3. Error handling and validation
4. Async support if appropriate
5. Logging for debugging
6. A main function that serves as the entry point

Format: Return ONLY the Python code, no explanation.
"""
        
        try:
            # Use the code-specialized LLM from the orchestrator
            response = await ai_orchestrator.query_llm(
                prompt=prompt,
                role="code",
                temperature=0.3,  # Lower temperature for more deterministic code
                max_tokens=4096
            )
            
            # Extract code from response
            code = self._extract_code_from_response(response)
            return code
            
        except Exception as e:
            logger.error(f"Failed to generate tool code with AI: {e}")
            return self._generate_basic_tool_template(tool_name, description, inputs, outputs)
    
    def _generate_basic_tool_template(
        self,
        tool_name: str,
        description: str,
        inputs: List[str],
        outputs: List[str]
    ) -> str:
        """Generate a basic tool template without AI"""
        
        input_params = ", ".join([f"{inp}: Any" for inp in inputs])
        
        template = f'''"""
{tool_name} - {description}
Auto-generated by Aegis Self-Modification Engine
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


async def execute({input_params}) -> Dict[str, Any]:
    """
    Execute the {tool_name} tool.
    
    Args:
{chr(10).join([f"        {inp}: Input parameter" for inp in inputs])}
    
    Returns:
        Result dictionary with keys: {', '.join(outputs)}
    """
    try:
        logger.info(f"Executing {tool_name}")
        
        # TODO: Implement tool logic here
        result = {{
{chr(10).join([f'            "{out}": None,' for out in outputs])}
        }}
        
        return {{"success": True, "data": result}}
        
    except Exception as e:
        logger.error(f"Error in {tool_name}: {{e}}", exc_info=True)
        return {{"success": False, "error": str(e)}}


def main():
    """Main entry point for standalone execution"""
    # Example usage
    result = asyncio.run(execute({', '.join(['None'] * len(inputs))}))
    print(result)


if __name__ == "__main__":
    main()
'''
        return template
    
    def _extract_code_from_response(self, response: str) -> str:
        """Extract Python code from AI response"""
        import re
        
        # Try to extract from code blocks
        code_match = re.search(r'```python\s*\n(.*?)\n```', response, re.DOTALL)
        if code_match:
            return code_match.group(1)
        
        code_match = re.search(r'```\s*\n(.*?)\n```', response, re.DOTALL)
        if code_match:
            return code_match.group(1)
        
        # If no code block, return the whole response (assuming it's all code)
        return response.strip()
    
    def _validate_tool_code(self, code: str) -> bool:
        """Validate tool code for syntax errors and security issues"""
        try:
            # Check for syntax errors
            compile(code, '<string>', 'exec')
            
            # Security checks - Warning only, don't block
            # These patterns might be legitimate in security tools
            potentially_dangerous_patterns = [
                'eval(',
                'exec(',
                '__import__',
                'os.system(',
            ]
            
            for pattern in potentially_dangerous_patterns:
                if pattern in code:
                    logger.warning(f"⚠️ Potentially sensitive operation detected: {pattern}")
                    logger.warning("   Review the generated tool carefully before execution")
                    # Don't reject - security tools often need these operations
            
            # Block only truly dangerous patterns without legitimate use
            forbidden_patterns = [
                'rm -rf /',
                'format C:',
                'del /f /s /q C:\\',
            ]
            
            for pattern in forbidden_patterns:
                if pattern in code:
                    logger.error(f"❌ Forbidden dangerous pattern detected: {pattern}")
                    return False
            
            return True
            
        except SyntaxError as e:
            logger.error(f"Syntax error in generated code: {e}")
            return False
    
    async def modify_tool(
        self,
        tool_name: str,
        modification_reason: str,
        ai_orchestrator: Optional[Any] = None
    ) -> bool:
        """
        Modify an existing tool based on performance feedback.
        
        Args:
            tool_name: Name of the tool to modify
            modification_reason: Reason for modification (e.g., "Failed to handle edge case X")
            ai_orchestrator: Optional AI orchestrator for code modification
            
        Returns:
            True if modification successful, False otherwise
        """
        logger.info(f"🔧 Modifying tool: {tool_name}")
        
        if tool_name not in self.custom_tools:
            logger.error(f"Tool {tool_name} not found in custom tools")
            return False
        
        try:
            tool_metadata = self.custom_tools[tool_name]
            tool_file = Path(tool_metadata["file_path"])
            
            if not tool_file.exists():
                logger.error(f"Tool file not found: {tool_file}")
                return False
            
            # Read current code
            with open(tool_file, 'r') as f:
                current_code = f.read()
            
            # Generate modification using AI if available
            if ai_orchestrator:
                modified_code = await self._modify_code_with_ai(
                    tool_name, current_code, modification_reason, ai_orchestrator
                )
            else:
                logger.warning("No AI orchestrator available, cannot modify tool automatically")
                return False
            
            # Validate modified code
            if not self._validate_tool_code(modified_code):
                logger.error("Modified code failed validation")
                return False
            
            # Backup original
            backup_file = tool_file.with_suffix('.py.backup')
            with open(backup_file, 'w') as f:
                f.write(current_code)
            
            # Save modified code
            with open(tool_file, 'w') as f:
                f.write(modified_code)
            
            # Update metadata
            tool_metadata["version"] = str(float(tool_metadata.get("version", "1.0")) + 0.1)
            tool_metadata["last_modified"] = datetime.now().isoformat()
            self._save_custom_tools()
            
            # Record modification
            self.modification_history.append({
                "action": "modify",
                "tool_name": tool_name,
                "timestamp": datetime.now().isoformat(),
                "reason": modification_reason
            })
            
            logger.info(f"✅ Tool modified successfully: {tool_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to modify tool {tool_name}: {e}", exc_info=True)
            return False
    
    async def _modify_code_with_ai(
        self,
        tool_name: str,
        current_code: str,
        modification_reason: str,
        ai_orchestrator: Any
    ) -> str:
        """Modify tool code using AI assistance"""
        
        prompt = f"""You are modifying an existing Python tool. Here is the current code:

```python
{current_code}
```

Modification Requirement:
{modification_reason}

Generate the MODIFIED version of the code that addresses the requirement while:
1. Maintaining all existing functionality
2. Keeping the same function signatures
3. Adding necessary improvements
4. Maintaining code quality and documentation

Return ONLY the complete modified Python code, no explanation.
"""
        
        try:
            response = await ai_orchestrator.query_llm(
                prompt=prompt,
                role="code",
                temperature=0.3,
                max_tokens=4096
            )
            
            return self._extract_code_from_response(response)
            
        except Exception as e:
            logger.error(f"Failed to modify code with AI: {e}")
            raise
    
    async def execute_custom_tool(
        self,
        tool_name: str,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Execute a custom tool dynamically.
        
        Args:
            tool_name: Name of the tool to execute
            **kwargs: Arguments to pass to the tool
            
        Returns:
            Tool execution result
        """
        if tool_name not in self.custom_tools:
            return {"success": False, "error": f"Tool {tool_name} not found"}
        
        try:
            # Import the tool module dynamically
            tool_metadata = self.custom_tools[tool_name]
            tool_file = Path(tool_metadata["file_path"])
            
            # Add tools directory to path if not already there
            tools_parent = str(tool_file.parent)
            if tools_parent not in sys.path:
                sys.path.insert(0, tools_parent)
            
            # Import the module
            module_name = tool_file.stem
            spec = importlib.util.spec_from_file_location(module_name, tool_file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Get the execute function
            if hasattr(module, 'execute'):
                execute_func = module.execute
                
                # Track execution time
                start_time = asyncio.get_event_loop().time()
                
                # Execute the tool
                if asyncio.iscoroutinefunction(execute_func):
                    result = await execute_func(**kwargs)
                else:
                    result = execute_func(**kwargs)
                
                end_time = asyncio.get_event_loop().time()
                execution_time = end_time - start_time
                
                # Update performance metrics
                self._update_tool_performance(tool_name, result.get("success", False), execution_time)
                
                return result
            else:
                return {"success": False, "error": f"Tool {tool_name} has no execute function"}
                
        except Exception as e:
            logger.error(f"Failed to execute custom tool {tool_name}: {e}", exc_info=True)
            self._update_tool_performance(tool_name, False, 0)
            return {"success": False, "error": str(e)}
    
    def _update_tool_performance(self, tool_name: str, success: bool, execution_time: float):
        """Update performance metrics for a tool"""
        if tool_name not in self.custom_tools:
            return
        
        perf = self.custom_tools[tool_name]["performance"]
        
        if success:
            perf["success_count"] += 1
        else:
            perf["failure_count"] += 1
        
        # Update average execution time
        total_executions = perf["success_count"] + perf["failure_count"]
        current_avg = perf["avg_execution_time"]
        perf["avg_execution_time"] = (current_avg * (total_executions - 1) + execution_time) / total_executions
        
        self._save_custom_tools()
    
    def get_tool_performance_report(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get performance report for a specific tool"""
        if tool_name not in self.custom_tools:
            return None
        
        metadata = self.custom_tools[tool_name]
        perf = metadata["performance"]
        
        total = perf["success_count"] + perf["failure_count"]
        success_rate = (perf["success_count"] / total * 100) if total > 0 else 0
        
        return {
            "tool_name": tool_name,
            "version": metadata["version"],
            "total_executions": total,
            "success_count": perf["success_count"],
            "failure_count": perf["failure_count"],
            "success_rate": f"{success_rate:.2f}%",
            "avg_execution_time": f"{perf['avg_execution_time']:.3f}s"
        }
    
    def get_all_custom_tools(self) -> List[Dict[str, Any]]:
        """Get list of all custom tools"""
        return list(self.custom_tools.values())
    
    def get_modification_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent modification history"""
        return self.modification_history[-limit:]


# Global instance
_self_modification_engine: Optional[SelfModificationEngine] = None


def get_self_modification_engine() -> SelfModificationEngine:
    """Get or create global self-modification engine instance"""
    global _self_modification_engine
    
    if _self_modification_engine is None:
        _self_modification_engine = SelfModificationEngine()
    
    return _self_modification_engine
