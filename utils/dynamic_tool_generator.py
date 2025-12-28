"""
Dynamic Tool Generator for Aegis AI v9.1
=========================================

This module enables the agent to create, modify, and execute custom Python tools
at runtime based on the scenario requirements.

Features:
- Runtime tool generation using LLM
- Safe sandboxed execution
- Tool caching and persistence
- Automatic tool improvement based on feedback
"""

import asyncio
import json
import logging
import hashlib
import os
import tempfile
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class GeneratedTool:
    """Represents a dynamically generated tool"""
    name: str
    description: str
    code: str
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    version: int = 1
    success_count: int = 0
    failure_count: int = 0
    last_used: Optional[str] = None
    last_error: Optional[str] = None
    category: str = "custom"
    
    @property
    def code_hash(self) -> str:
        """Generate hash of the code for caching"""
        return hashlib.sha256(self.code.encode()).hexdigest()[:12]
    
    @property
    def reliability_score(self) -> float:
        """Calculate reliability based on usage history"""
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.5  # No history, neutral score
        return self.success_count / total


class DynamicToolGenerator:
    """
    Generates and manages custom Python tools at runtime.
    
    The agent can request tools that don't exist, and this generator will:
    1. Use the Coder LLM to generate appropriate Python code
    2. Validate and sandbox the code for safe execution
    3. Cache successful tools for reuse
    4. Improve tools based on execution feedback
    """
    
    def __init__(self, ai_core=None):
        """
        Initialize the Dynamic Tool Generator.
        
        Args:
            ai_core: Reference to the EnhancedAegisAI core for LLM access
        """
        self.ai_core = ai_core
        self.generated_tools: Dict[str, GeneratedTool] = {}
        self.tools_dir = Path("data/generated_tools")
        self.tools_dir.mkdir(parents=True, exist_ok=True)
        
        # Execution limits for safety
        self.max_execution_time = 60  # seconds
        self.max_output_size = 1024 * 1024  # 1MB
        
        # Forbidden imports for security
        self.forbidden_imports = [
            'subprocess',  # Handled specially when needed
            'ctypes',
            'importlib',
            '__builtins__',
        ]
        
        # Load cached tools
        self._load_cached_tools()
        
        logger.info("🔧 DynamicToolGenerator initialized")
    
    def _load_cached_tools(self) -> None:
        """Load previously generated tools from disk"""
        cache_file = self.tools_dir / "tool_cache.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                    for tool_data in data.get('tools', []):
                        tool = GeneratedTool(**tool_data)
                        self.generated_tools[tool.name] = tool
                logger.info(f"📂 Loaded {len(self.generated_tools)} cached tools")
            except Exception as e:
                logger.warning(f"Failed to load tool cache: {e}")
    
    def _save_cached_tools(self) -> None:
        """Save generated tools to disk for persistence"""
        cache_file = self.tools_dir / "tool_cache.json"
        try:
            data = {
                'tools': [
                    {
                        'name': t.name,
                        'description': t.description,
                        'code': t.code,
                        'created_at': t.created_at,
                        'version': t.version,
                        'success_count': t.success_count,
                        'failure_count': t.failure_count,
                        'last_used': t.last_used,
                        'last_error': t.last_error,
                        'category': t.category
                    }
                    for t in self.generated_tools.values()
                ]
            }
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save tool cache: {e}")
    
    async def generate_tool(
        self,
        task_description: str,
        input_schema: Optional[Dict[str, Any]] = None,
        output_format: str = "json",
        examples: Optional[List[Dict]] = None
    ) -> GeneratedTool:
        """
        Generate a new custom tool based on task description.
        
        Args:
            task_description: What the tool should do
            input_schema: Expected input parameters
            output_format: Expected output format (json, text, binary)
            examples: Example inputs/outputs to guide generation
            
        Returns:
            GeneratedTool object ready for execution
        """
        # Create a unique tool name
        tool_name = self._generate_tool_name(task_description)
        
        # Check if we already have a suitable cached tool
        if tool_name in self.generated_tools:
            cached = self.generated_tools[tool_name]
            if cached.reliability_score > 0.7:
                logger.info(f"♻️ Reusing cached tool: {tool_name}")
                return cached
        
        # Generate new tool using LLM
        logger.info(f"🔨 Generating new tool: {tool_name}")
        
        generation_prompt = self._build_generation_prompt(
            task_description, input_schema, output_format, examples
        )
        
        if self.ai_core and hasattr(self.ai_core, 'orchestrator'):
            response = await self.ai_core.orchestrator.call_llm(
                'coder',
                [
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": generation_prompt}
                ],
                temperature=0.7,
                max_tokens=2048
            )
            code = self._extract_code(response.get('content', ''))
        else:
            # Fallback: generate a simple template
            code = self._generate_fallback_code(task_description, input_schema)
        
        # Validate the generated code
        if not self._validate_code(code):
            logger.warning(f"⚠️ Generated code failed validation")
            code = self._sanitize_code(code)
        
        # Create the tool object
        tool = GeneratedTool(
            name=tool_name,
            description=task_description,
            code=code,
            category=self._categorize_tool(task_description)
        )
        
        # Cache the tool
        self.generated_tools[tool_name] = tool
        self._save_cached_tools()
        
        logger.info(f"✅ Generated tool: {tool_name}")
        return tool
    
    async def execute_tool(
        self,
        tool: GeneratedTool,
        input_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a generated tool safely.
        
        Args:
            tool: The GeneratedTool to execute
            input_data: Input parameters for the tool
            
        Returns:
            Execution result dictionary
        """
        logger.info(f"▶️ Executing tool: {tool.name}")
        
        # Update usage tracking
        tool.last_used = datetime.now().isoformat()
        
        try:
            # Create sandboxed execution environment
            result = await self._sandboxed_execute(tool.code, input_data)
            
            if result.get('success'):
                tool.success_count += 1
                logger.info(f"✅ Tool {tool.name} executed successfully")
            else:
                tool.failure_count += 1
                tool.last_error = result.get('error', 'Unknown error')
                logger.warning(f"⚠️ Tool {tool.name} failed: {tool.last_error}")
            
            # Save updated stats
            self._save_cached_tools()
            
            return result
            
        except Exception as e:
            tool.failure_count += 1
            tool.last_error = str(e)
            self._save_cached_tools()
            
            logger.error(f"❌ Tool {tool.name} execution error: {e}")
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }
    
    async def improve_tool(
        self,
        tool: GeneratedTool,
        error_feedback: str,
        expected_behavior: str
    ) -> GeneratedTool:
        """
        Improve an existing tool based on feedback.
        
        Args:
            tool: The tool to improve
            error_feedback: What went wrong
            expected_behavior: What should happen instead
            
        Returns:
            Improved version of the tool
        """
        logger.info(f"🔄 Improving tool: {tool.name}")
        
        improvement_prompt = f"""Improve this Python tool based on feedback.

CURRENT CODE:
```python
{tool.code}
```

ISSUE ENCOUNTERED:
{error_feedback}

EXPECTED BEHAVIOR:
{expected_behavior}

REQUIREMENTS:
1. Fix the identified issue
2. Maintain the same function signature
3. Keep the code clean and efficient
4. Return a complete, working implementation

Return ONLY the improved Python code:
```python
# Improved code
```"""
        
        if self.ai_core and hasattr(self.ai_core, 'orchestrator'):
            response = await self.ai_core.orchestrator.call_llm(
                'coder',
                [
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": improvement_prompt}
                ],
                temperature=0.7,
                max_tokens=2048
            )
            new_code = self._extract_code(response.get('content', ''))
        else:
            new_code = tool.code  # Keep original if no LLM
        
        # Create improved version
        improved_tool = GeneratedTool(
            name=tool.name,
            description=tool.description,
            code=new_code,
            version=tool.version + 1,
            success_count=0,
            failure_count=0,
            category=tool.category
        )
        
        # Replace in cache
        self.generated_tools[tool.name] = improved_tool
        self._save_cached_tools()
        
        logger.info(f"✅ Tool improved: {tool.name} v{improved_tool.version}")
        return improved_tool
    
    async def _sandboxed_execute(
        self,
        code: str,
        input_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute Python code in a sandboxed environment.
        
        WARNING: This is a basic subprocess sandbox. For production use,
        consider using containers (Docker), RestrictedPython, or other
        proper isolation mechanisms for enhanced security.
        
        Args:
            code: Python code to execute
            input_data: Input data for the code
            
        Returns:
            Execution result dictionary
        """
        # Validate code before execution
        if not self._validate_code(code):
            return {
                'success': False,
                'error': 'Code validation failed - potential security risk detected'
            }
        
        # Write to temporary file
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.py',
            delete=False
        ) as f:
            # Create wrapper that handles input/output
            wrapper_code = f'''
import json
import sys

# Input data
INPUT_DATA = {json.dumps(input_data)}

# Tool code
{code}

# Execute main function if it exists
if __name__ == "__main__":
    try:
        if 'execute' in dir():
            result = execute(INPUT_DATA)
        elif 'main' in dir():
            result = main(INPUT_DATA)
        elif 'run' in dir():
            result = run(INPUT_DATA)
        else:
            # Try to find any callable
            result = {{"error": "No execute/main/run function found"}}
        
        # Output result as JSON
        print(json.dumps(result, default=str))
    except Exception as e:
        print(json.dumps({{"error": str(e)}}, default=str))
        sys.exit(1)
'''
            f.write(wrapper_code)
            script_path = f.name
        
        try:
            # Execute with timeout
            process = await asyncio.create_subprocess_exec(
                'python', script_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.max_execution_time
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    'success': False,
                    'error': f'Execution timed out after {self.max_execution_time}s'
                }
            
            # Parse output
            stdout_text = stdout.decode('utf-8', errors='replace')
            stderr_text = stderr.decode('utf-8', errors='replace')
            
            if len(stdout_text) > self.max_output_size:
                stdout_text = stdout_text[:self.max_output_size] + '... [truncated]'
            
            if process.returncode == 0:
                try:
                    result = json.loads(stdout_text.strip())
                    return {'success': True, 'output': result}
                except json.JSONDecodeError:
                    return {'success': True, 'output': {'raw': stdout_text}}
            else:
                return {
                    'success': False,
                    'error': stderr_text or 'Execution failed',
                    'stdout': stdout_text
                }
                
        finally:
            # Cleanup
            try:
                os.unlink(script_path)
            except OSError:
                pass
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for code generation"""
        return """You are an expert Python security tool developer. 
Generate clean, efficient, and safe Python code for security testing tools.

RULES:
1. Always create a main function called 'execute(input_data: dict) -> dict'
2. Handle all exceptions gracefully
3. Return results as a dictionary with 'status' and 'data' keys
4. Use only standard library or common security packages
5. Never use shell commands directly - use Python libraries
6. Validate all inputs before processing
7. Follow security best practices

OUTPUT FORMAT:
Always return complete, runnable Python code in a ```python block."""
    
    def _build_generation_prompt(
        self,
        task_description: str,
        input_schema: Optional[Dict[str, Any]],
        output_format: str,
        examples: Optional[List[Dict]]
    ) -> str:
        """Build the prompt for tool generation"""
        prompt = f"""Generate a Python security tool for the following task:

TASK: {task_description}

"""
        if input_schema:
            prompt += f"""INPUT SCHEMA:
{json.dumps(input_schema, indent=2)}

"""
        
        prompt += f"""OUTPUT FORMAT: {output_format}

"""
        
        if examples:
            prompt += "EXAMPLES:\n"
            for i, ex in enumerate(examples, 1):
                prompt += f"""Example {i}:
  Input: {json.dumps(ex.get('input', {}))}
  Output: {json.dumps(ex.get('output', {}))}

"""
        
        prompt += """Generate a complete Python tool with:
1. An 'execute(input_data: dict) -> dict' function
2. Proper error handling
3. Clear documentation

Return ONLY the Python code:
```python
# Your code here
```"""
        
        return prompt
    
    def _extract_code(self, content: str) -> str:
        """Extract Python code from LLM response"""
        import re
        
        # Try to find code blocks
        patterns = [
            r'```python\s*(.*?)\s*```',
            r'```\s*(.*?)\s*```',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content, re.DOTALL)
            if match:
                return match.group(1).strip()
        
        # If no code block, assume the entire content is code
        return content.strip()
    
    def _validate_code(self, code: str) -> bool:
        """Validate generated code for safety using AST parsing"""
        import ast
        
        # Try to compile to check syntax
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            logger.warning(f"Syntax error in generated code: {e}")
            return False
        
        # Check for dangerous imports and calls using AST
        class SecurityChecker(ast.NodeVisitor):
            def __init__(self):
                self.violations = []
            
            def visit_Import(self, node):
                for alias in node.names:
                    if alias.name in ['subprocess', 'ctypes', 'importlib', 'builtins', '__builtins__']:
                        self.violations.append(f"Forbidden import: {alias.name}")
                self.generic_visit(node)
            
            def visit_ImportFrom(self, node):
                if node.module in ['subprocess', 'ctypes', 'importlib', 'builtins', '__builtins__']:
                    self.violations.append(f"Forbidden import from: {node.module}")
                self.generic_visit(node)
            
            def visit_Call(self, node):
                # Check for dangerous function calls
                if isinstance(node.func, ast.Name):
                    if node.func.id in ['eval', 'exec', 'compile', '__import__']:
                        self.violations.append(f"Forbidden call: {node.func.id}")
                elif isinstance(node.func, ast.Attribute):
                    if node.func.attr in ['system', 'popen', 'spawn']:
                        self.violations.append(f"Forbidden method call: {node.func.attr}")
                self.generic_visit(node)
        
        checker = SecurityChecker()
        checker.visit(tree)
        
        if checker.violations:
            for violation in checker.violations:
                logger.warning(f"Security violation in generated code: {violation}")
            return False
        
        return True
    
    def _sanitize_code(self, code: str) -> str:
        """Sanitize code by removing dangerous elements"""
        import re
        
        # Remove dangerous imports
        for forbidden in self.forbidden_imports:
            code = re.sub(
                rf'^import\s+{forbidden}.*$',
                f'# import {forbidden}  # REMOVED FOR SAFETY',
                code,
                flags=re.MULTILINE
            )
            code = re.sub(
                rf'^from\s+{forbidden}\s+import.*$',
                f'# from {forbidden} import ...  # REMOVED FOR SAFETY',
                code,
                flags=re.MULTILINE
            )
        
        return code
    
    def _generate_tool_name(self, description: str) -> str:
        """Generate a unique tool name from description"""
        import re
        import hashlib
        
        # Extract key words
        words = re.findall(r'\b[a-z]+\b', description.lower())
        
        # Use first few significant words
        significant = [w for w in words if len(w) > 3][:3]
        
        if significant:
            return '_'.join(significant) + '_tool'
        else:
            # Fallback to hash - use SHA-256 for security
            return f"custom_tool_{hashlib.sha256(description.encode()).hexdigest()[:8]}"
    
    def _categorize_tool(self, description: str) -> str:
        """Categorize a tool based on its description"""
        description_lower = description.lower()
        
        categories = {
            'crypto': ['encrypt', 'decrypt', 'cipher', 'hash', 'base64', 'rot13'],
            'forensics': ['forensic', 'exif', 'metadata', 'steganography', 'hidden'],
            'network': ['network', 'packet', 'pcap', 'tcp', 'http', 'dns'],
            'web': ['web', 'http', 'html', 'javascript', 'xss', 'sql'],
            'binary': ['binary', 'elf', 'exe', 'disassemble', 'reverse'],
            'pwn': ['exploit', 'rop', 'buffer', 'overflow', 'shellcode'],
        }
        
        for category, keywords in categories.items():
            if any(kw in description_lower for kw in keywords):
                return category
        
        return 'general'
    
    def _generate_fallback_code(
        self,
        task_description: str,
        input_schema: Optional[Dict[str, Any]]
    ) -> str:
        """Generate simple fallback code when LLM is unavailable"""
        return f'''"""
Auto-generated fallback tool
Task: {task_description}
"""

def execute(input_data: dict) -> dict:
    """Execute the tool with given input data"""
    try:
        # Basic implementation - to be improved by LLM
        result = {{
            "status": "success",
            "message": "Fallback implementation executed",
            "input_received": input_data,
            "note": "This is a basic fallback. LLM generation recommended."
        }}
        return result
    except Exception as e:
        return {{
            "status": "error",
            "error": str(e)
        }}
'''
    
    def get_available_tools(self) -> List[Dict[str, Any]]:
        """Get list of all generated tools"""
        return [
            {
                'name': t.name,
                'description': t.description,
                'version': t.version,
                'reliability': t.reliability_score,
                'category': t.category,
                'usage': {
                    'success': t.success_count,
                    'failure': t.failure_count
                }
            }
            for t in self.generated_tools.values()
        ]
    
    def get_tool_by_name(self, name: str) -> Optional[GeneratedTool]:
        """Get a specific tool by name"""
        return self.generated_tools.get(name)


# Global instance
_generator_instance: Optional[DynamicToolGenerator] = None


def get_tool_generator(ai_core=None) -> DynamicToolGenerator:
    """Get the global DynamicToolGenerator instance"""
    global _generator_instance
    if _generator_instance is None:
        _generator_instance = DynamicToolGenerator(ai_core)
    elif ai_core is not None and _generator_instance.ai_core is None:
        _generator_instance.ai_core = ai_core
    return _generator_instance
