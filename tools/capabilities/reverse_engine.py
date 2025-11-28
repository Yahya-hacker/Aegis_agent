"""
Reverse Engineering Engine for Aegis v8.0

Provides binary analysis capabilities including:
- String extraction
- Disassembly and entry point analysis
- Basic reverse engineering automation

Tools wrapped: strings, objdump, radare2 (r2), gdb
"""

import asyncio
import logging
import subprocess
import shutil
from typing import Dict, Any, Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)


class ReverseEngine:
    """
    Reverse engineering engine for CTF and binary analysis.
    
    Wraps common RE tools (strings, objdump, radare2, gdb) with
    self-healing capabilities.
    """
    
    # Dependency mapping: command -> package name
    DEPENDENCIES = {
        "strings": "binutils",
        "objdump": "binutils",
        "r2": "radare2",
        "gdb": "gdb",
        "readelf": "binutils",
        "file": "file",
    }
    
    def __init__(self):
        """Initialize the reverse engineering engine."""
        self.tool_paths: Dict[str, Optional[str]] = {}
        self._discover_tools()
        logger.info("🔧 ReverseEngine initialized")
    
    def _discover_tools(self) -> None:
        """Discover available reverse engineering tools."""
        for tool in self.DEPENDENCIES.keys():
            path = shutil.which(tool)
            self.tool_paths[tool] = path
            if path:
                logger.debug(f"✅ Found {tool}: {path}")
            else:
                logger.debug(f"⚠️ Tool {tool} not found")
    
    def check_dependency(self, tool_name: str) -> bool:
        """
        Check if a specific tool is available.
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            True if the tool is available, False otherwise
        """
        if tool_name not in self.tool_paths:
            self._discover_tools()
        return self.tool_paths.get(tool_name) is not None
    
    def get_missing_dependencies(self) -> List[str]:
        """
        Get list of missing tools.
        
        Returns:
            List of tool names that are not installed
        """
        return [tool for tool, path in self.tool_paths.items() if path is None]
    
    async def analyze_binary(
        self,
        filepath: str,
        timeout: int = 120
    ) -> Dict[str, Any]:
        """
        Comprehensive binary analysis.
        
        Extracts:
        - File type and metadata
        - Strings (printable characters)
        - Entry points and sections
        - Basic disassembly
        
        Args:
            filepath: Path to the binary file
            timeout: Maximum time for analysis
            
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"🔍 Analyzing binary: {filepath}")
        
        # Validate file exists
        path = Path(filepath)
        if not path.exists():
            return {"status": "error", "error": f"File not found: {filepath}"}
        
        if not path.is_file():
            return {"status": "error", "error": f"Not a file: {filepath}"}
        
        results = {
            "status": "success",
            "filepath": str(path.absolute()),
            "filename": path.name,
            "size": path.stat().st_size,
            "file_type": None,
            "strings": [],
            "interesting_strings": [],
            "entry_point": None,
            "sections": [],
            "symbols": [],
            "security": {},
            "tools_used": [],
        }
        
        # Step 1: Get file type
        file_result = await self._get_file_type(filepath, timeout)
        if file_result.get("status") == "success":
            results["file_type"] = file_result.get("data")
            results["tools_used"].append("file")
        
        # Step 2: Extract strings
        strings_result = await self._extract_strings(filepath, timeout)
        if strings_result.get("status") == "success":
            results["strings"] = strings_result.get("data", [])[:100]  # Limit to 100
            results["interesting_strings"] = strings_result.get("interesting", [])
            results["tools_used"].append("strings")
        
        # Step 3: Get ELF info if applicable
        if results["file_type"] and "ELF" in str(results["file_type"]):
            elf_result = await self._analyze_elf(filepath, timeout)
            if elf_result.get("status") == "success":
                results["entry_point"] = elf_result.get("entry_point")
                results["sections"] = elf_result.get("sections", [])
                results["symbols"] = elf_result.get("symbols", [])[:50]
                results["tools_used"].extend(["readelf", "objdump"])
        
        # Step 4: Try radare2 analysis if available
        r2_result = await self._r2_analyze(filepath, timeout)
        if r2_result.get("status") == "success":
            results["r2_analysis"] = r2_result.get("data")
            results["tools_used"].append("radare2")
        
        return results
    
    async def _get_file_type(
        self,
        filepath: str,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """Get file type using `file` command."""
        if not self.check_dependency("file"):
            return {"status": "skipped", "error": "file command not available"}
        
        try:
            cmd = ["file", "-b", filepath]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            return {
                "status": "success",
                "data": stdout.decode('utf-8', errors='replace').strip()
            }
            
        except asyncio.TimeoutError:
            return {"status": "error", "error": "File type detection timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def _extract_strings(
        self,
        filepath: str,
        timeout: int = 60,
        min_length: int = 4
    ) -> Dict[str, Any]:
        """Extract printable strings from binary."""
        if not self.check_dependency("strings"):
            return {"status": "skipped", "error": "strings command not available"}
        
        try:
            cmd = ["strings", "-n", str(min_length), filepath]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            strings_list = stdout.decode('utf-8', errors='replace').strip().split('\n')
            strings_list = [s for s in strings_list if s.strip()]
            
            # Find interesting strings (potential flags, passwords, URLs, etc.)
            interesting = []
            patterns = [
                'flag', 'FLAG', 'password', 'secret', 'key',
                'http://', 'https://', 'ftp://',
                '/bin/sh', '/bin/bash', 'system',
                'admin', 'root', 'user',
            ]
            
            for s in strings_list:
                for pattern in patterns:
                    if pattern in s:
                        interesting.append(s)
                        break
            
            return {
                "status": "success",
                "data": strings_list,
                "interesting": interesting[:50],  # Limit interesting strings
                "total_count": len(strings_list)
            }
            
        except asyncio.TimeoutError:
            return {"status": "error", "error": "String extraction timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def _analyze_elf(
        self,
        filepath: str,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """Analyze ELF binary using readelf and objdump."""
        results = {
            "status": "success",
            "entry_point": None,
            "sections": [],
            "symbols": []
        }
        
        # Get entry point and sections with readelf
        if self.check_dependency("readelf"):
            try:
                # Get header info
                cmd = ["readelf", "-h", filepath]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
                output = stdout.decode('utf-8', errors='replace')
                
                # Parse entry point
                for line in output.split('\n'):
                    if 'Entry point address:' in line:
                        results["entry_point"] = line.split(':')[-1].strip()
                        break
                
                # Get sections
                cmd = ["readelf", "-S", filepath]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
                output = stdout.decode('utf-8', errors='replace')
                
                # Parse sections (simplified)
                sections = []
                for line in output.split('\n'):
                    if ']' in line and '.' in line:
                        parts = line.split()
                        for part in parts:
                            if part.startswith('.'):
                                sections.append(part)
                                break
                results["sections"] = sections
                
            except Exception as e:
                logger.warning(f"readelf analysis failed: {e}")
        
        # Get symbols with objdump
        if self.check_dependency("objdump"):
            try:
                cmd = ["objdump", "-t", filepath]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
                output = stdout.decode('utf-8', errors='replace')
                
                # Parse symbols (simplified - get function names)
                symbols = []
                for line in output.split('\n'):
                    parts = line.split()
                    if len(parts) >= 5 and parts[-2] in ['F', 'g', 'l']:
                        symbols.append(parts[-1])
                results["symbols"] = symbols
                
            except Exception as e:
                logger.warning(f"objdump analysis failed: {e}")
        
        return results
    
    async def _r2_analyze(
        self,
        filepath: str,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """Basic analysis using radare2."""
        if not self.check_dependency("r2"):
            return {"status": "skipped", "error": "radare2 not available"}
        
        try:
            # Run r2 with analysis commands
            # -q: quiet mode, -c: run commands
            cmd = ["r2", "-q", "-c", "aaa; afl; pdf @ main; q", filepath]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            output = stdout.decode('utf-8', errors='replace')
            
            # Parse function list
            functions = []
            disassembly = ""
            
            lines = output.split('\n')
            in_disasm = False
            
            for line in lines:
                if line.startswith('0x') and 'sym.' in line:
                    # Function entry
                    parts = line.split()
                    if len(parts) >= 4:
                        functions.append({
                            "address": parts[0],
                            "name": parts[-1]
                        })
                elif '┌' in line or '│' in line or '└' in line:
                    # Disassembly output
                    disassembly += line + '\n'
            
            return {
                "status": "success",
                "data": {
                    "functions": functions[:30],  # Limit functions
                    "main_disassembly": disassembly[:2000]  # Limit disassembly
                }
            }
            
        except asyncio.TimeoutError:
            return {"status": "error", "error": "Radare2 analysis timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def disassemble_function(
        self,
        filepath: str,
        function_name: str = "main",
        timeout: int = 60
    ) -> Dict[str, Any]:
        """
        Disassemble a specific function.
        
        Args:
            filepath: Path to binary
            function_name: Name of function to disassemble
            timeout: Maximum time for disassembly
            
        Returns:
            Dictionary with disassembly output
        """
        if not self.check_dependency("objdump"):
            return {"status": "error", "error": "objdump not available"}
        
        try:
            cmd = ["objdump", "-d", filepath]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            output = stdout.decode('utf-8', errors='replace')
            
            # Find the specified function
            lines = output.split('\n')
            in_function = False
            function_asm = []
            
            for line in lines:
                if f'<{function_name}>:' in line:
                    in_function = True
                    function_asm.append(line)
                elif in_function:
                    if line.strip() == '' or (line and not line.startswith(' ')):
                        if function_asm:
                            break
                    else:
                        function_asm.append(line)
            
            if function_asm:
                return {
                    "status": "success",
                    "data": {
                        "function": function_name,
                        "disassembly": '\n'.join(function_asm)
                    }
                }
            else:
                return {
                    "status": "not_found",
                    "error": f"Function '{function_name}' not found"
                }
                
        except asyncio.TimeoutError:
            return {"status": "error", "error": "Disassembly timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}


# Singleton instance
_reverse_engine_instance = None


def get_reverse_engine() -> ReverseEngine:
    """Get singleton reverse engine instance."""
    global _reverse_engine_instance
    if _reverse_engine_instance is None:
        _reverse_engine_instance = ReverseEngine()
    return _reverse_engine_instance
