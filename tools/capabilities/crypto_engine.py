"""
Cryptography Engine for Aegis v8.0

Provides automated cryptographic analysis capabilities including:
- Hash identification and cracking
- Cipher detection and decryption
- Encoding detection and decoding

Tools wrapped: ciphey, hashid, john
"""

import asyncio
import logging
import os
import shutil
import tempfile
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


class CryptoEngine:
    """
    Cryptography analysis engine for CTF and penetration testing.
    
    Wraps common cryptographic tools (ciphey, hashid, john) with
    self-healing capabilities - if a tool is missing, it can be
    installed on-the-fly.
    """
    
    # Dependency mapping: command -> package name
    DEPENDENCIES = {
        "ciphey": "ciphey",
        "hashid": "hashid",
        "john": "john",
        "hash-identifier": "hash-identifier",
    }
    
    def __init__(self):
        """Initialize the crypto engine."""
        self.tool_paths: Dict[str, Optional[str]] = {}
        self._discover_tools()
        logger.info("🔐 CryptoEngine initialized")
    
    def _discover_tools(self) -> None:
        """Discover available cryptography tools."""
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
    
    async def solve_crypto(
        self,
        text_or_file: str,
        timeout: int = 120
    ) -> Dict[str, Any]:
        """
        Auto-detect hash/encoding and attempt decryption.
        
        This function will:
        1. Try to identify if input is a hash (using hashid)
        2. Try to auto-decrypt using ciphey
        3. Return analysis results
        
        Args:
            text_or_file: Either a string to analyze or a file path
            timeout: Maximum time in seconds for analysis
            
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"🔐 Analyzing cryptographic content...")
        
        results = {
            "status": "success",
            "input": text_or_file[:100] + "..." if len(text_or_file) > 100 else text_or_file,
            "hash_identification": None,
            "decryption_result": None,
            "possible_types": [],
            "tools_used": [],
        }
        
        # Step 1: Try hash identification
        hash_result = await self._identify_hash(text_or_file, timeout)
        if hash_result.get("status") == "success":
            results["hash_identification"] = hash_result.get("data")
            results["possible_types"] = hash_result.get("possible_types", [])
            results["tools_used"].append("hashid")
        
        # Step 2: Try auto-decryption with ciphey
        decrypt_result = await self._auto_decrypt(text_or_file, timeout)
        if decrypt_result.get("status") == "success":
            results["decryption_result"] = decrypt_result.get("data")
            results["tools_used"].append("ciphey")
        
        # If no results, indicate analysis is inconclusive
        if not results["hash_identification"] and not results["decryption_result"]:
            results["status"] = "inconclusive"
            results["message"] = "Could not identify or decrypt the input"
        
        return results
    
    async def _identify_hash(
        self,
        hash_string: str,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """
        Identify hash type using hashid.
        
        Args:
            hash_string: The hash to identify
            timeout: Maximum time for identification
            
        Returns:
            Dictionary with identification results
        """
        if not self.check_dependency("hashid"):
            logger.warning("hashid not available, skipping hash identification")
            return {"status": "skipped", "error": "hashid not installed"}
        
        try:
            # Run hashid on the input
            cmd = ["hashid", hash_string.strip()]
            
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
            
            # Parse hashid output
            possible_types = []
            for line in output.strip().split('\n'):
                line = line.strip()
                if line and not line.startswith('Analyzing'):
                    # Extract hash type from lines like "[+] MD5"
                    if line.startswith('[+]'):
                        hash_type = line.replace('[+]', '').strip()
                        possible_types.append(hash_type)
            
            if possible_types:
                return {
                    "status": "success",
                    "data": output,
                    "possible_types": possible_types
                }
            else:
                return {
                    "status": "no_match",
                    "data": output,
                    "possible_types": []
                }
                
        except asyncio.TimeoutError:
            return {"status": "error", "error": f"Hash identification timed out after {timeout}s"}
        except Exception as e:
            logger.error(f"Hash identification error: {e}")
            return {"status": "error", "error": str(e)}
    
    async def _auto_decrypt(
        self,
        ciphertext: str,
        timeout: int = 120
    ) -> Dict[str, Any]:
        """
        Attempt automatic decryption using ciphey.
        
        Args:
            ciphertext: The encrypted/encoded text to decrypt
            timeout: Maximum time for decryption attempt
            
        Returns:
            Dictionary with decryption results
        """
        if not self.check_dependency("ciphey"):
            logger.warning("ciphey not available, skipping auto-decryption")
            return {"status": "skipped", "error": "ciphey not installed"}
        
        try:
            # Run ciphey with the input
            cmd = ["ciphey", "-t", ciphertext.strip(), "-q"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            output = stdout.decode('utf-8', errors='replace').strip()
            
            if output and process.returncode == 0:
                return {
                    "status": "success",
                    "data": {
                        "plaintext": output,
                        "original": ciphertext[:100]
                    }
                }
            else:
                return {
                    "status": "failed",
                    "data": None,
                    "message": "Could not decrypt"
                }
                
        except asyncio.TimeoutError:
            return {"status": "error", "error": f"Decryption timed out after {timeout}s"}
        except Exception as e:
            logger.error(f"Auto-decrypt error: {e}")
            return {"status": "error", "error": str(e)}
    
    async def crack_hash(
        self,
        hash_value: str,
        hash_type: Optional[str] = None,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Attempt to crack a hash using john.
        
        Args:
            hash_value: The hash to crack
            hash_type: Type of hash (e.g., 'md5', 'sha256')
            wordlist: Path to wordlist file
            timeout: Maximum time for cracking attempt
            
        Returns:
            Dictionary with cracking results
        """
        if not self.check_dependency("john"):
            logger.warning("john not available, skipping hash cracking")
            return {"status": "skipped", "error": "john not installed"}
        
        try:
            # Write hash to a temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.hash', delete=False) as f:
                f.write(hash_value.strip() + '\n')
                hash_file = f.name
            
            try:
                # Build john command
                cmd = ["john", hash_file]
                
                if hash_type:
                    cmd.extend(["--format=" + hash_type])
                
                if wordlist and os.path.exists(wordlist):
                    cmd.extend(["--wordlist=" + wordlist])
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                
                # Try to show cracked passwords
                show_cmd = ["john", "--show", hash_file]
                show_process = await asyncio.create_subprocess_exec(
                    *show_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                show_stdout, _ = await show_process.communicate()
                show_output = show_stdout.decode('utf-8', errors='replace').strip()
                
                # Parse output for cracked passwords
                cracked = []
                for line in show_output.split('\n'):
                    if ':' in line and not line.startswith('0 password'):
                        parts = line.split(':')
                        if len(parts) >= 2:
                            cracked.append({
                                "hash": parts[0],
                                "password": parts[1]
                            })
                
                return {
                    "status": "success" if cracked else "not_cracked",
                    "data": {
                        "cracked": cracked,
                        "output": show_output
                    }
                }
                
            finally:
                # Clean up temp file
                if os.path.exists(hash_file):
                    os.unlink(hash_file)
                    
        except asyncio.TimeoutError:
            return {"status": "error", "error": f"Hash cracking timed out after {timeout}s"}
        except Exception as e:
            logger.error(f"Hash cracking error: {e}")
            return {"status": "error", "error": str(e)}


# Singleton instance
_crypto_engine_instance = None


def get_crypto_engine() -> CryptoEngine:
    """Get singleton crypto engine instance."""
    global _crypto_engine_instance
    if _crypto_engine_instance is None:
        _crypto_engine_instance = CryptoEngine()
    return _crypto_engine_instance
