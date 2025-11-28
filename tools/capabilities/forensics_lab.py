"""
Digital Forensics Lab for Aegis v8.0

Provides forensic analysis capabilities including:
- Metadata extraction from files
- Embedded file extraction
- Steganography detection and extraction
- Memory forensics (basic)

Tools wrapped: exiftool, binwalk, steghide, volatility
"""

import asyncio
import json
import logging
import shutil
from typing import Dict, Any, Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)


class ForensicsLab:
    """
    Digital forensics analysis lab for CTF and incident response.
    
    Wraps common forensics tools (exiftool, binwalk, steghide, volatility)
    with self-healing capabilities.
    """
    
    # Dependency mapping: command -> package name
    DEPENDENCIES = {
        "exiftool": "libimage-exiftool-perl",
        "binwalk": "binwalk",
        "steghide": "steghide",
        "volatility": "volatility",
        "foremost": "foremost",
        "zsteg": "zsteg",
    }
    
    def __init__(self):
        """Initialize the forensics lab."""
        self.tool_paths: Dict[str, Optional[str]] = {}
        self._discover_tools()
        logger.info("🔬 ForensicsLab initialized")
    
    def _discover_tools(self) -> None:
        """Discover available forensics tools."""
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
    
    async def analyze_file_artifacts(
        self,
        filepath: str,
        timeout: int = 120
    ) -> Dict[str, Any]:
        """
        Comprehensive forensic analysis of a file.
        
        Extracts:
        - Metadata (EXIF, etc.)
        - Embedded files
        - Hidden data (steganography)
        
        Args:
            filepath: Path to the file to analyze
            timeout: Maximum time for analysis
            
        Returns:
            Dictionary with forensic analysis results
        """
        logger.info(f"🔬 Forensic analysis: {filepath}")
        
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
            "metadata": {},
            "embedded_files": [],
            "steganography": {},
            "anomalies": [],
            "tools_used": [],
        }
        
        # Step 1: Extract metadata
        meta_result = await self._extract_metadata(filepath, timeout)
        if meta_result.get("status") == "success":
            results["metadata"] = meta_result.get("data", {})
            results["tools_used"].append("exiftool")
        
        # Step 2: Check for embedded files
        embed_result = await self._find_embedded_files(filepath, timeout)
        if embed_result.get("status") == "success":
            results["embedded_files"] = embed_result.get("data", [])
            results["tools_used"].append("binwalk")
        
        # Step 3: Check for steganography (if image file)
        file_ext = path.suffix.lower()
        if file_ext in ['.png', '.jpg', '.jpeg', '.bmp', '.gif']:
            steg_result = await self._check_steganography(filepath, timeout)
            if steg_result.get("status") == "success":
                results["steganography"] = steg_result.get("data", {})
                if steg_result.get("tool"):
                    results["tools_used"].append(steg_result["tool"])
        
        # Step 4: Identify anomalies
        anomalies = self._identify_anomalies(results)
        results["anomalies"] = anomalies
        
        return results
    
    async def _extract_metadata(
        self,
        filepath: str,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """Extract metadata using exiftool."""
        if not self.check_dependency("exiftool"):
            return {"status": "skipped", "error": "exiftool not available"}
        
        try:
            cmd = ["exiftool", "-j", filepath]
            
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
            
            try:
                metadata = json.loads(output)
                if metadata and isinstance(metadata, list):
                    return {
                        "status": "success",
                        "data": metadata[0]
                    }
            except json.JSONDecodeError:
                # Fallback to text parsing
                return {
                    "status": "success",
                    "data": {"raw": output}
                }
            
            return {"status": "success", "data": {}}
            
        except asyncio.TimeoutError:
            return {"status": "error", "error": "Metadata extraction timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def _find_embedded_files(
        self,
        filepath: str,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """Find embedded files using binwalk."""
        if not self.check_dependency("binwalk"):
            return {"status": "skipped", "error": "binwalk not available"}
        
        try:
            # Just scan, don't extract
            cmd = ["binwalk", filepath]
            
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
            
            # Parse binwalk output
            embedded = []
            lines = output.strip().split('\n')
            
            for line in lines:
                # Skip header lines
                if line.startswith('DECIMAL') or line.startswith('-') or not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        offset = int(parts[0])
                        description = ' '.join(parts[2:])
                        embedded.append({
                            "offset": offset,
                            "hex_offset": parts[1] if len(parts) > 1 else hex(offset),
                            "description": description
                        })
                    except ValueError:
                        continue
            
            return {
                "status": "success",
                "data": embedded
            }
            
        except asyncio.TimeoutError:
            return {"status": "error", "error": "Embedded file scan timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def _check_steganography(
        self,
        filepath: str,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """Check for steganography in image files."""
        results = {"found": False, "details": []}
        tool_used = None
        
        # Try steghide info (for JPEG/BMP)
        if self.check_dependency("steghide"):
            try:
                cmd = ["steghide", "info", "-p", "", filepath]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    stdin=asyncio.subprocess.PIPE
                )
                
                # Send 'n' to not try to extract
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(input=b'n\n'),
                    timeout=timeout
                )
                
                output = stdout.decode('utf-8', errors='replace')
                output += stderr.decode('utf-8', errors='replace')
                
                # Check if embedded data was found
                if 'embedded data' in output.lower() or 'capacity' in output.lower():
                    results["found"] = True
                    results["details"].append({
                        "tool": "steghide",
                        "message": output.strip()
                    })
                    tool_used = "steghide"
                    
            except Exception as e:
                logger.debug(f"steghide check failed: {e}")
        
        # Try zsteg for PNG files
        if self.check_dependency("zsteg") and filepath.lower().endswith('.png'):
            try:
                cmd = ["zsteg", filepath]
                
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
                
                # Check for meaningful results
                if output.strip():
                    results["found"] = True
                    results["details"].append({
                        "tool": "zsteg",
                        "message": output.strip()[:1000]  # Limit output
                    })
                    tool_used = tool_used or "zsteg"
                    
            except Exception as e:
                logger.debug(f"zsteg check failed: {e}")
        
        return {
            "status": "success",
            "data": results,
            "tool": tool_used
        }
    
    def _identify_anomalies(self, results: Dict[str, Any]) -> List[str]:
        """Identify potential anomalies in forensic results."""
        anomalies = []
        
        # Check metadata for interesting fields
        metadata = results.get("metadata", {})
        
        # Look for hidden comments
        for key in ["Comment", "UserComment", "XPComment", "Description"]:
            if key in metadata and metadata[key]:
                anomalies.append(f"Found comment in metadata: {key}")
        
        # Look for GPS data (privacy concern)
        if any(k.startswith("GPS") for k in metadata.keys()):
            anomalies.append("GPS coordinates found in metadata")
        
        # Check for software that might indicate manipulation
        software = metadata.get("Software", "")
        manipulation_tools = ["photoshop", "gimp", "imagemagick"]
        if any(tool in software.lower() for tool in manipulation_tools):
            anomalies.append(f"Image editing software detected: {software}")
        
        # Check for embedded files
        if results.get("embedded_files"):
            anomalies.append(f"Found {len(results['embedded_files'])} embedded file signatures")
        
        # Check for steganography
        if results.get("steganography", {}).get("found"):
            anomalies.append("Potential steganographic content detected")
        
        return anomalies
    
    async def extract_embedded(
        self,
        filepath: str,
        output_dir: str = None,
        timeout: int = 120
    ) -> Dict[str, Any]:
        """
        Extract embedded files from a file.
        
        Args:
            filepath: Path to the file
            output_dir: Directory to extract to (default: <filepath>_extracted)
            timeout: Maximum extraction time
            
        Returns:
            Dictionary with extraction results
        """
        if not self.check_dependency("binwalk"):
            return {"status": "error", "error": "binwalk not available"}
        
        path = Path(filepath)
        if not path.exists():
            return {"status": "error", "error": f"File not found: {filepath}"}
        
        if not output_dir:
            output_dir = str(path.parent / f"{path.stem}_extracted")
        
        try:
            cmd = ["binwalk", "-e", "-C", output_dir, filepath]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            # List extracted files
            extracted = []
            output_path = Path(output_dir)
            if output_path.exists():
                for f in output_path.rglob('*'):
                    if f.is_file():
                        extracted.append(str(f))
            
            return {
                "status": "success",
                "data": {
                    "output_dir": output_dir,
                    "extracted_files": extracted,
                    "count": len(extracted)
                }
            }
            
        except asyncio.TimeoutError:
            return {"status": "error", "error": "Extraction timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def extract_steghide(
        self,
        filepath: str,
        password: str = "",
        output_file: str = None,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """
        Extract hidden data using steghide.
        
        Args:
            filepath: Path to the carrier file (JPEG/BMP)
            password: Passphrase (empty string for no password)
            output_file: Output filename (default: extracted from file)
            timeout: Maximum extraction time
            
        Returns:
            Dictionary with extraction results
        """
        if not self.check_dependency("steghide"):
            return {"status": "error", "error": "steghide not available"}
        
        path = Path(filepath)
        if not path.exists():
            return {"status": "error", "error": f"File not found: {filepath}"}
        
        try:
            if not output_file:
                output_file = str(path.parent / f"{path.stem}_steg_extracted")
            
            cmd = ["steghide", "extract", "-sf", filepath, "-xf", output_file, "-p", password, "-f"]
            
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
            error = stderr.decode('utf-8', errors='replace')
            
            if process.returncode == 0 and Path(output_file).exists():
                # Read extracted content
                with open(output_file, 'rb') as f:
                    content = f.read()
                
                # Try to decode as text
                try:
                    text_content = content.decode('utf-8')
                except UnicodeDecodeError:
                    text_content = None
                
                return {
                    "status": "success",
                    "data": {
                        "output_file": output_file,
                        "size": len(content),
                        "text_content": text_content,
                        "is_binary": text_content is None
                    }
                }
            else:
                return {
                    "status": "failed",
                    "error": error or "Failed to extract hidden data"
                }
                
        except asyncio.TimeoutError:
            return {"status": "error", "error": "Steghide extraction timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}


# Singleton instance
_forensics_lab_instance = None


def get_forensics_lab() -> ForensicsLab:
    """Get singleton forensics lab instance."""
    global _forensics_lab_instance
    if _forensics_lab_instance is None:
        _forensics_lab_instance = ForensicsLab()
    return _forensics_lab_instance
