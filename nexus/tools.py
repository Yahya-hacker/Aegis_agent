"""
Nexus - Tool Definitions
========================

Tool configurations for E2B sandbox execution.
Ports existing tool logic from tools/tool_manager.py.
"""

import os
import logging
from typing import Any, Callable, Optional
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


@dataclass
class ToolSpec:
    """Specification for a security tool."""
    name: str
    command: str
    description: str
    category: str  # recon, exploit, analysis, utility
    risk_score: float  # 0-10
    parser: Optional[str] = None  # Parser function name from utils/parsers.py
    requires_sudo: bool = False
    sandbox_type: str = "custom"  # custom, code_interpreter


# Tool registry
TOOLS: dict[str, ToolSpec] = {
    # Reconnaissance tools (low risk)
    "nmap_scan": ToolSpec(
        name="nmap_scan",
        command="nmap",
        description="Network port scanner",
        category="recon",
        risk_score=3.0,
        parser="parse_nmap_output",
    ),
    "subfinder": ToolSpec(
        name="subfinder",
        command="subfinder",
        description="Subdomain discovery",
        category="recon",
        risk_score=2.0,
        parser="parse_subfinder_output",
    ),
    "httpx": ToolSpec(
        name="httpx",
        command="httpx",
        description="HTTP probing",
        category="recon",
        risk_score=2.0,
        parser="parse_httpx_output",
    ),
    "nuclei": ToolSpec(
        name="nuclei",
        command="nuclei",
        description="Vulnerability scanner",
        category="recon",
        risk_score=4.0,
        parser="parse_nuclei_output",
    ),
    "ffuf": ToolSpec(
        name="ffuf",
        command="ffuf",
        description="Directory/file brute forcing",
        category="recon",
        risk_score=5.0,
        parser="parse_ffuf_output",
    ),
    
    # Exploitation tools (high risk)
    "sqlmap": ToolSpec(
        name="sqlmap",
        command="sqlmap",
        description="SQL injection testing",
        category="exploit",
        risk_score=8.0,
        parser="parse_sqlmap_output",
    ),
    "xss_test": ToolSpec(
        name="xss_test",
        command="dalfox",
        description="XSS vulnerability testing",
        category="exploit",
        risk_score=7.0,
        parser="parse_dalfox_output",
    ),
    
    # Analysis tools
    "curl": ToolSpec(
        name="curl",
        command="curl",
        description="HTTP client",
        category="utility",
        risk_score=2.0,
    ),
    "jq": ToolSpec(
        name="jq",
        command="jq",
        description="JSON processor",
        category="utility",
        risk_score=1.0,
    ),
    
    # Python-based tools (code interpreter)
    "python_script": ToolSpec(
        name="python_script",
        command="python3",
        description="Execute Python code",
        category="utility",
        risk_score=5.0,
        sandbox_type="code_interpreter",
    ),
}


def get_tool_spec(tool_name: str) -> Optional[ToolSpec]:
    """Get tool specification by name."""
    return TOOLS.get(tool_name)


def get_tool_risk(tool_name: str) -> float:
    """Get risk score for a tool."""
    spec = TOOLS.get(tool_name)
    return spec.risk_score if spec else 5.0


def is_tool_allowed(tool_name: str, epistemic_confidence: float) -> tuple[bool, str]:
    """
    Check if tool is allowed based on epistemic state.
    
    Implements the Epistemic Priority rule:
    - If confidence < 60%, high-risk tools (exploit category) are blocked
    
    Args:
        tool_name: Name of the tool
        epistemic_confidence: Current epistemic confidence (0.0-1.0)
    
    Returns:
        Tuple of (allowed, reason)
    """
    spec = TOOLS.get(tool_name)
    
    if not spec:
        return False, f"Unknown tool: {tool_name}"
    
    # Block exploitation tools if confidence is low
    if spec.category == "exploit" and epistemic_confidence < 0.6:
        return False, f"Tool '{tool_name}' blocked: Confidence ({epistemic_confidence:.0%}) < 60%"
    
    return True, "OK"


def build_tool_command(tool_name: str, args: dict[str, Any]) -> tuple[str, list[str]]:
    """
    Build command and arguments for a tool.
    
    Args:
        tool_name: Name of the tool
        args: Tool arguments
    
    Returns:
        Tuple of (command, argument_list)
    """
    spec = TOOLS.get(tool_name)
    if not spec:
        raise ValueError(f"Unknown tool: {tool_name}")
    
    cmd_args = []
    
    for key, value in args.items():
        if value is None:
            continue
        elif isinstance(value, bool):
            if value:
                cmd_args.append(f"--{key}")
        elif isinstance(value, list):
            for v in value:
                cmd_args.append(f"--{key}")
                cmd_args.append(str(v))
        else:
            # Handle short flags
            if len(key) == 1:
                cmd_args.append(f"-{key}")
                cmd_args.append(str(value))
            else:
                cmd_args.append(f"--{key}={value}")
    
    return spec.command, cmd_args


def get_parser(parser_name: Optional[str]) -> Optional[Callable]:
    """
    Get parser function by name.
    
    Imports from utils/parsers.py when needed.
    """
    if not parser_name:
        return None
    
    try:
        # Import parsers module
        import importlib
        parsers = importlib.import_module("utils.parsers")
        return getattr(parsers, parser_name, None)
    except ImportError:
        logger.warning(f"⚠️ Could not import parser: {parser_name}")
        return None


def parse_tool_output(tool_name: str, output: str) -> dict[str, Any]:
    """
    Parse tool output using the registered parser.
    
    Args:
        tool_name: Name of the tool
        output: Raw tool output
    
    Returns:
        Parsed output dict
    """
    spec = TOOLS.get(tool_name)
    if not spec or not spec.parser:
        return {"raw": output}
    
    parser = get_parser(spec.parser)
    if parser:
        try:
            return parser(output)
        except Exception as e:
            logger.warning(f"⚠️ Parser error for {tool_name}: {e}")
    
    return {"raw": output}


def list_tools(category: Optional[str] = None) -> list[dict[str, Any]]:
    """
    List available tools.
    
    Args:
        category: Optional category filter
    
    Returns:
        List of tool info dicts
    """
    tools = []
    for name, spec in TOOLS.items():
        if category and spec.category != category:
            continue
        tools.append({
            "name": name,
            "command": spec.command,
            "description": spec.description,
            "category": spec.category,
            "risk_score": spec.risk_score,
        })
    return tools


# Tool categories for UI
TOOL_CATEGORIES = {
    "recon": "Reconnaissance",
    "exploit": "Exploitation",
    "analysis": "Analysis",
    "utility": "Utility",
}
