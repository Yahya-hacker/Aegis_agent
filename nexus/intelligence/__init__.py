"""
Nexus v2.0 - Intelligence Layer
===============================

AI-powered analysis and planning components.
"""

from nexus.intelligence.litellm_client import (
    get_completion,
    get_json_completion,
    ModelType,
)
from nexus.intelligence.attack_planner import (
    AttackPlanner,
    AttackChain,
    AttackNode,
    get_attack_planner,
)
from nexus.intelligence.report_generator import (
    ReportGenerator,
    VulnerabilityFinding,
    BugBountyReport,
    Severity,
    ReportFormat,
    get_report_generator,
)

__all__ = [
    # LiteLLM Client
    "get_completion",
    "get_json_completion",
    "ModelType",
    # Attack Planner
    "AttackPlanner",
    "AttackChain",
    "AttackNode",
    "get_attack_planner",
    # Report Generator
    "ReportGenerator",
    "VulnerabilityFinding",
    "BugBountyReport",
    "Severity",
    "ReportFormat",
    "get_report_generator",
]
