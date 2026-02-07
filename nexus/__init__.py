"""
Nexus - Production-Grade Autonomous Pentesting Platform
========================================================

Built on:
- LangGraph: Stateful graph orchestration
- LiteLLM: Multi-provider LLM routing
- E2B SDK: Secure sandboxed execution
"""

from nexus.state import (
    NexusState,
    create_initial_state,
    add_event,
    consume_events,
    Phase,
    EpistemicMode,
)

from nexus.graph import (
    create_nexus_graph,
    compile_graph,
    get_nexus_graph,
    run_mission,
    stream_mission,
)

from nexus.nodes import (
    strategic_planner_node,
    field_operator_node,
    adversarial_judge_node,
)

from nexus.litellm_client import (
    get_completion,
    get_json_completion,
    stream_completion,
    get_litellm_client,
    LiteLLMClient,
)

from nexus.e2b_sandbox import (
    E2BSandbox,
    get_e2b_sandbox,
    execute_in_sandbox,
)

from nexus.tools import (
    TOOLS,
    ToolSpec,
    get_tool_spec,
    get_tool_risk,
    is_tool_allowed,
    parse_tool_output,
    list_tools,
)

__version__ = "1.0.0"

__all__ = [
    # State
    "NexusState",
    "create_initial_state",
    "add_event",
    "consume_events",
    "Phase",
    "EpistemicMode",
    # Graph
    "create_nexus_graph",
    "compile_graph",
    "get_nexus_graph",
    "run_mission",
    "stream_mission",
    # Nodes
    "strategic_planner_node",
    "field_operator_node",
    "adversarial_judge_node",
    # LiteLLM
    "get_completion",
    "get_json_completion",
    "stream_completion",
    "get_litellm_client",
    "LiteLLMClient",
    # E2B
    "E2BSandbox",
    "get_e2b_sandbox",
    "execute_in_sandbox",
    # Tools
    "TOOLS",
    "ToolSpec",
    "get_tool_spec",
    "get_tool_risk",
    "is_tool_allowed",
    "parse_tool_output",
    "list_tools",
]
