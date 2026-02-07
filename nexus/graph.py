"""
Nexus - LangGraph StateGraph
============================

Main graph definition for the Omega Protocol KTV loop.
Implements cyclic flow with backtracking on validation failure.
"""

import logging
from typing import Literal

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from nexus.state import NexusState, create_initial_state
from nexus.nodes import (
    strategic_planner_node,
    field_operator_node,
    adversarial_judge_node,
    should_validate,
    validation_result,
    should_continue,
)

logger = logging.getLogger(__name__)


def create_nexus_graph() -> StateGraph:
    """
    Create the Nexus StateGraph.
    
    Graph structure:
    
    START → strategic_planner → field_operator → adversarial_judge
                ↑                                        │
                └────────── backtrack ──────────────────┘
                                                         │
                                                         ↓
                                                       END
    
    Returns:
        Compiled StateGraph
    """
    # Create graph with NexusState
    graph = StateGraph(NexusState)
    
    # Add nodes
    graph.add_node("strategic_planner", strategic_planner_node)
    graph.add_node("field_operator", field_operator_node)
    graph.add_node("adversarial_judge", adversarial_judge_node)
    
    # Set entry point
    graph.set_entry_point("strategic_planner")
    
    # Add edges
    # strategic_planner → field_operator (always)
    graph.add_edge("strategic_planner", "field_operator")
    
    # field_operator → conditional (validate or continue)
    graph.add_conditional_edges(
        "field_operator",
        _route_after_test,
        {
            "validate": "adversarial_judge",
            "continue": "strategic_planner",
            "complete": END,
        }
    )
    
    # adversarial_judge → conditional (continue, backtrack, or complete)
    graph.add_conditional_edges(
        "adversarial_judge",
        _route_after_validate,
        {
            "continue": "strategic_planner",
            "backtrack": "strategic_planner",
            "complete": END,
        }
    )
    
    logger.info("📊 Nexus graph created")
    
    return graph


def _route_after_test(state: NexusState) -> Literal["validate", "continue", "complete"]:
    """Route after field_operator (TEST) phase."""
    # Check if mission complete
    if state["phase"] == "COMPLETE":
        return "complete"
    
    # Check if we have a result to validate
    result = state.get("last_result")
    if not result:
        return "continue"
    
    # Validate successful executions
    if result.get("status") == "success":
        # Check if high-risk action needs debate
        action = state.get("current_action")
        if action and action.get("risk_score", 0) > 5.0:
            return "validate"
    
    # Continue with next action
    return "continue"


def _route_after_validate(state: NexusState) -> Literal["continue", "backtrack", "complete"]:
    """Route after adversarial_judge (VALIDATE) phase."""
    # Check if mission complete
    if state["phase"] == "COMPLETE":
        return "complete"
    
    # Check debate result
    debate = state.get("debate_result")
    if debate and not debate.get("approved"):
        # Backtrack if rejected
        return "backtrack"
    
    # Continue with next action
    return "continue"


def compile_graph(checkpointer: bool = True) -> StateGraph:
    """
    Compile the Nexus graph with optional checkpointing.
    
    Args:
        checkpointer: Whether to enable state checkpointing
    
    Returns:
        Compiled graph ready for execution
    """
    graph = create_nexus_graph()
    
    if checkpointer:
        memory = MemorySaver()
        compiled = graph.compile(checkpointer=memory)
    else:
        compiled = graph.compile()
    
    logger.info("✅ Nexus graph compiled")
    return compiled


# Singleton compiled graph
_compiled_graph = None


def get_nexus_graph() -> StateGraph:
    """Get the compiled Nexus graph singleton."""
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = compile_graph()
    return _compiled_graph


async def run_mission(
    target: str,
    rules: str = "",
    mission_id: str = None,
    max_iterations: int = 50,
) -> NexusState:
    """
    Run a complete Nexus mission.
    
    Args:
        target: Target URL or IP
        rules: Mission rules
        mission_id: Optional mission ID
        max_iterations: Maximum iterations
    
    Returns:
        Final NexusState
    """
    import uuid
    
    if not mission_id:
        mission_id = str(uuid.uuid4())
    
    # Create initial state
    state = create_initial_state(
        target=target,
        mission_id=mission_id,
        rules=rules,
        max_iterations=max_iterations,
    )
    
    # Get compiled graph
    graph = get_nexus_graph()
    
    logger.info(f"🚀 Starting Nexus mission: {mission_id[:8]}...")
    
    # Run graph to completion
    config = {"configurable": {"thread_id": mission_id}}
    final_state = await graph.ainvoke(state, config)
    
    logger.info(f"✅ Nexus mission complete: {final_state['iteration']} iterations")
    
    return final_state


async def stream_mission(
    target: str,
    rules: str = "",
    mission_id: str = None,
    max_iterations: int = 50,
):
    """
    Stream a Nexus mission with real-time events.
    
    Yields events for WebSocket streaming.
    
    Args:
        target: Target URL or IP
        rules: Mission rules
        mission_id: Optional mission ID
        max_iterations: Maximum iterations
    
    Yields:
        Event dicts with type, node, and data
    """
    import uuid
    
    if not mission_id:
        mission_id = str(uuid.uuid4())
    
    # Create initial state
    state = create_initial_state(
        target=target,
        mission_id=mission_id,
        rules=rules,
        max_iterations=max_iterations,
    )
    
    # Get compiled graph
    graph = get_nexus_graph()
    
    logger.info(f"🚀 Streaming Nexus mission: {mission_id[:8]}...")
    
    config = {"configurable": {"thread_id": mission_id}}
    
    # Stream with events mode
    async for event in graph.astream_events(state, config, version="v2"):
        event_type = event.get("event")
        
        # Yield node start/end events
        if event_type in ("on_chain_start", "on_chain_end"):
            yield {
                "type": event_type,
                "node": event.get("name"),
                "data": event.get("data", {}),
            }
        
        # Yield custom events from state
        if event_type == "on_chain_end":
            output = event.get("data", {}).get("output", {})
            if isinstance(output, dict) and "pending_events" in output:
                for e in output.get("pending_events", []):
                    yield e
    
    logger.info(f"✅ Nexus mission stream complete")
