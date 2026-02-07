"""
Nexus - State Types
===================

TypedDict definitions for LangGraph state management.
Strictly typed for Python 3.10+.
"""

from typing import TypedDict, List, Dict, Any, Optional, Literal
from dataclasses import dataclass, field
from datetime import datetime


# Phase types for KTV Loop
Phase = Literal["KNOW", "THINK", "TEST", "VALIDATE", "COMPLETE", "BACKTRACK"]

# Epistemic modes
EpistemicMode = Literal["search", "balanced", "exploitation"]


class GraphNode(TypedDict):
    """Knowledge Graph node."""
    id: str
    type: str  # asset, technology, credential, vulnerability, endpoint
    label: str
    confidence: float
    properties: Dict[str, Any]


class GraphEdge(TypedDict):
    """Knowledge Graph edge."""
    id: str
    source: str
    target: str
    type: str  # uses, contains, vulnerable_to, leads_to
    confidence: float
    attack_vector: Optional[str]


class ActionProposal(TypedDict):
    """Action proposed by LLM."""
    tool: str
    args: Dict[str, Any]
    reasoning: str
    risk_score: float


class ToolResult(TypedDict):
    """Result from tool execution."""
    status: str  # success, error, blocked
    output: Any
    duration: float
    sandbox_type: str


class DebateResult(TypedDict):
    """Result from adversarial swarm debate."""
    approved: bool
    red_argument: str
    blue_argument: str
    judge_decision: str
    modifications: List[str]
    risk_score: float


class NexusState(TypedDict):
    """
    Main state for the Nexus LangGraph.
    
    This state flows through all nodes and edges,
    accumulating information as the KTV loop executes.
    """
    # Mission context
    target: str
    mission_id: str
    rules: str
    
    # Phase tracking
    phase: Phase
    iteration: int
    max_iterations: int
    
    # Epistemic state (from epistemic_priority.py)
    epistemic_confidence: float
    epistemic_mode: EpistemicMode
    knowledge_categories: Dict[str, float]  # category -> confidence
    
    # Knowledge graph (from knowledge_graph.py)
    graph_nodes: List[GraphNode]
    graph_edges: List[GraphEdge]
    attack_paths: List[List[str]]
    
    # Hive mind (from hive_mind.py)
    hive_knowledge: List[Dict[str, Any]]
    shared_discoveries: List[Dict[str, Any]]
    
    # Conversation history
    history: List[Dict[str, Any]]
    
    # Current action cycle
    current_action: Optional[ActionProposal]
    last_result: Optional[ToolResult]
    debate_result: Optional[DebateResult]
    
    # Backtracking
    backtrack_count: int
    backtrack_reason: Optional[str]
    
    # Error handling
    errors: List[str]
    
    # Streaming events (for WebSocket)
    pending_events: List[Dict[str, Any]]


def create_initial_state(
    target: str,
    mission_id: str,
    rules: str = "",
    max_iterations: int = 50
) -> NexusState:
    """Create initial Nexus state for a new mission."""
    return NexusState(
        target=target,
        mission_id=mission_id,
        rules=rules,
        phase="KNOW",
        iteration=0,
        max_iterations=max_iterations,
        epistemic_confidence=0.0,
        epistemic_mode="search",
        knowledge_categories={
            "technology_stack": 0.0,
            "architecture": 0.0,
            "input_vectors": 0.0,
            "authentication": 0.0,
            "api_structure": 0.0,
            "database": 0.0,
            "security_controls": 0.0,
            "business_logic": 0.0,
        },
        graph_nodes=[],
        graph_edges=[],
        attack_paths=[],
        hive_knowledge=[],
        shared_discoveries=[],
        history=[],
        current_action=None,
        last_result=None,
        debate_result=None,
        backtrack_count=0,
        backtrack_reason=None,
        errors=[],
        pending_events=[],
    )


def add_event(state: NexusState, event_type: str, data: Dict[str, Any]) -> None:
    """Add a streaming event to the state."""
    state["pending_events"].append({
        "type": event_type,
        "timestamp": datetime.now().isoformat(),
        "data": data
    })


def consume_events(state: NexusState) -> List[Dict[str, Any]]:
    """Consume and clear pending events."""
    events = state["pending_events"].copy()
    state["pending_events"] = []
    return events
