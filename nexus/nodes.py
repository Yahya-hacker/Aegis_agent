"""
Nexus - LangGraph Node Implementations
======================================

Node functions for the Nexus StateGraph.
Each node represents a phase of the Omega Protocol KTV loop.
"""

import logging
import time
from typing import Any

from nexus.state import (
    NexusState, 
    add_event, 
    ActionProposal, 
    ToolResult, 
    DebateResult,
    GraphNode,
    GraphEdge,
)
from nexus.litellm_client import get_json_completion
from nexus.e2b_sandbox import execute_in_sandbox
from nexus.tools import (
    get_tool_spec, 
    get_tool_risk, 
    is_tool_allowed, 
    parse_tool_output,
    list_tools,
)

logger = logging.getLogger(__name__)


# ============================================================================
# STRATEGIC PLANNER NODE (KNOW/THINK)
# ============================================================================

async def strategic_planner_node(state: NexusState) -> NexusState:
    """
    Strategic Planner: KNOW/THINK phase.
    
    Responsibilities:
    - Analyze current epistemic state
    - Build context from knowledge graph
    - Propose next action based on LLM reasoning
    """
    state["iteration"] += 1
    state["phase"] = "THINK"
    
    add_event(state, "phase_start", {"phase": "THINK", "iteration": state["iteration"]})
    logger.info(f"🧠 Strategic Planner: Iteration {state['iteration']}")
    
    # Check max iterations
    if state["iteration"] >= state["max_iterations"]:
        add_event(state, "max_iterations", {"count": state["iteration"]})
        state["phase"] = "COMPLETE"
        return state
    
    # Build system prompt based on epistemic state
    system_prompt = _build_planner_prompt(state)
    
    # Build conversation history
    messages = [
        {"role": "system", "content": system_prompt},
        *state["history"],
        {"role": "user", "content": f"Current confidence: {state['epistemic_confidence']:.0%}. Propose next action."}
    ]
    
    # Get LLM decision
    try:
        response = await get_json_completion(
            model_type="strategic",
            messages=messages,
            temperature=0.7,
        )
        
        if response:
            state["current_action"] = ActionProposal(
                tool=response.get("tool", ""),
                args=response.get("args", {}),
                reasoning=response.get("reasoning", ""),
                risk_score=get_tool_risk(response.get("tool", "")),
            )
            
            add_event(state, "action_proposed", {
                "tool": state["current_action"]["tool"],
                "reasoning": state["current_action"]["reasoning"][:200],
            })
            
            # Add to history
            state["history"].append({
                "role": "assistant",
                "content": f"Action: {state['current_action']['tool']} - {state['current_action']['reasoning']}"
            })
        else:
            state["errors"].append("LLM returned no response")
            state["phase"] = "BACKTRACK"
            state["backtrack_reason"] = "LLM failure"
            
    except Exception as e:
        logger.error(f"❌ Strategic planner error: {e}")
        state["errors"].append(str(e))
        state["phase"] = "BACKTRACK"
        state["backtrack_reason"] = str(e)
    
    return state


def _build_planner_prompt(state: NexusState) -> str:
    """Build system prompt for strategic planner."""
    # Get allowed tools based on epistemic state
    if state["epistemic_mode"] == "search":
        allowed_tools = [t for t in list_tools() if t["category"] == "recon"]
    else:
        allowed_tools = list_tools()
    
    tool_list = ", ".join([t["name"] for t in allowed_tools])
    
    # Build knowledge graph summary
    graph_summary = f"Nodes: {len(state['graph_nodes'])}, Edges: {len(state['graph_edges'])}"
    
    return f"""You are Nexus, an elite autonomous penetration testing agent.

TARGET: {state['target']}
RULES: {state['rules'] or "Standard penetration testing rules apply."}

EPISTEMIC STATE:
- Mode: {state['epistemic_mode'].upper()}
- Confidence: {state['epistemic_confidence']:.0%}
- Knowledge Graph: {graph_summary}

ALLOWED TOOLS: {tool_list}

Respond in JSON format:
{{
  "reasoning": "Your analysis of the situation...",
  "tool": "tool_name",
  "args": {{"arg1": "value1"}}
}}

IMPORTANT:
- In SEARCH mode, focus on reconnaissance to build confidence
- In EXPLOITATION mode, you may test vulnerabilities
- Always explain your reasoning"""


# ============================================================================
# FIELD OPERATOR NODE (TEST)
# ============================================================================

async def field_operator_node(state: NexusState) -> NexusState:
    """
    Field Operator: TEST phase.
    
    Responsibilities:
    - Execute proposed action in E2B sandbox
    - Parse and store results
    - Update knowledge graph with findings
    """
    state["phase"] = "TEST"
    
    if not state["current_action"]:
        state["errors"].append("No action to execute")
        return state
    
    action = state["current_action"]
    tool_name = action["tool"]
    
    add_event(state, "phase_start", {"phase": "TEST", "tool": tool_name})
    logger.info(f"🔧 Field Operator: Executing {tool_name}")
    
    # Check if tool is allowed
    allowed, reason = is_tool_allowed(tool_name, state["epistemic_confidence"])
    if not allowed:
        add_event(state, "tool_blocked", {"tool": tool_name, "reason": reason})
        state["last_result"] = ToolResult(
            status="blocked",
            output=reason,
            duration=0.0,
            sandbox_type="none",
        )
        state["history"].append({
            "role": "user",
            "content": f"Tool '{tool_name}' BLOCKED: {reason}"
        })
        return state
    
    # Execute in E2B sandbox
    start_time = time.time()
    try:
        spec = get_tool_spec(tool_name)
        sandbox_type = spec.sandbox_type if spec else "custom"
        
        result = await execute_in_sandbox(
            action={"tool": tool_name, "args": action["args"]},
            sandbox_type=sandbox_type
        )
        
        duration = time.time() - start_time
        
        # Parse output
        parsed = parse_tool_output(tool_name, result.get("stdout", result.get("output", "")))
        
        state["last_result"] = ToolResult(
            status=result.get("status", "success"),
            output=parsed,
            duration=duration,
            sandbox_type=sandbox_type,
        )
        
        add_event(state, "tool_executed", {
            "tool": tool_name,
            "status": result.get("status"),
            "duration": duration,
        })
        
        # Update knowledge graph with findings
        _update_knowledge_graph(state, tool_name, action["args"], parsed)
        
        # Update epistemic confidence
        _update_epistemic_state(state, parsed)
        
        # Add to history
        output_summary = str(parsed)[:500]
        state["history"].append({
            "role": "user",
            "content": f"Result from {tool_name}: {output_summary}"
        })
        
    except Exception as e:
        logger.error(f"❌ Field operator error: {e}")
        state["last_result"] = ToolResult(
            status="error",
            output=str(e),
            duration=time.time() - start_time,
            sandbox_type="none",
        )
        state["errors"].append(str(e))
    
    return state


def _update_knowledge_graph(
    state: NexusState, 
    tool: str, 
    args: dict, 
    result: dict
) -> None:
    """Update knowledge graph with tool results."""
    # Extract discovered assets
    if "hosts" in result:
        for host in result["hosts"]:
            state["graph_nodes"].append(GraphNode(
                id=f"host:{host}",
                type="asset",
                label=host,
                confidence=0.9,
                properties={"source": tool},
            ))
    
    if "endpoints" in result:
        for endpoint in result["endpoints"]:
            state["graph_nodes"].append(GraphNode(
                id=f"endpoint:{endpoint}",
                type="endpoint",
                label=endpoint,
                confidence=0.8,
                properties={"source": tool},
            ))
    
    if "vulnerabilities" in result:
        for vuln in result["vulnerabilities"]:
            node_id = f"vuln:{vuln.get('id', 'unknown')}"
            state["graph_nodes"].append(GraphNode(
                id=node_id,
                type="vulnerability",
                label=vuln.get("name", "Unknown"),
                confidence=vuln.get("confidence", 0.7),
                properties=vuln,
            ))


def _update_epistemic_state(state: NexusState, result: dict) -> None:
    """Update epistemic confidence based on results."""
    # Count discoveries
    discoveries = (
        len(result.get("hosts", [])) +
        len(result.get("endpoints", [])) +
        len(result.get("technologies", [])) +
        len(result.get("vulnerabilities", []))
    )
    
    # Increase confidence based on discoveries
    if discoveries > 0:
        confidence_gain = min(0.1 * discoveries, 0.3)
        state["epistemic_confidence"] = min(1.0, state["epistemic_confidence"] + confidence_gain)
        
        # Check mode shift
        if state["epistemic_confidence"] >= 0.6 and state["epistemic_mode"] == "search":
            state["epistemic_mode"] = "balanced"
            add_event(state, "mode_shift", {"new_mode": "balanced"})
        elif state["epistemic_confidence"] >= 0.8 and state["epistemic_mode"] == "balanced":
            state["epistemic_mode"] = "exploitation"
            add_event(state, "mode_shift", {"new_mode": "exploitation"})


# ============================================================================
# ADVERSARIAL JUDGE NODE (VALIDATE)
# ============================================================================

async def adversarial_judge_node(state: NexusState) -> NexusState:
    """
    Adversarial Judge: VALIDATE phase.
    
    Responsibilities:
    - Conduct RED/BLUE/JUDGE debate on high-risk actions
    - Validate results against expectations
    - Decide whether to continue, backtrack, or complete
    """
    state["phase"] = "VALIDATE"
    
    add_event(state, "phase_start", {"phase": "VALIDATE"})
    logger.info("⚖️ Adversarial Judge: Validating results")
    
    action = state["current_action"]
    result = state["last_result"]
    
    if not action or not result:
        return state
    
    # Check if debate is needed (high-risk tools)
    risk_score = get_tool_risk(action["tool"])
    
    if risk_score > 5.0:
        # Conduct RED/BLUE/JUDGE debate
        debate = await _conduct_debate(state, action, result)
        state["debate_result"] = debate
        
        add_event(state, "debate_complete", {
            "approved": debate["approved"],
            "risk_score": risk_score,
        })
        
        if not debate["approved"]:
            state["backtrack_count"] += 1
            state["backtrack_reason"] = debate["judge_decision"]
    else:
        # Auto-approve low-risk actions
        state["debate_result"] = DebateResult(
            approved=True,
            red_argument="Low risk, proceed",
            blue_argument="No concerns",
            judge_decision="Approved",
            modifications=[],
            risk_score=risk_score,
        )
    
    # Check for mission completion
    if action["tool"] == "finish_mission" or _should_complete(state):
        state["phase"] = "COMPLETE"
        add_event(state, "mission_complete", {
            "iterations": state["iteration"],
            "confidence": state["epistemic_confidence"],
        })
    
    return state


async def _conduct_debate(
    state: NexusState, 
    action: ActionProposal, 
    result: ToolResult
) -> DebateResult:
    """Conduct adversarial swarm debate."""
    logger.info(f"🎭 Conducting debate for {action['tool']}")
    
    debate_prompt = f"""You are simulating an ADVERSARIAL SWARM PROTOCOL debate.

ACTION: {action['tool']} with args {action['args']}
RESULT: {str(result['output'])[:500]}

Provide responses from THREE personas:

1. RED (Attacker): Argue for aggressive exploitation
2. BLUE (Defender): Identify risks and defenses
3. JUDGE (Strategist): Synthesize a safe path forward

Respond in JSON:
{{
  "red": "RED's argument...",
  "blue": "BLUE's argument...",
  "judge": "JUDGE's decision...",
  "approved": true/false,
  "modifications": ["mod1", "mod2"]
}}"""

    try:
        response = await get_json_completion(
            model_type="reasoning",
            messages=[{"role": "user", "content": debate_prompt}],
            temperature=0.7,
        )
        
        if response:
            return DebateResult(
                approved=response.get("approved", True),
                red_argument=response.get("red", ""),
                blue_argument=response.get("blue", ""),
                judge_decision=response.get("judge", ""),
                modifications=response.get("modifications", []),
                risk_score=get_tool_risk(action["tool"]),
            )
    except Exception as e:
        logger.error(f"❌ Debate error: {e}")
    
    # Default: approve with caution
    return DebateResult(
        approved=True,
        red_argument="Auto-approved",
        blue_argument="Proceed with caution",
        judge_decision="Approved by default",
        modifications=[],
        risk_score=get_tool_risk(action["tool"]),
    )


def _should_complete(state: NexusState) -> bool:
    """Check if mission should complete."""
    # Complete if max iterations reached
    if state["iteration"] >= state["max_iterations"]:
        return True
    
    # Complete if confidence is very high and attacks found
    if state["epistemic_confidence"] >= 0.9:
        vuln_count = sum(1 for n in state["graph_nodes"] if n["type"] == "vulnerability")
        if vuln_count > 0:
            return True
    
    return False


# ============================================================================
# ROUTING FUNCTIONS
# ============================================================================

def should_validate(state: NexusState) -> str:
    """Determine if validation is needed after TEST phase."""
    if state["last_result"] and state["last_result"].get("status") == "success":
        return "validate"
    return "continue"


def validation_result(state: NexusState) -> str:
    """Determine next step after VALIDATE phase."""
    if state["phase"] == "COMPLETE":
        return "complete"
    
    debate = state.get("debate_result")
    if debate and not debate.get("approved"):
        return "backtrack"
    
    return "continue"


def should_continue(state: NexusState) -> str:
    """Determine if mission should continue."""
    if state["phase"] == "COMPLETE":
        return "complete"
    if state["backtrack_count"] > 5:
        return "complete"  # Too many backtracks
    return "continue"
