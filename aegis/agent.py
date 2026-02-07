# aegis/agent.py
"""
AegisOmega - Enhanced Hybrid Autonomous Agent
==============================================

Combines fast Think-Act-Observe loop with Omega Protocol intelligence:
- OODA Loop: Observe → Orient → Decide → Act
- Epistemic Priority: Confidence-based mode shifting
- Adversarial Swarm: RED/BLUE/JUDGE debate on risky actions
- Knowledge Graph: Attack path mapping
- Virtual Sandbox: Pre-compute + verify responses
- Hive Mind: Multi-session knowledge sharing
"""

import asyncio
import json
import logging
import time
import uuid
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

from aegis.llm import get_llm
from aegis.state import get_app_state

logger = logging.getLogger(__name__)


# Constants
RECON_TOOLS = {
    "nmap_scan", "subdomain_enumeration", "http_request", 
    "directory_bruteforce", "port_scanning", "url_discovery"
}
EXPLOIT_TOOLS = {"run_sqlmap", "xss_test", "vulnerability_scan"}
ALL_TOOLS = RECON_TOOLS | EXPLOIT_TOOLS | {"finish_mission"}


@dataclass
class MissionContext:
    """Context passed through OODA loop"""
    target: str
    rules: str
    iteration: int = 0
    confidence: float = 0.0
    mode: str = "search"
    knowledge_graph_summary: str = ""
    hive_knowledge: List[Dict] = field(default_factory=list)
    history: List[Dict] = field(default_factory=list)


class AegisOmega:
    """
    OODA Loop Enhanced Agent
    
    The most intelligent, adaptive, and fast pentesting agent.
    Merges simple LLM reasoning with sophisticated Omega Protocol components.
    """
    
    def __init__(self):
        # Core components
        self.llm = get_llm()
        self.state = get_app_state()
        self._tool_manager = None
        
        # Omega Protocol components (lazy init)
        self._graph = None
        self._epistemic = None
        self._swarm = None
        self._sandbox = None
        self._hive = None
        
        # Mission state
        self.running = False
        self.current_mission_id = None
        self.mission_start_time = None
        
        logger.info("🚀 AegisOmega initialized")
    
    # =========================================================================
    # LAZY LOADERS (avoid circular imports)
    # =========================================================================
    
    def _get_tool_manager(self):
        if not self._tool_manager:
            from aegis.tools.manager import get_tool_manager
            self._tool_manager = get_tool_manager()
        return self._tool_manager
    
    def _get_graph(self):
        if not self._graph:
            from aegis.knowledge_graph import get_knowledge_graph
            self._graph = get_knowledge_graph()
        return self._graph
    
    def _get_epistemic(self):
        if not self._epistemic:
            from aegis.epistemic_priority import get_epistemic_manager
            self._epistemic = get_epistemic_manager()
        return self._epistemic
    
    def _get_swarm(self):
        if not self._swarm:
            from aegis.adversarial_swarm import get_adversarial_swarm
            self._swarm = get_adversarial_swarm()
        return self._swarm
    
    def _get_sandbox(self):
        if not self._sandbox:
            from aegis.virtual_sandbox import get_virtual_sandbox
            self._sandbox = get_virtual_sandbox()
        return self._sandbox
    
    def _get_hive(self):
        if not self._hive:
            from aegis.hive_mind import get_hive_mind
            self._hive = get_hive_mind()
        return self._hive
    
    # =========================================================================
    # PUBLIC INTERFACE
    # =========================================================================
    
    async def start_mission(self, target: str, rules: str = "") -> str:
        """Start an autonomous mission."""
        self.current_mission_id = str(uuid.uuid4())
        self.running = True
        self.mission_start_time = time.time()
        
        logger.info(f"🎯 AegisOmega Mission {self.current_mission_id[:8]} started: {target}")
        
        # Start OODA loop in background
        asyncio.create_task(self._ooda_loop(target, rules))
        
        return self.current_mission_id
    
    async def stop_mission(self):
        """Stop current mission."""
        self.running = False
        duration = time.time() - (self.mission_start_time or time.time())
        logger.info(f"🛑 Mission stopped after {duration:.1f}s")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current agent status."""
        epistemic_state = self._get_epistemic().get_state_summary()
        graph_state = self._get_graph().get_graph_state()
        
        return {
            "running": self.running,
            "mission_id": self.current_mission_id,
            "confidence": epistemic_state["overall_confidence"],
            "mode": epistemic_state["mode"],
            "graph_nodes": graph_state["total_nodes"],
            "attack_paths": graph_state["attack_paths_found"],
        }
    
    # =========================================================================
    # OODA LOOP
    # =========================================================================
    
    async def _ooda_loop(self, target: str, rules: str):
        """
        Main OODA Loop:
        - OBSERVE: Get tool result, query hive, update graph
        - ORIENT: Calculate confidence, determine mode
        - DECIDE: LLM proposes action, swarm debates if risky
        - ACT: Execute, verify, share discoveries
        """
        await self._broadcast("mission_start", {"target": target})
        
        # Initialize context
        ctx = MissionContext(target=target, rules=rules)
        ctx.history = [
            {"role": "system", "content": self._build_system_prompt(ctx)},
            {"role": "user", "content": f"Begin reconnaissance on {target}"}
        ]
        
        # Start hive mind
        try:
            await self._get_hive().start()
        except Exception as e:
            logger.warning(f"Hive Mind not available: {e}")
        
        max_iterations = 50
        
        while self.running and ctx.iteration < max_iterations:
            ctx.iteration += 1
            
            # ─────────────────────────────────────────────────────────────────
            # 1. OBSERVE - Gather context
            # ─────────────────────────────────────────────────────────────────
            await self._broadcast("phase", {"name": "OBSERVE", "iteration": ctx.iteration})
            
            # Query hive for shared knowledge
            try:
                hive_knowledge = await self._get_hive().backend.query(target_domain=target)
                ctx.hive_knowledge = [k.to_dict() for k in hive_knowledge[:5]]
                if ctx.hive_knowledge:
                    logger.info(f"🐝 Hive: Found {len(ctx.hive_knowledge)} shared insights")
            except Exception:
                pass
            
            # Get graph summary
            ctx.knowledge_graph_summary = self._get_graph().format_for_llm()
            
            # ─────────────────────────────────────────────────────────────────
            # 2. ORIENT - Assess situation
            # ─────────────────────────────────────────────────────────────────
            await self._broadcast("phase", {"name": "ORIENT"})
            
            epistemic_state = self._get_epistemic().get_state_summary()
            ctx.confidence = epistemic_state["overall_confidence"]
            ctx.mode = epistemic_state["mode"]
            
            # Determine allowed tools based on confidence
            if ctx.mode == "epistemic_search":
                allowed_tools = RECON_TOOLS | {"finish_mission"}
                await self._broadcast("info", {"message": f"🔍 SEARCH mode ({ctx.confidence:.0%} confidence)"})
            else:
                allowed_tools = ALL_TOOLS
                await self._broadcast("info", {"message": f"⚔️ EXPLOIT mode ({ctx.confidence:.0%} confidence)"})
            
            # ─────────────────────────────────────────────────────────────────
            # 3. DECIDE - Choose action
            # ─────────────────────────────────────────────────────────────────
            await self._broadcast("phase", {"name": "DECIDE"})
            
            # Update system prompt with current context
            ctx.history[0]["content"] = self._build_system_prompt(ctx, allowed_tools)
            
            # Get LLM decision
            response = await self.llm.get_json(ctx.history, model_type="reasoning")
            
            if not response:
                await self._broadcast("error", {"message": "LLM returned empty response"})
                break
            
            thought = response.get("thought", "")
            tool_call = response.get("tool_call")
            
            await self._broadcast("thought", {"content": thought})
            ctx.history.append({"role": "assistant", "content": json.dumps(response)})
            
            if not tool_call:
                await self._broadcast("info", {"message": "Agent paused - no action needed"})
                break
            
            tool_name = tool_call.get("tool")
            tool_args = tool_call.get("args", {})
            
            # Check if tool is allowed
            if tool_name not in allowed_tools:
                await self._broadcast("blocked", {
                    "tool": tool_name,
                    "reason": f"Tool blocked in {ctx.mode} mode"
                })
                ctx.history.append({
                    "role": "user",
                    "content": f"Tool '{tool_name}' blocked: Insufficient confidence. Focus on reconnaissance."
                })
                continue
            
            # Swarm debate for risky tools
            action = {"tool": tool_name, "args": tool_args}
            
            if await self._get_swarm().should_debate(action):
                await self._broadcast("debate_start", {"tool": tool_name})
                
                debate = await self._get_swarm().conduct_debate(action, {"target": target})
                
                await self._broadcast("debate_result", {
                    "approved": debate.approved,
                    "risk_score": debate.risk_score,
                    "modifications": debate.modifications
                })
                
                if not debate.approved:
                    ctx.history.append({
                        "role": "user",
                        "content": f"Swarm REJECTED: {debate.reasoning}. Choose safer approach."
                    })
                    continue
                
                # Use modified action from swarm
                action = debate.final_action
                tool_name = action.get("tool")
                tool_args = action.get("args", {})
            
            # Pre-compute expected response
            try:
                prediction = self._get_sandbox().predict_response(action, {"target": target})
                await self._broadcast("prediction", {
                    "expected_status": prediction.expected_status_code
                })
            except Exception:
                prediction = None
            
            # ─────────────────────────────────────────────────────────────────
            # 4. ACT - Execute and verify
            # ─────────────────────────────────────────────────────────────────
            await self._broadcast("phase", {"name": "ACT"})
            await self._broadcast("action", {"tool": tool_name, "args": tool_args})
            await self.state.update_tool_status(tool_name, "running")
            
            try:
                result = await self._get_tool_manager().execute(tool_name, tool_args)
                await self.state.update_tool_status(tool_name, "completed", output=str(result)[:500])
                
                # Verify response
                if prediction:
                    verification = self._get_sandbox().verify_response(prediction, result)
                    if verification.honeypot_indicators:
                        await self._broadcast("warning", {
                            "type": "honeypot",
                            "indicators": verification.honeypot_indicators
                        })
                        logger.warning(f"🍯 Honeypot detected: {verification.honeypot_indicators}")
                
            except Exception as e:
                result = {"status": "error", "error": str(e)}
                await self.state.update_tool_status(tool_name, "failed", output=str(e))
            
            # Update knowledge graph
            self._update_graph(tool_name, tool_args, result)
            
            # Update epistemic knowledge
            self._update_epistemic(tool_name, result)
            
            # Share with hive
            await self._share_with_hive(target, tool_name, result)
            
            # Observation for next loop
            observation = f"Tool '{tool_name}' result: {json.dumps(result)[:2000]}"
            ctx.history.append({"role": "user", "content": observation})
            
            await self._broadcast("observation", {"tool": tool_name, "result": result})
            
            # Check for mission completion
            if tool_name == "finish_mission":
                break
        
        # Mission complete
        duration = time.time() - self.mission_start_time
        final_state = self.get_status()
        
        await self._broadcast("mission_end", {
            "iterations": ctx.iteration,
            "duration": duration,
            "confidence": ctx.confidence,
            "graph_nodes": final_state["graph_nodes"],
            "attack_paths": final_state["attack_paths"]
        })
        
        self.running = False
        logger.info(f"✅ Mission complete: {ctx.iteration} iterations, {duration:.1f}s")
    
    # =========================================================================
    # HELPER METHODS
    # =========================================================================
    
    def _build_system_prompt(self, ctx: MissionContext, allowed_tools: set = None) -> str:
        """Build dynamic system prompt based on epistemic state."""
        if allowed_tools is None:
            allowed_tools = ALL_TOOLS
        
        tools_str = ", ".join(sorted(allowed_tools))
        
        hive_str = ""
        if ctx.hive_knowledge:
            hive_str = "\n\nHIVE KNOWLEDGE (shared by other agents):\n"
            for k in ctx.hive_knowledge[:3]:
                hive_str += f"- {k.get('knowledge_type')}: {k.get('data', {})}\n"
        
        graph_str = ""
        if ctx.knowledge_graph_summary:
            graph_str = f"\n\nKNOWLEDGE GRAPH:\n{ctx.knowledge_graph_summary}"
        
        return f"""You are AegisOmega, an elite autonomous penetration testing agent.

TARGET: {ctx.target}
RULES: {ctx.rules or "Standard pentest rules apply."}

CURRENT STATE:
- Mode: {ctx.mode.upper()}
- Confidence: {ctx.confidence:.0%}
- Iteration: {ctx.iteration}

ALLOWED TOOLS: {tools_str}
{hive_str}{graph_str}

RESPONSE FORMAT (JSON):
{{
  "thought": "Your analysis of the current situation...",
  "strategy": "High-level approach for this phase",
  "tool_call": {{
    "tool": "tool_name",
    "args": {{"arg1": "value1"}}
  }}
}}

GUIDELINES:
1. In SEARCH mode: Focus on reconnaissance, gather information
2. In EXPLOIT mode: Test vulnerabilities systematically
3. Leverage hive knowledge to avoid redundant work
4. Be precise with tool arguments"""
    
    def _update_graph(self, tool: str, args: Dict, result: Dict):
        """Update knowledge graph with tool results."""
        try:
            from aegis.knowledge_graph import NodeType
            graph = self._get_graph()
            
            url = args.get("url") or args.get("target") or args.get("domain")
            if url:
                graph.add_node(
                    node_type=NodeType.ENDPOINT,
                    label=url[:50],
                    description=f"Discovered via {tool}",
                    confidence=0.9 if result.get("status") == "success" else 0.5,
                    properties={"tool": tool, "args": args}
                )
        except Exception as e:
            logger.debug(f"Graph update failed: {e}")
    
    def _update_epistemic(self, tool: str, result: Dict):
        """Update epistemic knowledge from tool results."""
        try:
            from aegis.epistemic_priority import KnowledgeCategory
            epistemic = self._get_epistemic()
            
            if result.get("status") == "success":
                data = result.get("data", {})
                
                # Extract technology info
                if "headers" in data:
                    server = data["headers"].get("server")
                    if server:
                        epistemic.add_knowledge(
                            category=KnowledgeCategory.TECHNOLOGY_STACK,
                            key="server",
                            value=server,
                            confidence=0.95,
                            source=tool
                        )
        except Exception as e:
            logger.debug(f"Epistemic update failed: {e}")
    
    async def _share_with_hive(self, target: str, tool: str, result: Dict):
        """Share discoveries with the hive."""
        try:
            hive = self._get_hive()
            
            if result.get("vulnerabilities"):
                for vuln in result["vulnerabilities"]:
                    await hive.share_vulnerability(
                        target_domain=target,
                        vuln_type=vuln.get("type", "unknown"),
                        endpoint=vuln.get("url", target),
                        severity=vuln.get("severity", "medium"),
                        confidence=0.8
                    )
        except Exception as e:
            logger.debug(f"Hive share failed: {e}")
    
    async def _broadcast(self, event_type: str, data: Dict[str, Any]):
        """Broadcast event to connected clients."""
        message = {
            "type": event_type,
            "mission_id": self.current_mission_id,
            "timestamp": time.time(),
            "data": data
        }
        await self.state.broadcast_message(message)


# Singleton
_agent = None

def get_agent() -> AegisOmega:
    """Get the global AegisOmega agent instance."""
    global _agent
    if _agent is None:
        _agent = AegisOmega()
    return _agent
