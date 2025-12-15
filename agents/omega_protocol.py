#!/usr/bin/env python3
"""
AEGIS OMEGA PROTOCOL - Main Integration Module
================================================

Integrates all Omega Protocol components:
- Graph-Native KTV Loop (Knowledge Graph mapping)
- Adversarial Swarm Protocol (RED/BLUE/JUDGE debate)
- Epistemic Priority System (Confidence-based mode shifting)
- Virtual Sandbox (Pre-compute and atomic verification)
- Report Generation (PDF/JSON/HTML exports)

This module provides the unified interface for SOTA agent execution.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# Import Omega Protocol components
from agents.knowledge_graph import (
    KnowledgeGraph, get_knowledge_graph,
    NodeType, EdgeType, GraphNode, GraphEdge, AttackPath
)
from agents.adversarial_swarm import (
    AdversarialSwarm, get_adversarial_swarm,
    DebateResult, SwarmPersona
)
from agents.epistemic_priority import (
    EpistemicPriorityManager, get_epistemic_manager,
    EpistemicMode, KnowledgeCategory
)
from agents.virtual_sandbox import (
    VirtualSandbox, get_virtual_sandbox,
    VerificationResult, VerificationStatus
)
from utils.report_generator import (
    ReportGenerator, get_report_generator,
    ReportData, ReportFormat, VulnerabilityFinding
)

logger = logging.getLogger(__name__)


@dataclass
class OmegaState:
    """Current state of the Omega Protocol execution"""
    phase: str = "INITIALIZATION"
    graph_nodes: int = 0
    graph_edges: int = 0
    epistemic_confidence: float = 0.0
    epistemic_mode: str = "search"
    debates_conducted: int = 0
    verifications_passed: int = 0
    verifications_failed: int = 0
    attack_paths_found: int = 0
    attack_paths_validated: int = 0


class OmegaProtocol:
    """
    AEGIS OMEGA PROTOCOL - Unified Neuro-Symbolic Swarm System.
    
    Core Components:
    1. GRAPH-NATIVE KTV LOOP: Map reasoning to Knowledge Graph
       - Nodes: Assets, Technologies, Credentials
       - Edges: Probabilistic attack paths
       
    2. ADVERSARIAL SWARM: Internal debate before risky actions
       - RED: Aggressive exploit proposals
       - BLUE: Defense analysis
       - JUDGE: Stealth synthesis
       
    3. EPISTEMIC PRIORITY: Confidence-based mode shifting
       - < 60% confidence: Disable exploitation, focus on recon
       - Mode shift to "Epistemic Search"
       
    4. VIRTUAL SANDBOX: Safe execution with verification
       - Pre-compute expected responses
       - Halt on >20% deviation
       - Dependency lock
       
    5. REPORTING: Multi-format export (PDF, JSON, HTML)
    """
    
    def __init__(self, ai_core=None, scanner=None):
        """
        Initialize the Omega Protocol.
        
        Args:
            ai_core: Enhanced AI core for LLM operations
            scanner: Scanner for executing actions
        """
        self.ai_core = ai_core
        self.scanner = scanner
        
        # Initialize Omega Protocol components
        self.knowledge_graph = get_knowledge_graph()
        self.adversarial_swarm = get_adversarial_swarm(ai_core)
        self.epistemic_manager = get_epistemic_manager()
        self.virtual_sandbox = get_virtual_sandbox()
        self.report_generator = get_report_generator()
        
        # State tracking
        self.state = OmegaState()
        self._action_history: List[Dict[str, Any]] = []
        self._findings: List[Dict[str, Any]] = []
        
        logger.info("🌐 OMEGA PROTOCOL INITIALIZED")
        logger.info("="*80)
        logger.info("Components active:")
        logger.info("  📊 Knowledge Graph (Graph-Native KTV)")
        logger.info("  🎭 Adversarial Swarm (RED/BLUE/JUDGE)")
        logger.info("  🧭 Epistemic Priority (Confidence Gating)")
        logger.info("  🔒 Virtual Sandbox (Pre-Compute Verification)")
        logger.info("  📄 Report Generator (PDF/JSON/HTML)")
        logger.info("="*80)
    
    async def execute_action(self, action: Dict[str, Any], 
                              context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute an action through the Omega Protocol pipeline.
        
        Pipeline:
        1. Epistemic Check: Is tool allowed given current confidence?
        2. Swarm Debate: If high-risk, conduct RED/BLUE/JUDGE debate
        3. Pre-Compute: Predict expected response
        4. Execute: Run the action
        5. Verify: Check response against prediction
        6. Update: Add findings to Knowledge Graph
        
        Args:
            action: The action to execute (tool + args)
            context: Additional context
            
        Returns:
            Execution result with Omega Protocol metadata
        """
        tool = action.get("tool", "unknown")
        result = {
            "tool": tool,
            "omega_protocol": {
                "epistemic_allowed": False,
                "debate_conducted": False,
                "verification_status": None,
                "graph_updated": False
            },
            "status": "pending",
            "data": None
        }
        
        # Phase 1: Epistemic Check
        self.state.phase = "EPISTEMIC_CHECK"
        allowed, reason = self.epistemic_manager.is_tool_allowed(tool)
        result["omega_protocol"]["epistemic_allowed"] = allowed
        result["omega_protocol"]["epistemic_reason"] = reason
        
        if not allowed:
            logger.warning(f"⛔ EPISTEMIC LOCK: {reason}")
            result["status"] = "blocked"
            result["error"] = reason
            
            # Provide recommendations for information gain
            recommendations = self.epistemic_manager.get_recommended_actions()
            result["omega_protocol"]["recommendations"] = recommendations[:5]
            
            return result
        
        # Phase 2: Adversarial Swarm Debate (for high-risk actions)
        self.state.phase = "SWARM_DEBATE"
        if await self.adversarial_swarm.should_debate(action):
            logger.info(f"🎭 High-risk action detected: {tool}")
            
            debate_result = await self.adversarial_swarm.conduct_debate(action, context)
            result["omega_protocol"]["debate_conducted"] = True
            result["omega_protocol"]["debate"] = {
                "approved": debate_result.approved,
                "risk_score": debate_result.risk_score,
                "modifications": debate_result.modifications,
                "reasoning": debate_result.reasoning[:200]
            }
            
            self.state.debates_conducted += 1
            
            if not debate_result.approved:
                logger.warning(f"⛔ SWARM REJECTED: {debate_result.reasoning}")
                result["status"] = "rejected_by_swarm"
                result["error"] = debate_result.reasoning
                return result
            
            # Use modified action from judge
            action = debate_result.final_action
        
        # Phase 3: Pre-Compute Expected Response
        self.state.phase = "PRE_COMPUTE"
        prediction = self.virtual_sandbox.predict_response(action, context)
        result["omega_protocol"]["prediction"] = {
            "expected_status": prediction.expected_status_code,
            "expected_patterns": prediction.expected_content_patterns[:3]
        }
        
        # Phase 4: Execute Action
        self.state.phase = "EXECUTION"
        try:
            if self.scanner:
                execution_result = await self.scanner.execute_action(action)
            else:
                # Fallback for testing without scanner
                execution_result = {"status": "success", "simulated": True}
            
            result["data"] = execution_result
            result["status"] = "executed"
            
        except Exception as e:
            logger.error(f"Execution error: {e}")
            result["status"] = "error"
            result["error"] = str(e)
            return result
        
        # Phase 5: Atomic Verification
        self.state.phase = "VERIFICATION"
        verification = self.virtual_sandbox.verify_response(prediction, execution_result)
        result["omega_protocol"]["verification_status"] = verification.status.value
        result["omega_protocol"]["deviation_score"] = verification.deviation_score
        
        if verification.status == VerificationStatus.PASSED:
            self.state.verifications_passed += 1
        else:
            self.state.verifications_failed += 1
        
        if verification.should_halt:
            logger.warning(f"⚠️ VERIFICATION HALT: {verification.reasoning}")
            result["omega_protocol"]["halt_reason"] = verification.reasoning
            
            if verification.honeypot_indicators:
                result["omega_protocol"]["honeypot_warning"] = verification.honeypot_indicators
        
        # Phase 6: Update Knowledge Graph
        self.state.phase = "GRAPH_UPDATE"
        await self._update_knowledge_graph(action, execution_result, verification)
        result["omega_protocol"]["graph_updated"] = True
        
        # Store in history
        self._action_history.append({
            "action": action,
            "result": result,
            "timestamp": datetime.now().isoformat()
        })
        
        return result
    
    async def _update_knowledge_graph(self, action: Dict[str, Any],
                                       result: Dict[str, Any],
                                       verification: VerificationResult) -> None:
        """Update the knowledge graph with action results"""
        tool = action.get("tool", "unknown")
        args = action.get("args", {})
        
        # Add endpoint node if URL-based
        url = args.get("url", args.get("target", ""))
        if url:
            endpoint_node = self.knowledge_graph.add_node(
                node_type=NodeType.ENDPOINT,
                label=url[:50],
                description=f"Endpoint discovered via {tool}",
                confidence=0.9 if verification.status == VerificationStatus.PASSED else 0.5,
                properties={"url": url, "tool": tool}
            )
            self.state.graph_nodes = self.knowledge_graph.get_graph_state()["total_nodes"]
        
        # Add technology findings
        if result.get("status") == "success":
            headers = result.get("data", {}).get("headers", {})
            
            # Detect technologies from headers
            server = headers.get("server", "")
            if server:
                tech_node = self.knowledge_graph.add_node(
                    node_type=NodeType.TECHNOLOGY,
                    label=server[:30],
                    description=f"Server technology: {server}",
                    confidence=0.95,
                    properties={"header": "server", "value": server}
                )
                
                # Update epistemic knowledge
                self.epistemic_manager.add_knowledge(
                    category=KnowledgeCategory.TECHNOLOGY_STACK,
                    key="server",
                    value=server,
                    confidence=0.95,
                    source=tool
                )
            
            x_powered = headers.get("x-powered-by", "")
            if x_powered:
                self.epistemic_manager.add_knowledge(
                    category=KnowledgeCategory.TECHNOLOGY_STACK,
                    key="x-powered-by",
                    value=x_powered,
                    confidence=0.9,
                    source=tool
                )
        
        # Update state
        graph_state = self.knowledge_graph.get_graph_state()
        self.state.graph_nodes = graph_state["total_nodes"]
        self.state.graph_edges = graph_state["total_edges"]
        self.state.attack_paths_found = graph_state["attack_paths_found"]
        
        epistemic_state = self.epistemic_manager.get_state_summary()
        self.state.epistemic_confidence = epistemic_state["overall_confidence"]
        self.state.epistemic_mode = epistemic_state["mode"]
    
    async def run_epistemic_search(self, target: str, 
                                    max_actions: int = 20) -> Dict[str, Any]:
        """
        Run epistemic search mode to gather information.
        
        This mode focuses on maximizing information gain rather than
        finding vulnerabilities. Used when confidence is low.
        
        Args:
            target: Target URL
            max_actions: Maximum reconnaissance actions
            
        Returns:
            Search results with updated confidence
        """
        logger.info(f"\n{'='*80}")
        logger.info("🔍 EPISTEMIC SEARCH MODE ACTIVATED")
        logger.info(f"Target: {target}")
        logger.info(f"Goal: Maximize Information Gain until confidence >= 60%")
        logger.info(f"{'='*80}\n")
        
        results = {
            "target": target,
            "actions_taken": 0,
            "knowledge_gained": [],
            "final_confidence": 0.0,
            "mode_at_end": "search"
        }
        
        # Get recommended actions
        actions_taken = 0
        
        while actions_taken < max_actions:
            # Check current state
            state = self.epistemic_manager.get_state_summary()
            
            if state["mode"] != "epistemic_search":
                logger.info(f"✅ Confidence threshold reached: {state['overall_confidence']:.0%}")
                break
            
            # Get next recommended action
            recommendations = self.epistemic_manager.get_recommended_actions()
            
            if not recommendations:
                logger.info("No more recommended actions")
                break
            
            rec = recommendations[0]
            action = rec["action"]
            action["args"] = {"url": target}
            
            logger.info(f"\n📊 Epistemic Search [{actions_taken + 1}/{max_actions}]")
            logger.info(f"   Reason: {action.get('reason', 'Information gain')}")
            logger.info(f"   Category: {rec.get('category', 'unknown')}")
            logger.info(f"   Est. Info Gain: {rec.get('estimated_info_gain', 0):.2f}")
            
            # Execute action through Omega pipeline
            result = await self.execute_action(action, {"target": target})
            
            actions_taken += 1
            results["actions_taken"] = actions_taken
            
            if result.get("status") == "executed":
                results["knowledge_gained"].append({
                    "tool": action.get("tool"),
                    "category": rec.get("category"),
                    "confidence_before": rec.get("current_confidence"),
                    "confidence_after": self.epistemic_manager.get_state_summary()["overall_confidence"]
                })
            
            # Small delay
            await asyncio.sleep(0.5)
        
        # Final state
        final_state = self.epistemic_manager.get_state_summary()
        results["final_confidence"] = final_state["overall_confidence"]
        results["mode_at_end"] = final_state["mode"]
        
        logger.info(f"\n{'='*80}")
        logger.info("📊 EPISTEMIC SEARCH COMPLETE")
        logger.info(f"   Actions taken: {actions_taken}")
        logger.info(f"   Final confidence: {results['final_confidence']:.0%}")
        logger.info(f"   Mode: {results['mode_at_end']}")
        logger.info(f"{'='*80}\n")
        
        return results
    
    async def execute_omega_mission(self, target: str, rules: str = "",
                                     max_iterations: int = 10) -> Dict[str, Any]:
        """
        Execute a complete Omega Protocol mission.
        
        Phases:
        1. Epistemic Search (if confidence < 60%)
        2. Graph-based Attack Path Discovery
        3. Swarm-validated Exploitation
        4. Report Generation
        
        Args:
            target: Target URL
            rules: Mission rules and policies
            max_iterations: Maximum KTV loop iterations
            
        Returns:
            Complete mission results
        """
        logger.info("\n" + "="*80)
        logger.info("🌐 AEGIS OMEGA PROTOCOL - MISSION START")
        logger.info("="*80)
        logger.info(f"Target: {target}")
        logger.info(f"Rules: {rules or 'Standard penetration testing'}")
        logger.info("="*80 + "\n")
        
        mission_start = datetime.now()
        
        # Initialize mission state
        self.knowledge_graph.clear()
        self.epistemic_manager.reset()
        self._findings = []
        
        results = {
            "target": target,
            "status": "in_progress",
            "phases": {},
            "findings": [],
            "report_paths": {}
        }
        
        # Phase 1: Initial reconnaissance to build confidence
        logger.info("\n📋 PHASE 1: Epistemic Search")
        search_results = await self.run_epistemic_search(target, max_actions=10)
        results["phases"]["epistemic_search"] = search_results
        
        # Phase 2: Build attack graph
        logger.info("\n📋 PHASE 2: Attack Graph Construction")
        attack_paths = self.knowledge_graph.find_attack_paths()
        results["phases"]["attack_graph"] = {
            "nodes": self.knowledge_graph.get_graph_state()["total_nodes"],
            "edges": self.knowledge_graph.get_graph_state()["total_edges"],
            "paths_found": len(attack_paths)
        }
        self.state.attack_paths_found = len(attack_paths)
        
        # Phase 3: Execute KTV loop with swarm validation
        if self.epistemic_manager.get_state_summary()["mode"] != "epistemic_search":
            logger.info("\n📋 PHASE 3: Exploitation (Swarm-Validated)")
            
            # This would integrate with the existing KTV loop
            # For now, just log the capability
            logger.info("   Exploitation enabled - confidence threshold met")
            
            results["phases"]["exploitation"] = {
                "enabled": True,
                "confidence": self.epistemic_manager.get_state_summary()["overall_confidence"]
            }
        else:
            logger.info("\n📋 PHASE 3: Exploitation (SKIPPED - Low Confidence)")
            results["phases"]["exploitation"] = {
                "enabled": False,
                "reason": "Epistemic confidence below threshold"
            }
        
        # Phase 4: Generate reports
        logger.info("\n📋 PHASE 4: Report Generation")
        
        mission_end = datetime.now()
        duration = (mission_end - mission_start).total_seconds()
        
        # Create report data
        scan_results = {
            "target": target,
            "duration_seconds": duration,
            "vulnerabilities": self._findings,
            "ktv_loop": {
                "confirmed_vulnerabilities": []
            },
            "scope": rules
        }
        
        report_data = self.report_generator.create_report_from_scan(scan_results)
        report_paths = self.report_generator.generate_report(
            report_data,
            formats=[ReportFormat.JSON, ReportFormat.HTML]
        )
        
        results["report_paths"] = {fmt: str(path) for fmt, path in report_paths.items()}
        results["status"] = "complete"
        results["duration_seconds"] = duration
        
        # Print summary
        logger.info("\n" + "="*80)
        logger.info("✅ OMEGA PROTOCOL MISSION COMPLETE")
        logger.info("="*80)
        logger.info(f"Duration: {duration:.1f}s")
        logger.info(f"Graph: {self.state.graph_nodes} nodes, {self.state.graph_edges} edges")
        logger.info(f"Attack Paths: {self.state.attack_paths_found}")
        logger.info(f"Debates: {self.state.debates_conducted}")
        logger.info(f"Verifications: {self.state.verifications_passed} passed, {self.state.verifications_failed} failed")
        logger.info(f"Final Confidence: {self.state.epistemic_confidence:.0%}")
        
        for fmt, path in report_paths.items():
            logger.info(f"Report ({fmt}): {path}")
        
        logger.info("="*80 + "\n")
        
        return results
    
    def get_omega_state(self) -> Dict[str, Any]:
        """Get current Omega Protocol state for UI display"""
        return {
            "phase": self.state.phase,
            "graph": {
                "nodes": self.state.graph_nodes,
                "edges": self.state.graph_edges,
                "attack_paths": self.state.attack_paths_found
            },
            "epistemic": {
                "confidence": self.state.epistemic_confidence,
                "mode": self.state.epistemic_mode
            },
            "swarm": {
                "debates": self.state.debates_conducted
            },
            "sandbox": {
                "verifications_passed": self.state.verifications_passed,
                "verifications_failed": self.state.verifications_failed
            }
        }
    
    def format_for_llm(self) -> str:
        """Format Omega Protocol state for LLM consumption in prompts"""
        lines = [
            "<think>",
            self.knowledge_graph.format_for_llm(),
            "",
            self.epistemic_manager.format_for_llm(),
            "",
            f"[SWARM] Debates conducted: {self.state.debates_conducted}",
            f"[SANDBOX] Pass: {self.state.verifications_passed}, Fail: {self.state.verifications_failed}",
            "</think>"
        ]
        return "\n".join(lines)


# Global instance
_omega_protocol: Optional[OmegaProtocol] = None


def get_omega_protocol(ai_core=None, scanner=None) -> OmegaProtocol:
    """Get the global Omega Protocol instance"""
    global _omega_protocol
    if _omega_protocol is None:
        _omega_protocol = OmegaProtocol(ai_core=ai_core, scanner=scanner)
    return _omega_protocol
