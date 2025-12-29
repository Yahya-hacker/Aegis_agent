"""
OMEGA Protocol - Neuro-Symbolic Swarm Intelligence
Implements the advanced cognitive architecture for Aegis AI

Components:
- Knowledge Graph: Graph-native attack surface mapping
- Adversarial Swarm: RED/BLUE/JUDGE debate before risky actions
- Epistemic Priority: Confidence-based mode shifting
- Virtual Sandbox: Safe execution with verification
"""

import asyncio
import json
import logging
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import networkx as nx

logger = logging.getLogger(__name__)


# ============================================================================
# Epistemic State Management
# ============================================================================

class EpistemicMode(Enum):
    """Epistemic operation modes"""
    SEARCH = "search"      # Information gathering mode
    EXPLOIT = "exploit"    # Active exploitation mode


@dataclass
class EpistemicState:
    """Tracks epistemic state and confidence levels"""
    mode: EpistemicMode = EpistemicMode.SEARCH
    overall_confidence: float = 0.0
    confidence_threshold: float = 60.0  # Minimum confidence to enable exploitation
    
    # Per-domain confidence tracking
    domain_confidence: Dict[str, float] = field(default_factory=dict)
    
    # Confidence factors
    tech_stack_identified: bool = False
    attack_surface_mapped: bool = False
    vulnerabilities_confirmed: bool = False
    
    def calculate_overall_confidence(self) -> float:
        """Calculate overall confidence based on factors"""
        factors = [
            (self.tech_stack_identified, 25.0),
            (self.attack_surface_mapped, 25.0),
            (self.vulnerabilities_confirmed, 30.0),
            (len(self.domain_confidence) > 0, 20.0)
        ]
        
        confidence = sum(weight for condition, weight in factors if condition)
        
        # Add average domain confidence
        if self.domain_confidence:
            avg_domain = sum(self.domain_confidence.values()) / len(self.domain_confidence)
            confidence = (confidence * 0.7) + (avg_domain * 0.3)
        
        self.overall_confidence = min(100.0, confidence)
        return self.overall_confidence
    
    def should_enable_exploitation(self) -> bool:
        """Check if exploitation should be enabled"""
        return self.overall_confidence >= self.confidence_threshold
    
    def update_mode(self) -> EpistemicMode:
        """Update mode based on confidence"""
        self.calculate_overall_confidence()
        
        if self.should_enable_exploitation():
            self.mode = EpistemicMode.EXPLOIT
        else:
            self.mode = EpistemicMode.SEARCH
        
        return self.mode
    
    def get_state_summary(self) -> str:
        """Get formatted state summary"""
        self.calculate_overall_confidence()
        
        summary = f"""[EPISTEMIC STATE] Mode: {self.mode.value.upper()}
[CONFIDENCE] Overall: {self.overall_confidence:.0f}% (threshold: {self.confidence_threshold:.0f}%)
[EXPLOITATION] {'UNLOCKED ✅' if self.should_enable_exploitation() else 'LOCKED 🔒 - Complete reconnaissance first'}

[FACTORS]
- Tech Stack Identified: {'✅' if self.tech_stack_identified else '❌'}
- Attack Surface Mapped: {'✅' if self.attack_surface_mapped else '❌'}
- Vulnerabilities Confirmed: {'✅' if self.vulnerabilities_confirmed else '❌'}
- Domains Analyzed: {len(self.domain_confidence)}
"""
        return summary


# ============================================================================
# Knowledge Graph
# ============================================================================

class NodeType(Enum):
    """Types of nodes in the knowledge graph"""
    ASSET = "asset"           # Web servers, databases, services
    TECHNOLOGY = "technology" # Technologies, frameworks, versions
    CREDENTIAL = "credential" # Usernames, passwords, tokens
    VULNERABILITY = "vulnerability"  # CVEs, weaknesses
    ENDPOINT = "endpoint"     # URLs, API endpoints
    FILE = "file"             # Discovered files
    ACTION = "action"         # Possible actions


class EdgeType(Enum):
    """Types of edges in the knowledge graph"""
    HAS_VULN = "HAS_VULN"           # Asset has vulnerability
    EXPOSES = "EXPOSES"              # Port/service exposes something
    RUNS = "RUNS"                    # Server runs software
    ALLOWS_ACTION = "ALLOWS_ACTION"  # Vulnerability allows action
    LEADS_TO = "LEADS_TO"            # One thing leads to another
    PROTECTED_BY = "PROTECTED_BY"    # Protected by security control
    CONTAINS = "CONTAINS"            # Container relationship
    AUTHENTICATED_BY = "AUTHENTICATED_BY"  # Authentication relationship


@dataclass
class GraphNode:
    """Node in the knowledge graph"""
    id: str
    name: str
    node_type: NodeType
    confidence: float = 0.0
    verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class GraphEdge:
    """Edge in the knowledge graph"""
    source_id: str
    target_id: str
    edge_type: EdgeType
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


class KnowledgeGraph:
    """Graph-native attack surface mapping"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.nodes: Dict[str, GraphNode] = {}
        self.attack_paths: List[Dict[str, Any]] = []
    
    def _generate_node_id(self, name: str, node_type: NodeType) -> str:
        """Generate unique node ID"""
        content = f"{node_type.value}:{name}"
        return hashlib.md5(content.encode()).hexdigest()[:12]
    
    def add_node(
        self,
        name: str,
        node_type: NodeType,
        confidence: float = 0.0,
        verified: bool = False,
        **metadata
    ) -> str:
        """Add a node to the knowledge graph"""
        node_id = self._generate_node_id(name, node_type)
        
        if node_id not in self.nodes:
            node = GraphNode(
                id=node_id,
                name=name,
                node_type=node_type,
                confidence=confidence,
                verified=verified,
                metadata=metadata
            )
            self.nodes[node_id] = node
            self.graph.add_node(
                node_id,
                name=name,
                type=node_type.value,
                confidence=confidence,
                verified=verified,
                **metadata
            )
            logger.info(f"[GRAPH] Added node: {node_type.value}:{name} (conf: {confidence:.0%})")
        else:
            # Update existing node
            existing = self.nodes[node_id]
            existing.confidence = max(existing.confidence, confidence)
            existing.verified = existing.verified or verified
            existing.metadata.update(metadata)
        
        return node_id
    
    def add_edge(
        self,
        source_name: str,
        source_type: NodeType,
        target_name: str,
        target_type: NodeType,
        edge_type: EdgeType,
        confidence: float = 0.0,
        **metadata
    ) -> Tuple[str, str]:
        """Add an edge between nodes"""
        source_id = self.add_node(source_name, source_type)
        target_id = self.add_node(target_name, target_type)
        
        edge = GraphEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            confidence=confidence,
            metadata=metadata
        )
        
        self.graph.add_edge(
            source_id,
            target_id,
            type=edge_type.value,
            confidence=confidence,
            **metadata
        )
        
        logger.info(f"[GRAPH] Added edge: {source_name} --[{edge_type.value}, {confidence:.0%}]--> {target_name}")
        
        return source_id, target_id
    
    def find_attack_paths(
        self,
        source_type: NodeType = None,
        target_type: NodeType = NodeType.VULNERABILITY
    ) -> List[Dict[str, Any]]:
        """Find potential attack paths in the graph"""
        paths = []
        
        # Find all vulnerability nodes
        vuln_nodes = [
            node_id for node_id, data in self.graph.nodes(data=True)
            if data.get('type') == target_type.value
        ]
        
        # Find paths from assets to vulnerabilities
        asset_nodes = [
            node_id for node_id, data in self.graph.nodes(data=True)
            if source_type is None or data.get('type') == source_type.value
        ]
        
        for asset in asset_nodes:
            for vuln in vuln_nodes:
                try:
                    for path in nx.all_simple_paths(self.graph, asset, vuln, cutoff=5):
                        path_data = self._build_path_data(path)
                        if path_data:
                            paths.append(path_data)
                except nx.NetworkXNoPath:
                    continue
        
        self.attack_paths = paths
        return paths
    
    def _build_path_data(self, path: List[str]) -> Optional[Dict[str, Any]]:
        """Build path data structure from node IDs"""
        if len(path) < 2:
            return None
        
        steps = []
        total_confidence = 1.0
        
        for i in range(len(path) - 1):
            source = self.nodes.get(path[i])
            target = self.nodes.get(path[i + 1])
            
            if source and target:
                edge_data = self.graph.get_edge_data(path[i], path[i + 1], default={})
                confidence = edge_data.get('confidence', 0.5)
                total_confidence *= confidence
                
                steps.append({
                    'source': source.name,
                    'source_type': source.node_type.value,
                    'target': target.name,
                    'target_type': target.node_type.value,
                    'relation': edge_data.get('type', 'UNKNOWN'),
                    'confidence': confidence
                })
        
        if not steps:
            return None
        
        return {
            'path': path,
            'steps': steps,
            'total_confidence': total_confidence,
            'length': len(steps)
        }
    
    def get_graph_state(self) -> str:
        """Get formatted graph state"""
        node_count = len(self.nodes)
        edge_count = self.graph.number_of_edges()
        
        # Count by type
        type_counts = {}
        for node in self.nodes.values():
            type_name = node.node_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
        
        type_str = ", ".join(f"{v} {k}s" for k, v in type_counts.items())
        
        return f"[GRAPH STATE] Nodes: {node_count} ({type_str}), Edges: {edge_count}"
    
    def export_graphml(self, filepath: str):
        """Export graph to GraphML format"""
        nx.write_graphml(self.graph, filepath)
        logger.info(f"Graph exported to {filepath}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert graph to dictionary"""
        return {
            'nodes': [
                {
                    'id': n.id,
                    'name': n.name,
                    'type': n.node_type.value,
                    'confidence': n.confidence,
                    'verified': n.verified,
                    'metadata': n.metadata
                }
                for n in self.nodes.values()
            ],
            'edges': [
                {
                    'source': u,
                    'target': v,
                    'type': data.get('type'),
                    'confidence': data.get('confidence', 0)
                }
                for u, v, data in self.graph.edges(data=True)
            ],
            'attack_paths': self.attack_paths
        }


# ============================================================================
# Adversarial Swarm Protocol
# ============================================================================

@dataclass
class SwarmAgent:
    """Individual agent in the adversarial swarm"""
    id: str
    role: str  # "red", "blue", "judge"
    perspective: str
    
    def __post_init__(self):
        self.prompts = {
            "red": """You are the RED agent (Attacker). Your role is to advocate for aggressive attack strategies.
Analyze the proposed action and argue FOR its execution. Consider:
- Maximum impact potential
- Exploitation opportunities
- Speed of compromise
Be aggressive but realistic. Present the strongest case for taking this action.""",

            "blue": """You are the BLUE agent (Defender). Your role is to identify risks and defensive countermeasures.
Analyze the proposed action and present CONCERNS. Consider:
- Detection risks (WAF, IDS, logging)
- Potential for service disruption
- Legal/scope implications
- Stealth alternatives
Be cautious and thorough. Identify what could go wrong.""",

            "judge": """You are the JUDGE agent (Strategist). You synthesize the RED and BLUE perspectives.
After reviewing both arguments:
1. Weigh the potential gains vs risks
2. Consider the mission objectives
3. Propose an OPTIMAL strategy

Your decision should balance aggression with safety. Provide:
- Your verdict (PROCEED, MODIFY, or ABORT)
- The final recommended approach
- Specific modifications if needed"""
        }
    
    def get_system_prompt(self) -> str:
        return self.prompts.get(self.role, "")


class AdversarialSwarm:
    """
    Implements internal debate before risky actions.
    RED (Attacker) vs BLUE (Defender), arbitrated by JUDGE (Strategist)
    """
    
    def __init__(self, risk_threshold: float = 5.0):
        self.risk_threshold = risk_threshold
        self.agents = {
            "red": SwarmAgent(id="red", role="red", perspective="aggressive"),
            "blue": SwarmAgent(id="blue", role="blue", perspective="defensive"),
            "judge": SwarmAgent(id="judge", role="judge", perspective="strategic")
        }
        self.debate_history: List[Dict[str, Any]] = []
    
    def calculate_risk_score(self, action: Dict[str, Any]) -> float:
        """Calculate risk score for an action (0-10)"""
        tool = action.get('tool', '')
        args = action.get('args', {})
        
        # Base risk scores by tool category
        high_risk_tools = {'sqlmap', 'metasploit', 'exploit', 'inject', 'payload'}
        medium_risk_tools = {'nikto', 'dirb', 'gobuster', 'ffuf', 'nuclei'}
        
        base_score = 2.0  # Default low risk
        
        # Check tool name
        tool_lower = tool.lower()
        if any(hr in tool_lower for hr in high_risk_tools):
            base_score = 8.0
        elif any(mr in tool_lower for mr in medium_risk_tools):
            base_score = 5.0
        
        # Modifiers
        if args.get('aggressive') or args.get('force'):
            base_score += 1.5
        if args.get('stealth') or args.get('quiet'):
            base_score -= 1.0
        if args.get('rate_limit') or args.get('delay'):
            base_score -= 0.5
        
        return max(0.0, min(10.0, base_score))
    
    def should_debate(self, action: Dict[str, Any]) -> bool:
        """Check if action should trigger swarm debate"""
        risk_score = self.calculate_risk_score(action)
        return risk_score > self.risk_threshold
    
    async def conduct_debate(
        self,
        action: Dict[str, Any],
        context: str,
        orchestrator = None
    ) -> Dict[str, Any]:
        """
        Conduct adversarial debate about a proposed action
        
        Args:
            action: Proposed action dictionary
            context: Mission context
            orchestrator: LLM orchestrator for AI-powered debate
            
        Returns:
            Debate result with verdict and recommendations
        """
        risk_score = self.calculate_risk_score(action)
        
        logger.info(f"[SWARM DEBATE] Risk score: {risk_score}/10 - Initiating debate...")
        
        # Build debate context
        action_summary = json.dumps(action, indent=2)
        
        debate_prompt = f"""
PROPOSED ACTION:
{action_summary}

MISSION CONTEXT:
{context}

RISK ASSESSMENT: {risk_score}/10
"""
        
        debate_result = {
            "context": f"Evaluating: {action.get('tool', 'unknown')}",
            "risk_score": risk_score,
            "timestamp": datetime.now().isoformat(),
            "red": "",
            "blue": "",
            "judge": "",
            "verdict": "PENDING",
            "recommendation": action
        }
        
        if orchestrator and orchestrator.is_initialized:
            # Use AI for debate
            try:
                # RED agent
                red_response = await orchestrator.call_llm(
                    'vulnerability',  # Use reasoning LLM for debate
                    [
                        {"role": "system", "content": self.agents["red"].get_system_prompt()},
                        {"role": "user", "content": debate_prompt}
                    ],
                    temperature=0.7
                )
                debate_result["red"] = red_response.get('content', '')
                
                # BLUE agent
                blue_response = await orchestrator.call_llm(
                    'vulnerability',
                    [
                        {"role": "system", "content": self.agents["blue"].get_system_prompt()},
                        {"role": "user", "content": debate_prompt}
                    ],
                    temperature=0.7
                )
                debate_result["blue"] = blue_response.get('content', '')
                
                # JUDGE synthesis
                judge_prompt = f"""
{debate_prompt}

RED AGENT ARGUMENT:
{debate_result["red"]}

BLUE AGENT CONCERNS:
{debate_result["blue"]}

Synthesize these perspectives and provide your verdict.
"""
                judge_response = await orchestrator.call_llm(
                    'strategic',  # Use strategic LLM for final decision
                    [
                        {"role": "system", "content": self.agents["judge"].get_system_prompt()},
                        {"role": "user", "content": judge_prompt}
                    ],
                    temperature=0.5
                )
                debate_result["judge"] = judge_response.get('content', '')
                
                # Parse verdict from judge response
                judge_text = debate_result["judge"].upper()
                if "PROCEED" in judge_text:
                    debate_result["verdict"] = "PROCEED"
                elif "ABORT" in judge_text:
                    debate_result["verdict"] = "ABORT"
                elif "MODIFY" in judge_text:
                    debate_result["verdict"] = "MODIFY"
                else:
                    debate_result["verdict"] = "PROCEED"  # Default to proceed
                
            except Exception as e:
                logger.error(f"Swarm debate error: {e}")
                debate_result["error"] = str(e)
                debate_result["verdict"] = "PROCEED"  # Default on error
        else:
            # Heuristic-based debate (no AI)
            if risk_score >= 8.0:
                debate_result["red"] = "High-impact action with significant exploitation potential."
                debate_result["blue"] = f"Risk score {risk_score}/10 - High detection probability."
                debate_result["judge"] = "Recommend stealth modifications or user approval."
                debate_result["verdict"] = "MODIFY"
            elif risk_score >= 5.0:
                debate_result["red"] = "Moderate risk action worth attempting."
                debate_result["blue"] = "Proceed with rate limiting and monitoring."
                debate_result["judge"] = "Proceed with caution."
                debate_result["verdict"] = "PROCEED"
            else:
                debate_result["verdict"] = "PROCEED"
        
        # Log debate summary
        logger.info(f"""
[DEBATE SUMMARY]
  RED: {debate_result['red'][:100]}...
  BLUE: {debate_result['blue'][:100]}...
  JUDGE: {debate_result['judge'][:100]}...
  VERDICT: {debate_result['verdict']}
""")
        
        self.debate_history.append(debate_result)
        return debate_result
    
    def get_formatted_debate(self, debate: Dict[str, Any]) -> str:
        """Format debate for display"""
        return f"""
[DEBATE] 
  RED: {debate.get('red', 'No input')[:150]}
  BLUE: {debate.get('blue', 'No input')[:150]}
  JUDGE: {debate.get('judge', 'No decision')[:150]}
  VERDICT: {debate.get('verdict', 'PENDING')}
"""


# ============================================================================
# Virtual Sandbox
# ============================================================================

@dataclass
class SandboxPrediction:
    """Prediction for sandbox verification"""
    tool: str
    expected_status: int  # Expected HTTP status
    expected_patterns: List[str] = field(default_factory=list)
    max_response_time: float = 10.0  # seconds
    deviation_threshold: float = 0.2  # 20% deviation triggers halt


class VirtualSandbox:
    """
    Safe execution with pre-computation and verification.
    - Pre-compute expected responses before execution
    - Halt on >20% deviation from prediction
    - Dependency lock: no tool installation mid-mission
    """
    
    def __init__(self, deviation_threshold: float = 0.2):
        self.deviation_threshold = deviation_threshold
        self.predictions: Dict[str, SandboxPrediction] = {}
        self.verified_tools: set = set()
        self.locked_dependencies: bool = False
        self.execution_log: List[Dict[str, Any]] = []
    
    def lock_dependencies(self):
        """Lock dependencies - no new tool installation allowed"""
        self.locked_dependencies = True
        logger.info("[SANDBOX] Dependencies locked - no new tool installation allowed")
    
    def unlock_dependencies(self):
        """Unlock dependencies"""
        self.locked_dependencies = False
        logger.info("[SANDBOX] Dependencies unlocked")
    
    def can_install_tool(self, tool_name: str) -> Tuple[bool, str]:
        """Check if a tool can be installed"""
        if self.locked_dependencies:
            return False, "Dependency lock active - cannot install new tools mid-mission"
        return True, "Installation allowed"
    
    def create_prediction(
        self,
        tool: str,
        expected_status: int = 200,
        expected_patterns: List[str] = None,
        max_response_time: float = 10.0
    ) -> SandboxPrediction:
        """Create a prediction for an action"""
        prediction = SandboxPrediction(
            tool=tool,
            expected_status=expected_status,
            expected_patterns=expected_patterns or [],
            max_response_time=max_response_time,
            deviation_threshold=self.deviation_threshold
        )
        
        prediction_id = f"{tool}_{datetime.now().timestamp()}"
        self.predictions[prediction_id] = prediction
        
        logger.info(f"[SANDBOX] Prediction created: {tool} -> status={expected_status}")
        
        return prediction
    
    def verify_execution(
        self,
        prediction: SandboxPrediction,
        actual_status: int,
        actual_response: str,
        actual_time: float
    ) -> Tuple[bool, float, str]:
        """
        Verify execution against prediction
        
        Returns:
            Tuple of (passed, deviation_score, message)
        """
        deviations = []
        
        # Check status code
        if actual_status != prediction.expected_status:
            status_deviation = 1.0  # 100% deviation on status mismatch
            deviations.append(f"Status: expected {prediction.expected_status}, got {actual_status}")
        else:
            status_deviation = 0.0
        
        # Check patterns
        pattern_matches = 0
        for pattern in prediction.expected_patterns:
            if pattern.lower() in actual_response.lower():
                pattern_matches += 1
        
        if prediction.expected_patterns:
            pattern_deviation = 1.0 - (pattern_matches / len(prediction.expected_patterns))
            if pattern_deviation > 0:
                deviations.append(f"Pattern match: {pattern_matches}/{len(prediction.expected_patterns)}")
        else:
            pattern_deviation = 0.0
        
        # Check response time
        if actual_time > prediction.max_response_time:
            time_deviation = (actual_time - prediction.max_response_time) / prediction.max_response_time
            deviations.append(f"Response time: {actual_time:.2f}s (max: {prediction.max_response_time}s)")
        else:
            time_deviation = 0.0
        
        # Calculate overall deviation
        overall_deviation = (status_deviation * 0.5) + (pattern_deviation * 0.3) + (time_deviation * 0.2)
        
        # Log execution
        self.execution_log.append({
            "tool": prediction.tool,
            "deviation": overall_deviation,
            "passed": overall_deviation <= prediction.deviation_threshold,
            "timestamp": datetime.now().isoformat()
        })
        
        if overall_deviation > prediction.deviation_threshold:
            message = f"HALT: Deviation {overall_deviation:.0%} exceeds threshold {prediction.deviation_threshold:.0%}. Issues: {'; '.join(deviations)}"
            logger.warning(f"[SANDBOX] {message}")
            return False, overall_deviation, message
        
        message = f"PASS: Deviation {overall_deviation:.0%} within threshold"
        logger.info(f"[SANDBOX] {message}")
        return True, overall_deviation, message


# ============================================================================
# OMEGA Protocol Orchestrator
# ============================================================================

class OmegaProtocol:
    """
    Master orchestrator for the OMEGA Protocol cognitive architecture.
    Coordinates Knowledge Graph, Adversarial Swarm, Epistemic Priority, and Virtual Sandbox.
    """
    
    def __init__(self):
        self.knowledge_graph = KnowledgeGraph()
        self.epistemic_state = EpistemicState()
        self.adversarial_swarm = AdversarialSwarm()
        self.virtual_sandbox = VirtualSandbox()
        self.active = False
    
    def activate(self):
        """Activate OMEGA Protocol"""
        self.active = True
        self.virtual_sandbox.lock_dependencies()
        logger.info("[OMEGA] Protocol activated")
    
    def deactivate(self):
        """Deactivate OMEGA Protocol"""
        self.active = False
        self.virtual_sandbox.unlock_dependencies()
        logger.info("[OMEGA] Protocol deactivated")
    
    async def evaluate_action(
        self,
        action: Dict[str, Any],
        context: str,
        orchestrator = None
    ) -> Dict[str, Any]:
        """
        Evaluate an action through the OMEGA Protocol pipeline
        
        1. Check epistemic state (is exploitation allowed?)
        2. Calculate risk and potentially trigger swarm debate
        3. Return modified action or halt signal
        """
        if not self.active:
            return {"proceed": True, "action": action, "message": "OMEGA Protocol inactive"}
        
        result = {
            "proceed": True,
            "action": action,
            "message": "",
            "epistemic_state": self.epistemic_state.get_state_summary(),
            "debate": None
        }
        
        # Step 1: Check epistemic state
        is_exploit_action = self._is_exploitation_action(action)
        
        if is_exploit_action and not self.epistemic_state.should_enable_exploitation():
            result["proceed"] = False
            result["message"] = f"[EPISTEMIC BLOCK] Exploitation locked. Confidence: {self.epistemic_state.overall_confidence:.0f}% (need {self.epistemic_state.confidence_threshold:.0f}%)"
            result["recommended_actions"] = self._get_recommended_recon_actions()
            return result
        
        # Step 2: Risk assessment and swarm debate
        if self.adversarial_swarm.should_debate(action):
            debate = await self.adversarial_swarm.conduct_debate(action, context, orchestrator)
            result["debate"] = debate
            
            if debate["verdict"] == "ABORT":
                result["proceed"] = False
                result["message"] = "[SWARM ABORT] Action vetoed by adversarial swarm"
                return result
            elif debate["verdict"] == "MODIFY":
                # Apply recommended modifications
                result["action"] = debate.get("recommendation", action)
                result["message"] = "[SWARM MODIFY] Action modified per swarm recommendation"
        
        return result
    
    def _is_exploitation_action(self, action: Dict[str, Any]) -> bool:
        """Check if action is an exploitation attempt"""
        exploit_keywords = {
            'exploit', 'inject', 'payload', 'sqlmap', 'metasploit',
            'attack', 'crack', 'brute', 'execute', 'shell'
        }
        
        tool = action.get('tool', '').lower()
        return any(kw in tool for kw in exploit_keywords)
    
    def _get_recommended_recon_actions(self) -> List[str]:
        """Get recommended reconnaissance actions"""
        recommendations = []
        
        if not self.epistemic_state.tech_stack_identified:
            recommendations.append("technology_fingerprint - Identify technology stack")
        
        if not self.epistemic_state.attack_surface_mapped:
            recommendations.append("subdomain_enumeration - Map attack surface")
            recommendations.append("javascript_analysis - Extract endpoints from JS")
        
        recommendations.append("api_discovery - Find API endpoints")
        
        return recommendations
    
    def update_knowledge(
        self,
        facts: List[str],
        relationships: List[Tuple[str, str, str]]
    ):
        """Update knowledge graph with new facts and relationships"""
        for fact in facts:
            # Simple parsing - could be enhanced
            self.knowledge_graph.add_node(
                fact,
                NodeType.ASSET,
                confidence=0.8,
                verified=True
            )
        
        for source, relation, target in relationships:
            try:
                edge_type = EdgeType[relation.upper()]
            except KeyError:
                edge_type = EdgeType.LEADS_TO
            
            self.knowledge_graph.add_edge(
                source, NodeType.ASSET,
                target, NodeType.ASSET,
                edge_type,
                confidence=0.7
            )
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive OMEGA Protocol status"""
        return {
            "active": self.active,
            "epistemic": {
                "mode": self.epistemic_state.mode.value,
                "confidence": self.epistemic_state.overall_confidence,
                "exploitation_enabled": self.epistemic_state.should_enable_exploitation()
            },
            "knowledge_graph": {
                "nodes": len(self.knowledge_graph.nodes),
                "edges": self.knowledge_graph.graph.number_of_edges(),
                "attack_paths": len(self.knowledge_graph.attack_paths)
            },
            "swarm": {
                "debates": len(self.adversarial_swarm.debate_history)
            },
            "sandbox": {
                "locked": self.virtual_sandbox.locked_dependencies,
                "executions": len(self.virtual_sandbox.execution_log)
            }
        }


# Singleton instance
_omega_protocol = None


def get_omega_protocol() -> OmegaProtocol:
    """Get or create the OMEGA Protocol singleton"""
    global _omega_protocol
    if _omega_protocol is None:
        _omega_protocol = OmegaProtocol()
    return _omega_protocol
