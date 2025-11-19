# agents/enhanced_ai_core.py
# --- VERSION 7.0 - OpenRouter Multi-LLM Enhanced ---

import asyncio
import json
import re
import os
from typing import Dict, List, Any, Optional
import logging
from pathlib import Path
import networkx as nx
from json_repair import repair_json
from agents.learning_engine import AegisLearningEngine
from agents.multi_llm_orchestrator import MultiLLMOrchestrator
from utils.reasoning_display import get_reasoning_display
from utils.database_manager import get_database

logger = logging.getLogger(__name__)

# CRITICAL: Model constants for OpenRouter API - Load from environment or use defaults
ORCHESTRATOR_MODEL = os.getenv("ORCHESTRATOR_MODEL", "nousresearch/hermes-3-llama-3.1-70b")
# CODER_MODEL can override CODE_MODEL for specialized coding tasks (e.g., Dolphin-Deepseek)
CODE_MODEL = os.getenv("CODER_MODEL", os.getenv("CODE_MODEL", "qwen/qwen-2.5-72b-instruct"))
REASONING_MODEL = os.getenv("REASONING_MODEL", "cognitivecomputations/dolphin3.0-r1-mistral-24b")


def parse_json_robust(content: str) -> Optional[Dict]:
    """
    Robustly parse JSON from LLM response with fallback strategies.
    
    This function implements multiple parsing strategies:
    1. Try to extract JSON from markdown code blocks (```json ... ```)
    2. Try to extract raw JSON object from content
    3. Try to repair malformed JSON using json_repair
    4. Try direct JSON parsing
    
    Args:
        content: String content that may contain JSON
    
    Returns:
        Parsed JSON as dictionary, or None if parsing fails
    """
    if not content:
        return None
    
    # Strategy 1: Extract from markdown code block
    json_match = re.search(r'```json\s*(\{.*?\})\s*```', content, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            # Try to repair it
            try:
                repaired = repair_json(json_match.group(1))
                return json.loads(repaired)
            except:
                pass
    
    # Strategy 2: Extract raw JSON object
    json_match = re.search(r'\{.*\}', content, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            # Try to repair it
            try:
                repaired = repair_json(json_match.group(0))
                return json.loads(repaired)
            except:
                pass
    
    # Strategy 3: Try direct parsing
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        try:
            repaired = repair_json(content)
            return json.loads(repaired)
        except:
            pass
    
    return None


class MissionBlackboard:
    """
    Persistent mission blackboard memory system with Knowledge Graph support.
    Stores verified facts, pending goals, and discarded attack vectors across the session.
    
    This implements a "blackboard architecture" where:
    - verified_facts: Ground truths discovered and confirmed
    - pending_goals: Objectives to achieve, prioritized
    - discarded_vectors: Attack paths already tried and failed
    - knowledge_graph: NetworkX DiGraph storing relationships between entities
    """
    
    def __init__(self, mission_id: Optional[str] = None):
        """
        Initialize the blackboard
        
        Args:
            mission_id: Optional mission identifier for persistence
        """
        self.mission_id = mission_id or "default"
        self.verified_facts: List[str] = []
        self.pending_goals: List[str] = []
        self.discarded_vectors: List[str] = []
        self.knowledge_graph = nx.DiGraph()  # Knowledge graph for relationships
        self.blackboard_file = Path(f"data/blackboard_{self.mission_id}.json")
        self.graph_file = Path(f"data/graph_{self.mission_id}.graphml")
        
        # Load existing blackboard if it exists
        self._load()
        self._load_graph()
    
    def _load(self) -> None:
        """Load blackboard from disk if it exists"""
        if self.blackboard_file.exists():
            try:
                with open(self.blackboard_file, 'r') as f:
                    data = json.load(f)
                    self.verified_facts = data.get('verified_facts', [])
                    self.pending_goals = data.get('pending_goals', [])
                    self.discarded_vectors = data.get('discarded_vectors', [])
                    logger.info(f"📋 Loaded blackboard: {len(self.verified_facts)} facts, "
                              f"{len(self.pending_goals)} goals, {len(self.discarded_vectors)} discarded vectors")
            except Exception as e:
                logger.warning(f"Failed to load blackboard: {e}")
    
    def _save(self) -> None:
        """Save blackboard to disk"""
        try:
            # Ensure data directory exists
            self.blackboard_file.parent.mkdir(exist_ok=True, parents=True)
            
            data = {
                'verified_facts': self.verified_facts,
                'pending_goals': self.pending_goals,
                'discarded_vectors': self.discarded_vectors,
                'mission_id': self.mission_id
            }
            
            with open(self.blackboard_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.debug(f"💾 Saved blackboard to {self.blackboard_file}")
        except Exception as e:
            logger.error(f"Failed to save blackboard: {e}")
    
    def _load_graph(self) -> None:
        """Load knowledge graph from disk if it exists"""
        if self.graph_file.exists():
            try:
                self.knowledge_graph = nx.read_graphml(str(self.graph_file))
                logger.info(f"📊 Loaded knowledge graph: {self.knowledge_graph.number_of_nodes()} nodes, "
                          f"{self.knowledge_graph.number_of_edges()} edges")
            except Exception as e:
                logger.warning(f"Failed to load knowledge graph: {e}")
                self.knowledge_graph = nx.DiGraph()
    
    def _save_graph(self) -> None:
        """Save knowledge graph to disk"""
        try:
            # Ensure data directory exists
            self.graph_file.parent.mkdir(exist_ok=True, parents=True)
            
            # Save as GraphML format for persistence
            nx.write_graphml(self.knowledge_graph, str(self.graph_file))
            
            logger.debug(f"💾 Saved knowledge graph to {self.graph_file}")
        except Exception as e:
            logger.error(f"Failed to save knowledge graph: {e}")
    
    def add_relationship(self, source: str, relation: str, target: str, **metadata) -> None:
        """
        Maps a relationship in the knowledge graph.
        
        Args:
            source: Source node (e.g., "192.168.1.5", "admin.example.com")
            relation: Relationship type (e.g., "HAS_VULN", "EXPOSES", "ALLOWS_ACTION")
            target: Target node (e.g., "Port 80", "SQLi", "Dump DB")
            **metadata: Additional metadata for the relationship
        
        Example:
            blackboard.add_relationship("admin.example.com", "HAS_VULN", "SQLi")
            blackboard.add_relationship("SQLi", "ALLOWS_ACTION", "Dump DB")
        """
        if not source or not target:
            logger.warning("Cannot add relationship with empty source or target")
            return
        
        # Add edge with relationship type and metadata
        self.knowledge_graph.add_edge(
            source, 
            target, 
            relationship=relation,
            **metadata
        )
        self._save_graph()
        logger.info(f"🔗 Added relationship: {source} --[{relation}]--> {target}")
    
    def get_attack_path(self, target_goal: str, source: str = "Entry_Point") -> List[List[str]]:
        """
        Finds attack paths from source to target goal in the knowledge graph.
        
        Args:
            target_goal: Goal node to reach (e.g., "Domain Admin", "Database Access")
            source: Starting point (default: "Entry_Point")
        
        Returns:
            List of paths, where each path is a list of nodes
        
        Example:
            paths = blackboard.get_attack_path("Domain Admin")
            # Returns: [["Entry_Point", "Web Server", "SQLi", "Domain Admin"], ...]
        """
        try:
            # Check if source and target exist in the graph
            if source not in self.knowledge_graph.nodes():
                logger.warning(f"Source node '{source}' not found in knowledge graph")
                return []
            
            if target_goal not in self.knowledge_graph.nodes():
                logger.warning(f"Target node '{target_goal}' not found in knowledge graph")
                return []
            
            # Find all simple paths (no cycles)
            paths = list(nx.all_simple_paths(
                self.knowledge_graph, 
                source=source, 
                target=target_goal,
                cutoff=10  # Limit path length to avoid infinite loops
            ))
            
            logger.info(f"🎯 Found {len(paths)} attack path(s) from '{source}' to '{target_goal}'")
            return paths
            
        except nx.NetworkXNoPath:
            logger.info(f"No path found from '{source}' to '{target_goal}'")
            return []
        except Exception as e:
            logger.error(f"Error finding attack path: {e}")
            return []
    
    def get_graph_summary(self) -> str:
        """
        Get a summary of the knowledge graph.
        
        Returns:
            Formatted string with graph statistics and key relationships
        """
        if self.knowledge_graph.number_of_nodes() == 0:
            return "Knowledge Graph: Empty"
        
        summary_parts = [
            f"Knowledge Graph: {self.knowledge_graph.number_of_nodes()} nodes, "
            f"{self.knowledge_graph.number_of_edges()} edges"
        ]
        
        # Show key nodes (nodes with most connections)
        if self.knowledge_graph.number_of_nodes() > 0:
            node_degrees = dict(self.knowledge_graph.degree())
            top_nodes = sorted(node_degrees.items(), key=lambda x: x[1], reverse=True)[:5]
            
            if top_nodes:
                summary_parts.append("\nKey nodes:")
                for node, degree in top_nodes:
                    summary_parts.append(f"  - {node} ({degree} connections)")
        
        return "\n".join(summary_parts)
    
    def add_fact(self, fact: str) -> None:
        """Add a verified fact to the blackboard"""
        if fact and fact not in self.verified_facts:
            self.verified_facts.append(fact)
            self._save()
            logger.info(f"✅ Added fact: {fact[:80]}...")
    
    def add_goal(self, goal: str) -> None:
        """Add a pending goal to the blackboard"""
        if goal and goal not in self.pending_goals:
            self.pending_goals.append(goal)
            self._save()
            logger.info(f"🎯 Added goal: {goal[:80]}...")
    
    def complete_goal(self, goal: str) -> None:
        """Mark a goal as completed and remove it"""
        if goal in self.pending_goals:
            self.pending_goals.remove(goal)
            self._save()
            logger.info(f"✓ Completed goal: {goal[:80]}...")
    
    def discard_vector(self, vector: str) -> None:
        """Mark an attack vector as discarded (tried and failed)"""
        if vector and vector not in self.discarded_vectors:
            self.discarded_vectors.append(vector)
            self._save()
            logger.info(f"🚫 Discarded vector: {vector[:80]}...")
    
    def get_summary(self) -> str:
        """Get a formatted summary of the blackboard state"""
        summary_parts = ["=== MISSION BLACKBOARD ==="]
        
        if self.verified_facts:
            summary_parts.append(f"\nVERIFIED FACTS ({len(self.verified_facts)}):")
            for i, fact in enumerate(self.verified_facts[-10:], 1):  # Last 10 facts
                summary_parts.append(f"  {i}. {fact}")
        else:
            summary_parts.append("\nVERIFIED FACTS: None yet")
        
        if self.pending_goals:
            summary_parts.append(f"\nPENDING GOALS ({len(self.pending_goals)}):")
            for i, goal in enumerate(self.pending_goals[:5], 1):  # Top 5 goals
                summary_parts.append(f"  {i}. {goal}")
        else:
            summary_parts.append("\nPENDING GOALS: None")
        
        if self.discarded_vectors:
            summary_parts.append(f"\nDISCARDED VECTORS ({len(self.discarded_vectors)}):")
            for i, vector in enumerate(self.discarded_vectors[-5:], 1):  # Last 5 discarded
                summary_parts.append(f"  {i}. {vector}")
        else:
            summary_parts.append("\nDISCARDED VECTORS: None")
        
        # Add knowledge graph summary
        summary_parts.append(f"\n{self.get_graph_summary()}")
        
        summary_parts.append("=" * 30)
        
        return "\n".join(summary_parts)
    
    def clear(self) -> None:
        """Clear all blackboard data"""
        self.verified_facts = []
        self.pending_goals = []
        self.discarded_vectors = []
        self.knowledge_graph.clear()
        self._save()
        self._save_graph()
        logger.info("🗑️ Cleared blackboard")


class CortexMemory:
    """
    Advanced Knowledge Graph Memory for state-aware navigation and backtracking.
    
    Every URL/State is a "Node". Every action is an "Edge".
    This allows algorithmic backtracking when stuck, e.g.:
    "I am stuck at Admin Panel, let me go back 3 steps to Registration and try a different approach"
    """
    
    def __init__(self, mission_id: Optional[str] = None):
        """
        Initialize Cortex Memory with state tracking
        
        Args:
            mission_id: Optional mission identifier for persistence
        """
        self.mission_id = mission_id or "default"
        self.graph = nx.DiGraph()
        self.current_node = "root"
        self.node_counter = 0
        
        # Initialize root node
        self.graph.add_node(
            "root", 
            url="START", 
            artifacts="{}",
            dom_hash="",
            timestamp="0",
            node_type="entry"
        )
        
        # Path tracking for backtracking
        self.current_path: List[str] = ["root"]
        self.visited_states: set = set()
        
        # Persistence
        self.cortex_file = Path(f"data/cortex_{self.mission_id}.graphml")
        self._load()
        
        logger.info(f"[Cortex] Memory initialized: {self.graph.number_of_nodes()} nodes")
    
    def _load(self) -> None:
        """Load cortex graph from disk if it exists"""
        if self.cortex_file.exists():
            try:
                self.graph = nx.read_graphml(str(self.cortex_file))
                # Restore current node from graph attributes
                graph_data = dict(self.graph.graph)
                self.current_node = graph_data.get('current_node', 'root')
                node_counter_str = graph_data.get('node_counter', '0')
                self.node_counter = int(node_counter_str) if isinstance(node_counter_str, str) else node_counter_str
                
                # Convert JSON strings back to dicts
                for node in self.graph.nodes():
                    node_data = self.graph.nodes[node]
                    if 'artifacts' in node_data and isinstance(node_data['artifacts'], str):
                        try:
                            self.graph.nodes[node]['artifacts'] = json.loads(node_data['artifacts'])
                        except:
                            pass
                    if 'state' in node_data and isinstance(node_data['state'], str):
                        try:
                            self.graph.nodes[node]['state'] = json.loads(node_data['state'])
                        except:
                            pass
                
                logger.info(f"[Cortex] Loaded graph: {self.graph.number_of_nodes()} nodes, "
                          f"{self.graph.number_of_edges()} edges")
            except Exception as e:
                logger.warning(f"[Cortex] Failed to load graph: {e}")
                self.graph = nx.DiGraph()
    
    def _save(self) -> None:
        """Save cortex graph to disk"""
        try:
            self.cortex_file.parent.mkdir(exist_ok=True, parents=True)
            
            # Store current state as graph attributes
            self.graph.graph['current_node'] = self.current_node
            self.graph.graph['node_counter'] = str(self.node_counter)
            
            nx.write_graphml(self.graph, str(self.cortex_file))
            logger.debug(f"[Cortex] Saved graph to {self.cortex_file}")
        except Exception as e:
            logger.error(f"[Cortex] Failed to save graph: {e}")
    
    def record_action(
        self, 
        action: str, 
        result: dict, 
        new_url: str,
        artifacts: dict = None,
        dom_hash: str = None
    ) -> str:
        """
        Maps the exploitation path by recording an action and its result.
        
        Args:
            action: Description of the action taken (e.g., "Submit login form", "Click admin link")
            result: Result dictionary containing response data
            new_url: URL after the action
            artifacts: Optional artifacts discovered (forms, inputs, vulnerabilities)
            dom_hash: Optional hash of the DOM state for duplicate detection
        
        Returns:
            The new node ID
        """
        import time
        
        # Generate unique node ID
        self.node_counter += 1
        state_signature = f"{new_url}_{dom_hash or hash(str(result))}"
        new_node_id = f"node_{self.node_counter}_{hash(state_signature) % 10000}"
        
        # Create new node with detailed state information
        self.graph.add_node(
            new_node_id,
            url=new_url,
            artifacts=json.dumps(artifacts or {}),
            dom_hash=dom_hash or "",
            timestamp=str(time.time()),
            visited="1",
            node_type="state"
        )
        
        # Create edge from current node to new node
        success_score = result.get('success_score', 1)
        status_code = result.get('status_code', 200)
        
        self.graph.add_edge(
            self.current_node,
            new_node_id,
            action=action,
            weight=str(success_score),
            status_code=str(status_code),
            timestamp=str(time.time())
        )
        
        # Update current node and path
        self.current_node = new_node_id
        self.current_path.append(new_node_id)
        self.visited_states.add(state_signature)
        
        # Save state
        self._save()
        
        logger.info(f"[Cortex] Recorded: {self.current_node} via '{action}' -> {new_url}")
        
        return new_node_id
    
    def find_backtrack_path(self, heuristic: str = "untested") -> Optional[str]:
        """
        Algorithmic Backtracking:
        If current path fails, find the nearest unexplored node with high heuristic value.
        
        Args:
            heuristic: Backtracking strategy
                - "untested": Find nodes with unexplored outgoing edges
                - "successful": Find nodes from successful actions (high weight edges)
                - "nearest": Find the nearest unvisited node
        
        Returns:
            Node ID to backtrack to, or None if no suitable node found
        """
        if heuristic == "untested":
            # Find nodes with low out-degree (unexplored)
            candidates = []
            for node in self.graph.nodes():
                if node == self.current_node:
                    continue
                
                out_degree = self.graph.out_degree(node)
                # Nodes with few outgoing edges are less explored
                if out_degree < 3:
                    # Calculate path distance from current node
                    try:
                        path_length = nx.shortest_path_length(
                            self.graph, 
                            source=node, 
                            target=self.current_node
                        )
                        candidates.append((node, out_degree, path_length))
                    except nx.NetworkXNoPath:
                        continue
            
            if candidates:
                # Sort by: lowest out_degree first, then shortest path
                candidates.sort(key=lambda x: (x[1], x[2]))
                best_node = candidates[0][0]
                logger.info(f"[Cortex] Backtracking to {best_node} (untested strategy)")
                return best_node
        
        elif heuristic == "successful":
            # Find nodes connected by high-weight edges (successful actions)
            candidates = []
            for node in self.graph.nodes():
                if node == self.current_node or node == "root":
                    continue
                
                # Get incoming edges and their weights
                incoming = list(self.graph.in_edges(node, data=True))
                if incoming:
                    avg_weight = sum(data.get('weight', 1) for _, _, data in incoming) / len(incoming)
                    if avg_weight > 0.5:  # Threshold for "successful"
                        candidates.append((node, avg_weight))
            
            if candidates:
                candidates.sort(key=lambda x: x[1], reverse=True)
                best_node = candidates[0][0]
                logger.info(f"[Cortex] Backtracking to {best_node} (successful strategy)")
                return best_node
        
        elif heuristic == "nearest":
            # Find nearest node in the current path
            if len(self.current_path) > 2:
                backtrack_node = self.current_path[-3]  # Go back 2 steps
                logger.info(f"[Cortex] Backtracking to {backtrack_node} (nearest strategy)")
                return backtrack_node
        
        logger.warning("[Cortex] No suitable backtrack node found")
        return None
    
    def set_current_node(self, node_id: str) -> bool:
        """
        Manually set the current node (for backtracking).
        
        Args:
            node_id: Node to set as current
        
        Returns:
            True if successful, False if node doesn't exist
        """
        if node_id in self.graph.nodes():
            self.current_node = node_id
            # Update path
            if node_id in self.current_path:
                # Truncate path to backtrack point
                idx = self.current_path.index(node_id)
                self.current_path = self.current_path[:idx + 1]
            else:
                self.current_path.append(node_id)
            
            self._save()
            logger.info(f"[Cortex] Current node set to {node_id}")
            return True
        else:
            logger.warning(f"[Cortex] Node {node_id} not found")
            return False
    
    def get_current_state(self) -> Dict[str, Any]:
        """
        Get the current state information.
        
        Returns:
            Dictionary with current state details
        """
        node_data = dict(self.graph.nodes[self.current_node])
        
        return {
            "node_id": self.current_node,
            "url": node_data.get("url", "unknown"),
            "artifacts": node_data.get("artifacts", {}),
            "path_length": len(self.current_path),
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges()
        }
    
    def get_available_actions(self) -> List[Dict[str, Any]]:
        """
        Get available actions from the current node.
        
        Returns:
            List of dictionaries describing available edges/actions
        """
        outgoing_edges = list(self.graph.out_edges(self.current_node, data=True))
        
        actions = []
        for source, target, data in outgoing_edges:
            actions.append({
                "action": data.get("action", "unknown"),
                "target_node": target,
                "weight": data.get("weight", 1),
                "status_code": data.get("status_code", 200)
            })
        
        return actions
    
    def visualize_path(self) -> str:
        """
        Generate a text visualization of the current path.
        
        Returns:
            String representation of the path
        """
        if not self.current_path:
            return "No path recorded"
        
        path_str = "Current Exploration Path:\n"
        
        for i, node_id in enumerate(self.current_path):
            node_data = dict(self.graph.nodes[node_id])
            url = node_data.get("url", "unknown")
            
            path_str += f"  {i+1}. [{node_id}] {url}\n"
            
            # Show the action that led to next node
            if i < len(self.current_path) - 1:
                next_node = self.current_path[i + 1]
                if self.graph.has_edge(node_id, next_node):
                    edge_data = dict(self.graph.edges[node_id, next_node])
                    action = edge_data.get("action", "unknown")
                    path_str += f"      └─> {action}\n"
        
        return path_str
    
    def clear(self) -> None:
        """Clear all cortex memory"""
        self.graph.clear()
        self.current_node = "root"
        self.node_counter = 0
        self.current_path = ["root"]
        self.visited_states.clear()
        
        # Re-initialize root
        self.graph.add_node(
            "root", 
            url="START", 
            artifacts="{}",
            dom_hash="",
            timestamp="0",
            node_type="entry"
        )
        
        self._save()
        logger.info("[Cortex] Memory cleared")


class EnhancedAegisAI:
    """
    Enhanced AI Core v7.0 - Powered by Three Specialized LLMs via OpenRouter
    
    This class orchestrates three LLMs from OpenRouter API:
    1. Hermes 3 Llama 70B - Strategic planning, triage, and decision-making
    2. Dolphin 3.0 R1 Mistral 24B - Reasoning and vulnerability analysis  
    3. Qwen 2.5 72B - Code analysis and payload generation
    """
    
    def __init__(self, learning_engine: AegisLearningEngine = None):
        self.orchestrator = MultiLLMOrchestrator()
        self.learning_engine = learning_engine or AegisLearningEngine()
        self.learned_patterns = ""
        self.is_initialized = False
        self.reasoning_display = get_reasoning_display(verbose=True)
        self.conversation_history = []  # Added for memory management
        self.dynamic_tool_prompt = ""  # TASK 3: Dynamic tool prompt
        self.max_history_size = 10  # Maximum conversation history to keep
        self.context_summary = None  # Summary of older context
        self.db = get_database()  # TASK 2: Mission database integration
        self.blackboard = MissionBlackboard()  # Mission blackboard memory
        
        # PHASE 2: Business logic mapper for application-specific testing
        from utils.business_logic_mapper import get_business_logic_mapper
        self.logic_mapper = get_business_logic_mapper()
    
    async def initialize(self):
        """Initialize the enhanced AI core with all LLMs"""
        try:
            logger.info("🚀 Initializing Enhanced Aegis AI with Multi-LLM support...")
            
            # Initialize the orchestrator
            await self.orchestrator.initialize()
            
            # TASK 3: Load dynamic tool prompt
            from utils.dynamic_tool_loader import get_tool_loader
            tool_loader = get_tool_loader()
            self.dynamic_tool_prompt = tool_loader.build_dynamic_tool_prompt()
            logger.info("✅ Dynamic tool prompt loaded.")
            
            # Load learned patterns if learning engine is available
            if self.learning_engine:
                logger.info("🧠 Loading learned patterns from previous missions...")
                try:
                    loop = asyncio.get_event_loop()
                    self.learned_patterns = await loop.run_in_executor(
                        None, self.learning_engine.load_learned_patterns
                    )
                    logger.info("✅ Learned patterns loaded.")
                except AttributeError:
                    logger.warning("⚠️ load_learned_patterns method not available, skipping.")
                    self.learned_patterns = ""
            
            self.is_initialized = True
            logger.info("✅ Enhanced AI Core ready with multi-LLM support.")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize Enhanced AI Core: {e}", exc_info=True)
            raise
    
    def _prune_memory(self, history: List[Dict]) -> List[Dict]:
        """
        Enhanced memory management to prevent "Digital Alzheimer's"
        Keeps recent detailed interactions and maintains contextual summary
        
        Args:
            history: Full conversation history
            
        Returns:
            Pruned history with summary of old interactions
        """
        if len(history) <= self.max_history_size:
            return history
        
        # Keep the last max_history_size interactions
        recent = history[-self.max_history_size:]
        
        # Summarize older interactions if we haven't done so recently
        older = history[:-self.max_history_size]
        
        # Extract key information from older interactions
        key_findings = []
        key_decisions = []
        for item in older:
            content = item.get('content', '')
            if 'vulnerability' in content.lower() or 'finding' in content.lower():
                key_findings.append(content[:100])  # First 100 chars
            if 'decision' in content.lower() or 'action' in content.lower():
                key_decisions.append(content[:100])
        
        # Build comprehensive summary
        summary_parts = [
            f"[Context from {len(older)} previous interactions:",
            f"Key findings: {len(key_findings)}",
            f"Key decisions: {len(key_decisions)}"
        ]
        
        if key_findings:
            summary_parts.append(f"Notable findings: {', '.join(key_findings[:3])}")
        
        summary_content = " ".join(summary_parts) + "]"
        
        # Create a summary entry
        summary_entry = {
            "role": "system",
            "content": summary_content
        }
        
        return [summary_entry] + recent
    
    # --- LEVEL 1: STRATEGIC TRIAGE (using Llama 70B) ---
    async def triage_mission(self, conversation_history: List[Dict]) -> Dict:
        """
        Analyzes conversation and determines if mission is ready
        Uses Llama 70B for strategic planning and decision-making
        """
        if not self.is_initialized:
            return {"response_type": "error", "text": "AI not initialized."}
        
        # Show reasoning about mission triage
        self.reasoning_display.show_thought(
            "Analyzing conversation to determine mission readiness",
            thought_type="strategic",
            metadata={
                "conversation_length": len(conversation_history),
                "function": "triage_mission"
            }
        )
        
        system_prompt = """You are Aegis AI, a cybersecurity mission planner. Your goal is to gather ALL necessary information before launching a mission.

Required information:
1. **TARGET** (e.g., "example.com", "192.168.1.1", or a file like "image.png")
2. **RULES** (e.g., scope, out-of-scope, rate limits, CTF rules)

YOUR TASK:
- Analyze the conversation history
- If information is missing, ask a CLEAR and CONCISE question
- When user provides information, acknowledge it and ask for what's next
- **DO NOT start any scans yourself**

**ONCE YOU HAVE ALL INFORMATION (TARGET + RULES)**, respond ONLY with this JSON:
```json
{
  "response_type": "start_mission",
  "target": "[the main target]",
  "rules": "[summary of all rules and instructions]"
}
```

If information is missing, respond with:
```json
{
  "response_type": "question",
  "text": "[your question to the user]"
}
```"""

        # Convert conversation history to message format
        conversation_text = "\n".join([
            f"{msg.get('role', 'user')}: {msg.get('content', '')}"
            for msg in conversation_history
        ])
        
        user_message = f"""Conversation history:
{conversation_text}

Analyze this conversation and determine if we have all information (target and rules) to start the mission. Respond with the appropriate JSON."""

        try:
            response = await self.orchestrator.execute_task(
                task_type='triage',
                system_prompt=system_prompt,
                user_message=user_message,
                temperature=0.7,
                max_tokens=1024
            )
            
            content = response['content']
            
            # Extract JSON from response using robust parser
            result = parse_json_robust(content)
            
            if result:
                # Show reasoning about the triage decision
                self.reasoning_display.show_thought(
                    f"Triage decision: {result.get('response_type', 'unknown')}",
                    thought_type="decision",
                    metadata=result
                )
                
                return result
            
            # Fallback: treat as conversational response
            result = {
                "response_type": "question",
                "text": content
            }
            
            self.reasoning_display.show_thought(
                "Could not parse as JSON, treating as conversational response",
                thought_type="warning",
                metadata={"raw_response": content[:200]}
            )
            
            return result
                
        except Exception as e:
            logger.error(f"Error in triage_mission: {e}", exc_info=True)
            return {
                "response_type": "error",
                "text": f"Error analyzing mission: {str(e)}"
            }
    
    # --- LEVEL 2: AUTONOMOUS AGENT (using Mixtral 8x7B) ---
    def get_next_action(self, bbp_rules: str, agent_memory: List[Dict]) -> Dict:
        """
        Decides the next action based on BBP rules and agent memory
        Uses Mixtral 8x7B for vulnerability analysis and exploitation planning
        
        Note: This is synchronous to maintain compatibility with existing code
        """
        # Run async function in sync context
        return asyncio.run(self._get_next_action_async(bbp_rules, agent_memory))
    
    async def _get_next_action_async(self, bbp_rules: str, agent_memory: List[Dict]) -> Dict:
        """Async implementation of get_next_action"""
        if not self.is_initialized:
            return {"tool": "system", "message": "AI not initialized"}
        
        # TASK 1: Prune memory to prevent unlimited growth
        agent_memory = self._prune_memory(agent_memory)
        
        # TASK 2: Get database statistics for context awareness
        db_stats = self.db.get_statistics()
        scanned_targets = self.db.get_scanned_targets()
        
        # Build database context string
        db_context = f"""
DATABASE STATUS (Avoid Duplicate Work):
- Total scanned targets: {db_stats.get('total_scanned_targets', 0)}
- Total findings: {db_stats.get('total_findings', 0)}
- Verified findings: {db_stats.get('verified_findings', 0)}
"""
        if scanned_targets:
            recent_scans = scanned_targets[:5]  # Last 5 scans
            db_context += "\nRecent scans (avoid duplicating):\n"
            for scan in recent_scans:
                db_context += f"  - {scan['target']} ({scan['scan_type']}) at {scan['scanned_at']}\n"
        
        # BLACKBOARD MEMORY: Get current blackboard summary
        blackboard_summary = self.blackboard.get_summary()
        
        # Show reasoning about next action decision
        self.reasoning_display.show_thought(
            "Determining next action based on mission rules and agent memory",
            thought_type="tactical",
            metadata={
                "memory_items": len(agent_memory),
                "last_observation": agent_memory[-1] if agent_memory else None,
                "db_stats": db_stats,
                "blackboard_facts": len(self.blackboard.verified_facts),
                "blackboard_goals": len(self.blackboard.pending_goals)
            }
        )
        
        system_prompt = f"""You are an advanced autonomous penetration testing agent with sophisticated reasoning capabilities.
Your task is to decide the next action based on mission rules, observations, and learned patterns.

MISSION RULES:
{bbp_rules}

{db_context}

{blackboard_summary}

LEARNED PATTERNS FROM PREVIOUS MISSIONS:
{self.learned_patterns}

{self.dynamic_tool_prompt}

{self.logic_mapper.get_testable_functions()}

PHASE 4 - MULTIMODAL CAPABILITIES & VISUAL GROUNDING:
You now have access to visual reconnaissance tools for analyzing web interfaces:
- capture_screenshot_som(url, full_page=True/False): Capture screenshot with Set-of-Mark (SoM) visual grounding
  * Returns a screenshot with numbered red badges on all clickable elements
  * Provides element_mapping with {ID: selector} for each interactive element
  * Use this when you need to understand the UI layout and identify clickable elements
- click_element_by_id(url, element_id): Click a specific element using its SoM ID
  * Must be called AFTER capture_screenshot_som
  * Use the element ID from the SoM mapping
  * This allows precise interaction with UI elements identified in screenshots
- visual_screenshot(url, full_page=True/False): Capture regular authenticated screenshot (no SoM badges)
- visual_recon.get_dom_snapshot(url, selectors=[]): Extract DOM elements and analyze page structure
- logic_tester.test_logic_flow(flow_name, steps, expected_behavior): Test business logic for vulnerabilities

VISUAL GROUNDING WORKFLOW (Set-of-Mark):
1. First, call capture_screenshot_som(url) to get a tagged screenshot
2. The screenshot will show numbered red badges on all clickable elements
3. Analyze the screenshot to identify which element to interact with
4. Call click_element_by_id(url, element_id) with the ID of the desired element
5. The system will automatically use the stored selector to perform the click

Use visual grounding tools when:
- You need to understand the visual layout or UI of a target
- You want to identify and interact with specific UI elements (buttons, links, forms)
- You're testing multi-step workflows that require clicking through the interface
- You need to verify visual elements or CAPTCHA-type protections
- You're analyzing client-side elements that might not be visible in HTTP responses

MULTI-SESSION PRIVILEGE ESCALATION TESTING:
You can now test for privilege escalation vulnerabilities using multi-session management:
- manage_multi_session(action="login", session_name="Session_Admin", credentials={{...}}): Login as admin user
- manage_multi_session(action="login", session_name="Session_User", credentials={{...}}): Login as low-privilege user
- manage_multi_session(action="list"): List all active sessions
- replay_request_with_session(request={{method, url, headers, data}}, session_name="Session_User"): Replay admin request with user cookies

PRIVILEGE ESCALATION WORKFLOW:
1. Login as admin user with manage_multi_session to create Session_Admin
2. Login as low-privilege user with manage_multi_session to create Session_User
3. When you find a privileged action (e.g., POST /api/add_device), capture the request details
4. Use replay_request_with_session to replay the same request with Session_User cookies
5. If the request succeeds (status 2xx), it's a confirmed privilege escalation vulnerability

IMPACT QUANTIFIER (RAG SYSTEM):
You now have access to a RAG system for assessing real-world business impact:
- ingest_documentation(url="https://docs.example.com/api", type="api"): Ingest documentation into RAG system
- assess_impact(finding={{type, endpoint, description}}, context="..."): Query RAG and assess real-world impact
- rag_statistics(): Get statistics about ingested documentation

IMPACT ASSESSMENT WORKFLOW:
1. When target scope includes documentation URLs (e.g., docs.cfengine.com), ingest them first
2. When you discover a hidden API endpoint (e.g., POST /api/create_report), use assess_impact
3. The RAG system will query the documentation to understand what the endpoint does
4. Strategic LLM will reason: "This endpoint consumes 500MB disk. If looped, causes DoS. High impact."
5. Use the impact assessment to prioritize findings and write better reports

ENHANCED MULTI-STAGE REASONING FRAMEWORK:

STAGE 1 - DEEP ANALYSIS:
1. Current State Assessment:
   - What has been accomplished so far?
   - What vulnerabilities or findings have been discovered?
   - What areas remain unexplored?
   - What patterns or anomalies are present in the results?
   - Are there any dead ends or rabbit holes to avoid?
   - Check the DATABASE STATUS above to avoid duplicate scans!

2. Information Gap Analysis:
   - What critical information is missing?
   - What assumptions are we making?
   - What dependencies exist between discoveries?
   - What could we be overlooking?

STAGE 2 - STRATEGIC PLANNING:
1. Multi-Path Exploration:
   - Generate 3-5 possible next actions
   - Evaluate each action's potential value
   - Consider both breadth (new attack surfaces) and depth (following leads)
   - Assess resource cost vs expected gain

2. Prioritization Framework:
   - Severity: Which actions target high-impact vulnerabilities?
   - Likelihood: Which actions have the highest success probability?
   - Coverage: Which areas need more comprehensive testing?
   - Efficiency: Which actions provide maximum insight with minimal effort?

STAGE 3 - RISK ASSESSMENT:
1. Scope Compliance:
   - Does this action stay within the authorized scope?
   - Are there any out-of-scope dependencies?
   - What are the potential unintended consequences?

2. Technical Risk:
   - Could this action cause service disruption?
   - What is the intrusive level of this action?
   - Are there safer alternatives?

STAGE 4 - DECISION MAKING:
1. Select the optimal action that:
   - Maximizes detection chances
   - Follows a logical progression
   - Respects mission rules and scope
   - Provides actionable intelligence
   - Balances thoroughness with efficiency

2. Adaptive Learning:
   - Learn from previous failed attempts
   - Adjust strategy based on target behavior
   - Recognize when to pivot vs persist

STAGE 5 - REFLECTION:
1. Self-Assessment:
   - Is this the best possible action right now?
   - What could go wrong?
   - What fallback options exist?
   - How will this contribute to the overall mission?

CRITICAL INSTRUCTIONS:
- Show ALL your reasoning through each stage
- Explain WHY you chose this specific action over alternatives
- Consider edge cases and potential obstacles
- Follow the rules STRICTLY (no out-of-scope testing)
- If mission is complete, use finish_mission
- If uncertain or need guidance, use ask_user_for_approval
- Be thorough, methodical, and intelligent in your approach
- Learn from past observations and avoid repeating failed attempts

⚠️ STRICT GROUNDING RULE (ANTI-HALLUCINATION) ⚠️
You can ONLY attack targets that explicitly exist in the 'DATABASE STATUS' list provided above.
When proposing an action, you MUST cite the specific 'target_id' or exact string from the database context.
If you want to attack a new target, you must first run 'subdomain_enumeration' to find it and add it to the DB.
DO NOT invent URLs, domains, or targets that are not present in the database or mission context.
ANY action targeting a URL/domain MUST reference an existing entry from the scanned targets list.

Respond with JSON ONLY including comprehensive multi-stage reasoning:
```json
{{
  "tool": "tool_name",
  "args": {{"param": "value"}},
  "reasoning": {{
    "analysis": "Deep analysis of current state, findings, and patterns",
    "options_considered": ["option1", "option2", "option3"],
    "selected_option": "tool_name",
    "justification": "Why this option is optimal: expected outcomes, strategic fit, risk assessment",
    "expected_outcome": "What we expect to discover or achieve",
    "fallback_plan": "What to do if this action fails or doesn't yield results",
    "mission_progress": "How this action advances the overall mission objectives"
  }}
}}
```"""

        # Format agent memory
        memory_text = "\n".join([
            f"[{mem.get('type', 'unknown')}] {mem.get('content', '')}"
            for mem in agent_memory[-10:]  # Last 10 observations
        ])
        
        user_message = f"""Agent memory:
{memory_text}

Based on this context, what should be the next action? Respond with JSON only."""

        try:
            response = await self.orchestrator.execute_task(
                task_type='next_action',
                system_prompt=system_prompt,
                user_message=user_message,
                temperature=0.8,
                max_tokens=1024
            )
            
            content = response['content']
            
            # Extract JSON from response using robust parser
            action = parse_json_robust(content)
            
            if action:
                # Display the proposed action with reasoning
                self.reasoning_display.show_action_proposal(
                    action=action,
                    reasoning=action.get('reasoning', 'No explicit reasoning provided')
                )
                
                return action
            
            # Fallback if parsing failed
            logger.warning(f"Could not parse action as JSON: {content}")
            
            self.reasoning_display.show_thought(
                f"Failed to parse LLM response as action JSON",
                thought_type="error",
                metadata={"raw_response": content[:200]}
            )
            
            return {
                "tool": "system",
                "message": "Failed to parse action. Please reformulate."
            }
                
        except Exception as e:
            logger.error(f"Error getting next action: {e}", exc_info=True)
            return {
                "tool": "system",
                "message": f"Error: {str(e)}"
            }
    
    # --- LEVEL 3: CODE ANALYSIS (using Qwen-coder) ---
    async def analyze_code(self, code: str, context: str = "") -> Dict[str, Any]:
        """
        Analyzes code for vulnerabilities
        Uses Qwen-coder for deep code analysis
        """
        if not self.is_initialized:
            return {"error": "AI not initialized"}
        
        system_prompt = """You are an expert code analyst specialized in security vulnerabilities.
Analyze the provided code and identify:
1. Security vulnerabilities
2. Potential exploits
3. Weaknesses in implementation
4. Recommended fixes

Provide detailed analysis with severity ratings."""

        user_message = f"""Context: {context}

Code to analyze:
```
{code}
```

Provide a comprehensive security analysis."""

        try:
            response = await self.orchestrator.execute_task(
                task_type='code_analysis',
                system_prompt=system_prompt,
                user_message=user_message,
                temperature=0.6,
                max_tokens=2048
            )
            
            return {
                "analysis": response['content'],
                "model_used": response['role']
            }
            
        except Exception as e:
            logger.error(f"Error analyzing code: {e}", exc_info=True)
            return {"error": str(e)}
    
    # --- LEVEL 4: PAYLOAD GENERATION (using Qwen-coder) ---
    async def generate_payload(
        self,
        vulnerability_type: str,
        target_info: Dict[str, Any],
        constraints: List[str] = None
    ) -> Dict[str, Any]:
        """
        Generates exploit payloads for a specific vulnerability
        Uses Qwen-coder for technical payload engineering
        """
        if not self.is_initialized:
            return {"error": "AI not initialized"}
        
        constraints_text = "\n".join(constraints) if constraints else "No specific constraints"
        
        system_prompt = f"""You are an expert payload engineer for penetration testing.
Generate safe, educational payloads for vulnerability testing.
Always include:
1. The payload code/string
2. How to use it
3. Expected result
4. Safety considerations"""

        user_message = f"""Generate a payload for:
Vulnerability Type: {vulnerability_type}
Target Information: {json.dumps(target_info, indent=2)}
Constraints: {constraints_text}

Provide multiple payload variants if applicable."""

        try:
            response = await self.orchestrator.execute_task(
                task_type='payload_generation',
                system_prompt=system_prompt,
                user_message=user_message,
                temperature=0.7,
                max_tokens=2048
            )
            
            return {
                "payloads": response['content'],
                "model_used": response['role']
            }
            
        except Exception as e:
            logger.error(f"Error generating payload: {e}", exc_info=True)
            return {"error": str(e)}
    
    # --- SPECIALIZED MODEL CALLS (using explicit model constants) ---
    
    async def call_code_specialist(
        self,
        prompt: str,
        context: str = "",
        temperature: float = 0.6,
        max_tokens: int = 2048,
        model_override: str = None
    ) -> Dict[str, Any]:
        """
        Call the code specialist model explicitly
        Uses CODE_MODEL constant to ensure correct model
        
        Args:
            prompt: The code analysis or generation prompt
            context: Additional context
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            model_override: Override model (should be CODE_MODEL)
            
        Returns:
            Response dictionary
        """
        if not self.is_initialized:
            return {"error": "AI not initialized"}
        
        # Use explicit model constant
        model_to_use = model_override if model_override else CODE_MODEL
        
        # Ensure the model override matches our approved model
        if model_override and model_override != CODE_MODEL:
            logger.warning(f"⚠️ Model override '{model_override}' does not match CODE_MODEL '{CODE_MODEL}'")
        
        system_prompt = f"""You are an expert code analyst and payload engineer for penetration testing.
{context}"""
        
        try:
            # Call the coder LLM directly with explicit model
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
            
            response = await self.orchestrator.call_llm(
                'coder',
                messages,
                temperature=temperature,
                max_tokens=max_tokens
            )
            
            return {
                "content": response['content'],
                "model_used": response['model'],
                "role": response['role']
            }
            
        except Exception as e:
            logger.error(f"Error calling code specialist: {e}", exc_info=True)
            return {"error": str(e)}
    
    async def call_reasoning_specialist(
        self,
        prompt: str,
        context: str = "",
        temperature: float = 0.7,
        max_tokens: int = 2048,
        model_override: str = None
    ) -> Dict[str, Any]:
        """
        Call the reasoning specialist model explicitly
        Uses REASONING_MODEL constant to ensure correct model
        
        Args:
            prompt: The reasoning or analysis prompt
            context: Additional context
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            model_override: Override model (should be REASONING_MODEL)
            
        Returns:
            Response dictionary
        """
        if not self.is_initialized:
            return {"error": "AI not initialized"}
        
        # Use explicit model constant
        model_to_use = model_override if model_override else REASONING_MODEL
        
        # Ensure the model override matches our approved model
        if model_override and model_override != REASONING_MODEL:
            logger.warning(f"⚠️ Model override '{model_override}' does not match REASONING_MODEL '{REASONING_MODEL}'")
        
        system_prompt = f"""You are an expert reasoning and vulnerability analysis specialist.
{context}"""
        
        try:
            # Call the vulnerability/reasoning LLM directly with explicit model
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
            
            response = await self.orchestrator.call_llm(
                'vulnerability',
                messages,
                temperature=temperature,
                max_tokens=max_tokens
            )
            
            return {
                "content": response['content'],
                "model_used": response['model'],
                "role": response['role']
            }
            
        except Exception as e:
            logger.error(f"Error calling reasoning specialist: {e}", exc_info=True)
            return {"error": str(e)}
    
    # --- COLLABORATIVE ANALYSIS ---
    async def collaborative_vulnerability_assessment(
        self,
        target: str,
        findings: List[Dict]
    ) -> Dict[str, Any]:
        """
        Performs collaborative analysis using all three LLMs
        Each provides its specialized perspective
        """
        if not self.is_initialized:
            return {"error": "AI not initialized"}
        
        findings_summary = json.dumps(findings, indent=2)
        context = f"Target: {target}\nFindings: {findings_summary}"
        
        strategic_q = f"Based on these findings, what should be our strategic priorities and overall risk assessment?"
        vulnerability_q = f"Analyze these vulnerabilities: which are most critical and what exploitation paths exist?"
        coding_q = f"For the technical findings, what payloads or exploits should we develop to validate them?"
        
        try:
            results = await self.orchestrator.collaborative_analysis(
                context=context,
                strategic_question=strategic_q,
                vulnerability_question=vulnerability_q,
                coding_question=coding_q
            )
            
            return {
                "strategic_assessment": results['strategic']['content'],
                "vulnerability_analysis": results['vulnerability']['content'],
                "technical_recommendations": results['coder']['content']
            }
            
        except Exception as e:
            logger.error(f"Error in collaborative assessment: {e}", exc_info=True)
            return {"error": str(e)}
    
    # --- AI-ENHANCED TRIAGE ---
    async def contextual_triage(
        self,
        finding: Dict,
        mission_context: str
    ) -> Dict[str, Any]:
        """
        AI-enhanced triage using the Reasoning LLM to re-assess vulnerability priority
        
        This method takes a vulnerability finding and mission context, then uses the
        Reasoning specialist to provide an AI-enhanced assessment of true priority,
        exploitability, and business impact.
        
        Args:
            finding: Vulnerability finding dictionary with type, description, severity, etc.
            mission_context: Mission context including target, goals, and constraints
            
        Returns:
            Enhanced finding with AI-triaged priority and assessment
        """
        if not self.is_initialized:
            return {"error": "AI not initialized"}
        
        logger.info(f"🧠 AI Triage: Analyzing {finding.get('type', 'unknown')} vulnerability")
        
        # Build context for the reasoning LLM
        finding_summary = json.dumps(finding, indent=2)
        
        triage_prompt = f"""You are an expert security analyst performing vulnerability triage.

MISSION CONTEXT:
{mission_context}

VULNERABILITY FINDING:
{finding_summary}

Your task is to re-assess this vulnerability's TRUE PRIORITY considering:
1. The specific mission context and target
2. Real-world exploitability (not just theoretical severity)
3. Business impact in this specific scenario
4. Likelihood of successful exploitation
5. Effort required vs potential gain

Provide your assessment as JSON with this EXACT structure:
{{
  "priority": "P0-Critical|P1-High|P2-Medium|P3-Low|P4-Info",
  "risk_score": 0.0-10.0,
  "exploitability": "trivial|easy|moderate|difficult|very_difficult",
  "business_impact": "critical|high|medium|low|minimal",
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation of your assessment",
  "recommended_actions": ["action1", "action2"],
  "should_verify": true|false,
  "verification_priority": 1-10
}}

Respond with ONLY the JSON, no additional text."""
        
        try:
            # Call the reasoning specialist for intelligent triage
            response = await self.call_reasoning_specialist(
                prompt=triage_prompt,
                context="Vulnerability triage and prioritization",
                temperature=0.6,  # Lower temperature for more focused analysis
                max_tokens=1024
            )
            
            content = response.get('content', '')
            
            # Extract JSON from response using robust parser
            triage_result = parse_json_robust(content)
            
            if triage_result:
                # Enhance the original finding with AI triage
                enhanced_finding = {
                    **finding,
                    'ai_triage': triage_result,
                    'ai_triaged': True,
                    'triage_model': response.get('model_used', 'unknown')
                }
                
                logger.info(f"✅ AI Triage complete: {triage_result.get('priority', 'unknown')} "
                          f"(confidence: {triage_result.get('confidence', 0.0)})")
                
                # Show triage reasoning in display
                self.reasoning_display.show_thought(
                    f"AI triage assessed {finding.get('type')} as {triage_result.get('priority')}",
                    thought_type="decision",
                    metadata={
                        "original_severity": finding.get('severity', 'unknown'),
                        "ai_priority": triage_result.get('priority'),
                        "risk_score": triage_result.get('risk_score'),
                        "exploitability": triage_result.get('exploitability'),
                        "reasoning": triage_result.get('reasoning', '')[:100]
                    }
                )
                
                return enhanced_finding
            
            # If JSON parsing fails, return original finding with error note
            logger.warning("Failed to parse AI triage JSON response")
            return {
                **finding,
                'ai_triage': {
                    'error': 'Failed to parse triage response',
                    'raw_response': content[:200]
                },
                'ai_triaged': False
            }
            
        except Exception as e:
            logger.error(f"Error in contextual triage: {e}", exc_info=True)
            return {
                **finding,
                'ai_triage': {
                    'error': str(e)
                },
                'ai_triaged': False
            }
    
    # --- DEEP THINK VERIFICATION (TASK 1) ---
    async def verify_finding_with_reasoning(
        self,
        finding: Dict,
        target_url: str
    ) -> Optional[Dict]:
        """
        Devil's Advocate verification loop - Reasoning Model critiques findings
        to drastically reduce hallucinations and false positives.
        
        Args:
            finding: Vulnerability finding dictionary
            target_url: Target URL where vulnerability was found
            
        Returns:
            Finding if valid, None if hallucination detected
        """
        if not self.is_initialized:
            logger.warning("AI not initialized for verification")
            return finding
        
        logger.info(f"🔍 Deep Think: Verifying {finding.get('type', 'unknown')} finding...")
        
        # Construct comprehensive prompt for the Reasoning LLM
        finding_summary = json.dumps(finding, indent=2)
        
        verification_prompt = f"""You are a Senior Security Engineer reviewing a junior researcher's vulnerability report.
Your role is to act as a "Devil's Advocate" and critically assess whether this is a legitimate finding or a false positive.

TARGET URL: {target_url}

REPORTED FINDING:
{finding_summary}

CRITICAL ANALYSIS REQUIRED:
As a senior expert, you must scrutinize this finding for common false positives:
1. **404 Errors Masquerading as Vulnerabilities**: Is this just a 404/403 page being misinterpreted?
2. **Generic WAF Blocks**: Is this a WAF/security product blocking the request rather than an actual vulnerability?
3. **Expected Security Responses**: Is this a normal security control working as intended?
4. **Misinterpreted Error Messages**: Are error messages being confused with exploitable conditions?
5. **Context Confusion**: Does the evidence actually prove the vulnerability claim?
6. **Insufficient Evidence**: Is there concrete proof, or just speculation?

RESPOND WITH JSON ONLY:
{{
  "is_hallucination": true|false,
  "confidence_score": 0-100,
  "reasoning": "Detailed explanation of why this is or isn't a hallucination/false positive. Include specific technical reasoning."
}}

Be skeptical and thorough. Only mark is_hallucination=false if you have high confidence this is a real vulnerability."""

        try:
            # Call the vulnerability/reasoning specialist
            response = await self.call_reasoning_specialist(
                prompt=verification_prompt,
                context="Devil's Advocate verification of security findings",
                temperature=0.6,  # Lower temperature for more focused analysis
                max_tokens=1024
            )
            
            content = response.get('content', '')
            
            # Extract JSON from response using robust parser
            verification = parse_json_robust(content)
            
            if verification:
                is_hallucination = verification.get('is_hallucination', False)
                confidence = verification.get('confidence_score', 0)
                reasoning = verification.get('reasoning', 'No reasoning provided')
                
                logger.info(f"📊 Verification: hallucination={is_hallucination}, confidence={confidence}")
                logger.info(f"💭 Reasoning: {reasoning[:200]}...")
                
                # Show verification reasoning
                self.reasoning_display.show_thought(
                    f"Deep Think verification: {'REJECTED' if is_hallucination else 'ACCEPTED'} (confidence: {confidence}%)",
                    thought_type="verification",
                    metadata={
                        "finding_type": finding.get('type'),
                        "is_hallucination": is_hallucination,
                        "confidence_score": confidence,
                        "reasoning": reasoning[:200]
                    }
                )
                
                # If hallucination detected, log warning and return None
                if is_hallucination:
                    logger.warning(f"⚠️ HALLUCINATION DETECTED: {finding.get('type')} at {target_url}")
                    logger.warning(f"   Reason: {reasoning}")
                    return None
                
                # Valid finding - return it
                logger.info(f"✅ Finding verified as legitimate")
                return finding
            
            # If JSON parsing fails, be conservative and accept the finding with warning
            logger.warning("Could not parse verification JSON, accepting finding with warning")
            return finding
            
        except Exception as e:
            logger.error(f"Error during Deep Think verification: {e}", exc_info=True)
            # On error, be conservative and return the finding
            return finding
    
    # --- MULTIMODAL VISUAL ANALYSIS ---
    async def analyze_visuals(
        self,
        image_path: str,
        text_prompt: str
    ) -> str:
        """
        Analyze visual content (screenshots, UI images) using the Visual LLM
        
        This method provides the "Eyes" capability - it processes visual information
        and returns a neutral text description that separates perception from action.
        The visual analysis is internal and provides context for decision-making.
        
        Args:
            image_path: Path to the image file to analyze
            text_prompt: What to analyze or look for in the image
            
        Returns:
            Text description of the visual analysis
        """
        if not self.is_initialized:
            return "Error: AI not initialized"
        
        logger.info(f"👁️ Analyzing visual content: {image_path}")
        
        # Show reasoning about visual analysis
        self.reasoning_display.show_thought(
            "Initiating visual analysis of screenshot/image",
            thought_type="analysis",
            metadata={
                "image_path": image_path,
                "prompt": text_prompt[:100]
            }
        )
        
        try:
            # Call the orchestrator's multimodal task executor
            response = await self.orchestrator.execute_multimodal_task(
                text_prompt=text_prompt,
                image_path=image_path
            )
            
            if 'error' in response:
                error_msg = f"Visual analysis failed: {response['error']}"
                logger.error(error_msg)
                
                self.reasoning_display.show_thought(
                    error_msg,
                    thought_type="error",
                    metadata={"image_path": image_path}
                )
                
                return error_msg
            
            content = response.get('content', '')
            
            logger.info(f"✅ Visual analysis complete")
            
            # Show the visual analysis result
            self.reasoning_display.show_thought(
                "Visual analysis completed successfully",
                thought_type="observation",
                metadata={
                    "image_path": image_path,
                    "analysis_length": len(content),
                    "model": response.get('model', 'unknown')
                }
            )
            
            return content
            
        except Exception as e:
            error_msg = f"Error analyzing visuals: {str(e)}"
            logger.error(error_msg, exc_info=True)
            
            self.reasoning_display.show_thought(
                error_msg,
                thought_type="error",
                metadata={"image_path": image_path}
            )
            
            return error_msg
    
    # --- BLACKBOARD MEMORY: FACT EXTRACTION ---
    async def extract_facts_from_output(
        self,
        tool_name: str,
        tool_output: Dict[str, Any],
        mission_context: str = ""
    ) -> None:
        """
        Extract facts, goals, and discarded vectors from tool output
        and update the mission blackboard.
        
        This method is called after EVERY tool execution to continuously
        update the blackboard with new knowledge.
        
        Args:
            tool_name: Name of the tool that was executed
            tool_output: Output from the tool execution
            mission_context: Current mission context
        """
        if not self.is_initialized:
            logger.warning("AI not initialized for fact extraction")
            return
        
        logger.info(f"🧠 Extracting facts from {tool_name} output...")
        
        # Format tool output for analysis
        output_summary = json.dumps(tool_output, indent=2)[:2000]  # First 2000 chars
        
        extraction_prompt = f"""You are analyzing the output of a security testing tool to extract key information.

TOOL EXECUTED: {tool_name}
MISSION CONTEXT: {mission_context}

TOOL OUTPUT:
{output_summary}

Your task is to extract and categorize information into FOUR categories:

1. **VERIFIED FACTS**: Confirmed, concrete discoveries (e.g., "Port 443 is open", "WordPress 5.8 detected", "Admin panel found at /wp-admin")
2. **PENDING GOALS**: New objectives or targets to investigate (e.g., "Test admin panel for weak credentials", "Enumerate WordPress plugins")
3. **DISCARDED VECTORS**: Attack paths that failed or are not viable (e.g., "SQL injection in search parameter - WAF blocked", "Port 22 filtered")
4. **RELATIONSHIPS**: Knowledge graph relationships in the format [source, relation, target] (e.g., ["admin.example.com", "HAS_VULN", "SQLi"], ["Port 443", "EXPOSES", "Web Server"], ["SQLi", "ALLOWS_ACTION", "Dump DB"])

RELATIONSHIP TYPES:
- HAS_VULN: Entity has a vulnerability (e.g., "admin.example.com" HAS_VULN "SQLi")
- EXPOSES: Port/service exposes something (e.g., "Port 443" EXPOSES "HTTPS Service")
- RUNS: Server runs software (e.g., "example.com" RUNS "WordPress 5.8")
- ALLOWS_ACTION: Vulnerability allows action (e.g., "SQLi" ALLOWS_ACTION "Read Database")
- LEADS_TO: One thing leads to another (e.g., "Web Server" LEADS_TO "Admin Panel")
- PROTECTED_BY: Protected by security control (e.g., "Login" PROTECTED_BY "WAF")

IMPORTANT RULES:
- Only extract CONCRETE information from the actual output
- Do NOT speculate or invent information
- Do NOT include generic advice or best practices
- Each item should be specific and actionable
- Relationships should represent actual connections found in the output
- If the output shows an error or failure, categorize it as a discarded vector
- If the output is successful, extract facts, goals, and relationships from the results

Respond with JSON ONLY:
{{
  "verified_facts": ["fact1", "fact2", ...],
  "pending_goals": ["goal1", "goal2", ...],
  "discarded_vectors": ["vector1", "vector2", ...],
  "relationships": [
    ["source1", "RELATION_TYPE", "target1"],
    ["source2", "RELATION_TYPE", "target2"]
  ]
}}

If there's nothing to extract in a category, use an empty list []."""

        try:
            # Call the reasoning specialist for fact extraction
            response = await self.call_reasoning_specialist(
                prompt=extraction_prompt,
                context="Fact extraction from security tool output",
                temperature=0.5,  # Lower temperature for focused extraction
                max_tokens=1024
            )
            
            content = response.get('content', '')
            
            # Extract JSON from response - use robust parsing
            extraction = parse_json_robust(content)
            
            if extraction:
                verified_facts = extraction.get('verified_facts', [])
                pending_goals = extraction.get('pending_goals', [])
                discarded_vectors = extraction.get('discarded_vectors', [])
                relationships = extraction.get('relationships', [])
                
                # Update blackboard
                for fact in verified_facts:
                    self.blackboard.add_fact(fact)
                
                for goal in pending_goals:
                    self.blackboard.add_goal(goal)
                
                for vector in discarded_vectors:
                    self.blackboard.discard_vector(vector)
                
                # Add relationships to knowledge graph
                for rel in relationships:
                    if len(rel) >= 3:
                        source, relation, target = rel[0], rel[1], rel[2]
                        metadata = {'tool': tool_name, 'context': mission_context[:100]}
                        self.blackboard.add_relationship(source, relation, target, **metadata)
                
                logger.info(f"✅ Extracted: {len(verified_facts)} facts, "
                          f"{len(pending_goals)} goals, {len(discarded_vectors)} discarded vectors, "
                          f"{len(relationships)} relationships")
                
                # Show extraction result
                self.reasoning_display.show_thought(
                    f"Blackboard updated from {tool_name} output",
                    thought_type="learning",
                    metadata={
                        "tool": tool_name,
                        "facts_added": len(verified_facts),
                        "goals_added": len(pending_goals),
                        "vectors_discarded": len(discarded_vectors),
                        "relationships_added": len(relationships)
                    }
                )
            else:
                logger.warning("Could not parse fact extraction JSON")
                
        except Exception as e:
            logger.error(f"Error extracting facts: {e}", exc_info=True)
