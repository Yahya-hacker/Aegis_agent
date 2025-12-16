# agents/memory.py
# --- Mission Memory Systems for Aegis AI ---
# 
# This module contains the memory management classes that were extracted from
# enhanced_ai_core.py to follow the Single Responsibility Principle and 
# make the codebase easier to maintain, test, and extend.

import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
import networkx as nx

logger = logging.getLogger(__name__)


class MissionBlackboard:
    """
    Persistent mission blackboard memory system with Knowledge Graph support.
    Stores verified facts, pending goals, and discarded attack vectors across the session.
    
    This implements a "blackboard architecture" where:
    - verified_facts: Ground truths discovered and confirmed
    - pending_goals: Objectives to achieve, prioritized
    - discarded_vectors: Attack paths already tried and failed
    - knowledge_graph: NetworkX DiGraph storing relationships between entities
    - domain_context: Current operation domain (Web, Binary, Network, Crypto, Forensics)
    """
    
    # Valid domain contexts for CTF/Red Team operations
    DOMAIN_CONTEXTS = ["Web", "Binary", "Network", "Crypto", "Forensics", "General"]
    
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
        self.domain_context: str = "General"  # Current operation domain
        self.blackboard_file = Path(f"data/blackboard_{self.mission_id}.json")
        self.graph_file = Path(f"data/graph_{self.mission_id}.graphml")
        
        # Load existing blackboard if it exists
        self._load()
        self._load_graph()
    
    def set_domain_context(self, context: str) -> None:
        """
        Set the current domain context for the mission.
        
        This affects which LLM is prioritized for tasks:
        - "Binary" -> Prioritize Coder LLM (Qwen) for exploit scripts
        - "Crypto" -> Prioritize Reasoning LLM (DeepSeek) for mathematical analysis
        - "Network" -> Prioritize Reasoning LLM for protocol analysis
        - "Web" -> Balanced approach
        - "Forensics" -> Prioritize Reasoning LLM for evidence analysis
        
        Args:
            context: One of "Web", "Binary", "Network", "Crypto", "Forensics", "General"
        """
        if context not in self.DOMAIN_CONTEXTS:
            logger.warning(f"Invalid domain context '{context}', using 'General'")
            context = "General"
        
        self.domain_context = context
        self._save()
        logger.info(f"🎯 Domain context set to: {context}")
    
    def get_domain_context(self) -> str:
        """Get the current domain context."""
        return self.domain_context
    
    def _load(self) -> None:
        """Load blackboard from disk if it exists"""
        if self.blackboard_file.exists():
            try:
                with open(self.blackboard_file, 'r') as f:
                    data = json.load(f)
                    self.verified_facts = data.get('verified_facts', [])
                    self.pending_goals = data.get('pending_goals', [])
                    self.discarded_vectors = data.get('discarded_vectors', [])
                    self.domain_context = data.get('domain_context', 'General')
                    logger.info(f"📋 Loaded blackboard: {len(self.verified_facts)} facts, "
                              f"{len(self.pending_goals)} goals, {len(self.discarded_vectors)} discarded vectors, "
                              f"domain={self.domain_context}")
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
                'mission_id': self.mission_id,
                'domain_context': self.domain_context
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
                        except (json.JSONDecodeError, ValueError, TypeError) as e:
                            logger.debug(f"Failed to parse artifacts JSON for node {node}: {e}")
                            pass
                    if 'state' in node_data and isinstance(node_data['state'], str):
                        try:
                            self.graph.nodes[node]['state'] = json.loads(node_data['state'])
                        except (json.JSONDecodeError, ValueError, TypeError) as e:
                            logger.debug(f"Failed to parse state JSON for node {node}: {e}")
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
                    avg_weight = sum(float(data.get('weight', 1)) for _, _, data in incoming) / len(incoming)
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
