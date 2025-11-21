# tools/logic_mapper.py
# --- VERSION 7.5 - NetworkX Business Logic State Mapper ---
"""
Business Logic Mapper with NetworkX Graph Support

Creates directed graphs of application business logic states and transitions.
This enables:
1. Automated discovery of state transition vulnerabilities
2. Path finding for privilege escalation
3. State bypass detection
4. Workflow analysis for logic flaws

Example: Register -> Verify Email -> Login -> Access Dashboard -> Admin Panel
The graph reveals: Can we skip "Verify Email"? Can we reach "Admin Panel" without proper authentication?
"""

import logging
import networkx as nx
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import json

logger = logging.getLogger(__name__)


class LogicMapper:
    """
    Creates and analyzes NetworkX graphs of business logic states.
    
    This mapper builds state transition graphs that can be analyzed for:
    - Missing authorization checks
    - State bypass vulnerabilities
    - Privilege escalation paths
    - Workflow logic flaws
    """
    
    def __init__(self, mission_id: Optional[str] = None):
        """
        Initialize the logic mapper.
        
        Args:
            mission_id: Optional mission identifier for persistence
        """
        self.mission_id = mission_id or "default"
        self.graph = nx.DiGraph()  # Directed graph for state transitions
        self.entry_state = "Entry_Point"
        self.target_states: List[str] = []  # High-value targets (e.g., "Admin Panel")
        
        # Persistence
        self.graph_file = Path(f"data/logic_map_{self.mission_id}.graphml")
        
        # Initialize entry point
        self.graph.add_node(
            self.entry_state,
            state_type="entry",
            privilege_level="none",
            description="Application entry point (unauthenticated)"
        )
        
        logger.info(f"[LogicMapper] Initialized for mission: {self.mission_id}")
    
    def add_state(
        self,
        state_name: str,
        state_type: str = "normal",
        privilege_level: str = "user",
        description: str = "",
        **metadata
    ) -> None:
        """
        Add a business logic state to the graph.
        
        Args:
            state_name: Unique name for the state (e.g., "Login Page", "Admin Dashboard")
            state_type: Type of state (entry, normal, privileged, target)
            privilege_level: Required privilege (none, user, admin, root)
            description: Human-readable description
            **metadata: Additional state metadata
        
        Example:
            mapper.add_state(
                "Admin Dashboard",
                state_type="privileged",
                privilege_level="admin",
                description="Administrative control panel",
                url="/admin/dashboard"
            )
        """
        self.graph.add_node(
            state_name,
            state_type=state_type,
            privilege_level=privilege_level,
            description=description,
            **metadata
        )
        
        # Track target states (high-value)
        if state_type in ["privileged", "target"]:
            if state_name not in self.target_states:
                self.target_states.append(state_name)
        
        logger.info(f"[LogicMapper] Added state: {state_name} ({privilege_level})")
    
    def add_transition(
        self,
        from_state: str,
        to_state: str,
        action: str,
        required_auth: bool = False,
        required_role: Optional[str] = None,
        endpoint: Optional[str] = None,
        **metadata
    ) -> None:
        """
        Add a state transition (edge) to the graph.
        
        Args:
            from_state: Source state
            to_state: Destination state
            action: Action that causes the transition (e.g., "Submit login form")
            required_auth: Whether authentication is required
            required_role: Required role/privilege for transition
            endpoint: API endpoint or URL for this transition
            **metadata: Additional transition metadata
        
        Example:
            mapper.add_transition(
                "Login Page",
                "User Dashboard",
                action="Submit valid credentials",
                required_auth=True,
                required_role="user",
                endpoint="/api/login"
            )
        """
        # Ensure both states exist
        if from_state not in self.graph.nodes():
            self.add_state(from_state)
        
        if to_state not in self.graph.nodes():
            self.add_state(to_state)
        
        # Add edge with transition details
        self.graph.add_edge(
            from_state,
            to_state,
            action=action,
            required_auth=required_auth,
            required_role=required_role,
            endpoint=endpoint,
            **metadata
        )
        
        logger.info(f"[LogicMapper] Added transition: {from_state} --[{action}]--> {to_state}")
    
    def find_paths_to_target(
        self,
        target_state: str,
        source_state: Optional[str] = None,
        max_length: int = 10
    ) -> List[List[str]]:
        """
        Find all paths from source to target state.
        
        This is crucial for finding privilege escalation paths and state bypasses.
        
        Args:
            target_state: Target state to reach (e.g., "Admin Panel")
            source_state: Starting state (defaults to entry point)
            max_length: Maximum path length to prevent infinite loops
        
        Returns:
            List of paths, where each path is a list of state names
        
        Example:
            paths = mapper.find_paths_to_target("Admin Dashboard")
            # Returns: [
            #     ["Entry_Point", "Login", "User Dashboard", "Admin Dashboard"],
            #     ["Entry_Point", "Register", "Login", "User Dashboard", "Admin Dashboard"]
            # ]
        """
        if source_state is None:
            source_state = self.entry_state
        
        if target_state not in self.graph.nodes():
            logger.warning(f"[LogicMapper] Target state '{target_state}' not found in graph")
            return []
        
        if source_state not in self.graph.nodes():
            logger.warning(f"[LogicMapper] Source state '{source_state}' not found in graph")
            return []
        
        try:
            # Find all simple paths (no cycles)
            paths = list(nx.all_simple_paths(
                self.graph,
                source=source_state,
                target=target_state,
                cutoff=max_length
            ))
            
            logger.info(f"[LogicMapper] Found {len(paths)} path(s) from '{source_state}' to '{target_state}'")
            return paths
        
        except nx.NetworkXNoPath:
            logger.info(f"[LogicMapper] No path found from '{source_state}' to '{target_state}'")
            return []
        except Exception as e:
            logger.error(f"[LogicMapper] Error finding paths: {e}")
            return []
    
    def find_bypass_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Analyze graph for potential state bypass vulnerabilities.
        
        Detects:
        1. Paths to privileged states without authentication
        2. Missing authorization checks in transitions
        3. State sequences that skip critical validation steps
        
        Returns:
            List of potential vulnerabilities
        """
        vulnerabilities = []
        
        # Check each target state
        for target in self.target_states:
            target_data = self.graph.nodes[target]
            required_privilege = target_data.get("privilege_level", "user")
            
            # Find all paths from entry to target
            paths = self.find_paths_to_target(target)
            
            for path in paths:
                # Analyze each edge in the path
                vulnerability_indicators = []
                
                for i in range(len(path) - 1):
                    from_state = path[i]
                    to_state = path[i + 1]
                    
                    # Get edge data
                    if self.graph.has_edge(from_state, to_state):
                        edge_data = self.graph.edges[from_state, to_state]
                        
                        # Check if transition requires auth
                        requires_auth = edge_data.get("required_auth", False)
                        required_role = edge_data.get("required_role")
                        
                        # Flag if no auth required for privileged transition
                        if not requires_auth and required_privilege in ["admin", "root"]:
                            vulnerability_indicators.append({
                                "transition": f"{from_state} -> {to_state}",
                                "issue": "No authentication required",
                                "severity": "HIGH"
                            })
                        
                        # Flag if role requirement is weaker than target privilege
                        if required_role and required_role != required_privilege:
                            vulnerability_indicators.append({
                                "transition": f"{from_state} -> {to_state}",
                                "issue": f"Role mismatch: requires '{required_role}' but target needs '{required_privilege}'",
                                "severity": "MEDIUM"
                            })
                
                if vulnerability_indicators:
                    vulnerabilities.append({
                        "target_state": target,
                        "path": path,
                        "required_privilege": required_privilege,
                        "indicators": vulnerability_indicators,
                        "severity": max([v["severity"] for v in vulnerability_indicators], default="LOW")
                    })
        
        logger.info(f"[LogicMapper] Found {len(vulnerabilities)} potential bypass vulnerabilities")
        return vulnerabilities
    
    def find_shortest_escalation_path(
        self,
        current_privilege: str = "none",
        target_privilege: str = "admin"
    ) -> Optional[Tuple[List[str], int]]:
        """
        Find the shortest path for privilege escalation.
        
        Args:
            current_privilege: Current privilege level
            target_privilege: Target privilege level to achieve
        
        Returns:
            Tuple of (path, path_length) or None if no path exists
        """
        # Find states matching current and target privileges
        current_states = [
            node for node, data in self.graph.nodes(data=True)
            if data.get("privilege_level") == current_privilege
        ]
        
        target_states = [
            node for node, data in self.graph.nodes(data=True)
            if data.get("privilege_level") == target_privilege
        ]
        
        if not current_states:
            current_states = [self.entry_state]
        
        shortest_path = None
        shortest_length = float('inf')
        
        # Find shortest path across all source-target combinations
        for source in current_states:
            for target in target_states:
                try:
                    path = nx.shortest_path(self.graph, source, target)
                    if len(path) < shortest_length:
                        shortest_path = path
                        shortest_length = len(path)
                except nx.NetworkXNoPath:
                    continue
        
        if shortest_path:
            logger.info(f"[LogicMapper] Shortest escalation path ({shortest_length} steps): {' -> '.join(shortest_path)}")
            return shortest_path, shortest_length
        
        logger.info(f"[LogicMapper] No escalation path found from '{current_privilege}' to '{target_privilege}'")
        return None
    
    def get_graph_summary(self) -> str:
        """
        Get a human-readable summary of the logic graph.
        
        Returns:
            Formatted string with graph statistics
        """
        num_states = self.graph.number_of_nodes()
        num_transitions = self.graph.number_of_edges()
        num_targets = len(self.target_states)
        
        summary = [
            "=== BUSINESS LOGIC MAP ===",
            f"States: {num_states}",
            f"Transitions: {num_transitions}",
            f"Target States: {num_targets}",
            ""
        ]
        
        if self.target_states:
            summary.append("High-Value Targets:")
            for target in self.target_states:
                target_data = self.graph.nodes[target]
                privilege = target_data.get("privilege_level", "unknown")
                summary.append(f"  - {target} (requires: {privilege})")
            summary.append("")
        
        # Find states by privilege level
        privilege_counts = {}
        for node, data in self.graph.nodes(data=True):
            priv = data.get("privilege_level", "unknown")
            privilege_counts[priv] = privilege_counts.get(priv, 0) + 1
        
        if privilege_counts:
            summary.append("States by Privilege:")
            for priv, count in sorted(privilege_counts.items()):
                summary.append(f"  - {priv}: {count}")
        
        summary.append("=" * 27)
        
        return "\n".join(summary)
    
    def visualize_path(self, path: List[str]) -> str:
        """
        Generate ASCII visualization of a path through the graph.
        
        Args:
            path: List of state names forming a path
        
        Returns:
            String representation of the path with actions
        """
        if not path:
            return "Empty path"
        
        visualization = ["Path Visualization:", ""]
        
        for i, state in enumerate(path):
            # Add state
            state_data = self.graph.nodes.get(state, {})
            privilege = state_data.get("privilege_level", "unknown")
            visualization.append(f"  [{i}] {state} (privilege: {privilege})")
            
            # Add transition to next state
            if i < len(path) - 1:
                next_state = path[i + 1]
                if self.graph.has_edge(state, next_state):
                    edge_data = self.graph.edges[state, next_state]
                    action = edge_data.get("action", "unknown action")
                    requires_auth = edge_data.get("required_auth", False)
                    
                    auth_marker = "[AUTH]" if requires_auth else ""
                    visualization.append(f"      |")
                    visualization.append(f"      +--[{action}] {auth_marker}")
                    visualization.append(f"      |")
        
        return "\n".join(visualization)
    
    def save(self) -> None:
        """Save the logic graph to disk."""
        try:
            self.graph_file.parent.mkdir(exist_ok=True, parents=True)
            nx.write_graphml(self.graph, str(self.graph_file))
            logger.info(f"[LogicMapper] Saved graph to {self.graph_file}")
        except Exception as e:
            logger.error(f"[LogicMapper] Failed to save graph: {e}")
    
    def load(self) -> bool:
        """
        Load logic graph from disk.
        
        Returns:
            True if successful, False otherwise
        """
        if not self.graph_file.exists():
            logger.info(f"[LogicMapper] No saved graph found at {self.graph_file}")
            return False
        
        try:
            self.graph = nx.read_graphml(str(self.graph_file))
            
            # Reconstruct target states list
            self.target_states = [
                node for node, data in self.graph.nodes(data=True)
                if data.get("state_type") in ["privileged", "target"]
            ]
            
            logger.info(f"[LogicMapper] Loaded graph: {self.graph.number_of_nodes()} states, "
                       f"{self.graph.number_of_edges()} transitions")
            return True
        except Exception as e:
            logger.error(f"[LogicMapper] Failed to load graph: {e}")
            return False
    
    def export_to_dict(self) -> Dict[str, Any]:
        """
        Export graph to dictionary format for JSON serialization.
        
        Returns:
            Dictionary representation of the graph
        """
        export_data = {
            "mission_id": self.mission_id,
            "entry_state": self.entry_state,
            "target_states": self.target_states,
            "states": [],
            "transitions": []
        }
        
        # Export states
        for node, data in self.graph.nodes(data=True):
            state_data = {"name": node}
            state_data.update(data)
            export_data["states"].append(state_data)
        
        # Export transitions
        for from_state, to_state, data in self.graph.edges(data=True):
            transition_data = {
                "from": from_state,
                "to": to_state
            }
            transition_data.update(data)
            export_data["transitions"].append(transition_data)
        
        return export_data


# Singleton instance
_logic_mapper_instance = None


def get_logic_mapper(mission_id: Optional[str] = None) -> LogicMapper:
    """
    Get or create the singleton logic mapper instance.
    
    Args:
        mission_id: Optional mission identifier
    
    Returns:
        LogicMapper instance
    """
    global _logic_mapper_instance
    
    if _logic_mapper_instance is None:
        _logic_mapper_instance = LogicMapper(mission_id)
    
    return _logic_mapper_instance
