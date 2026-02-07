"""
Nexus v2.0 - Knowledge Graph
============================

Graph-based representation of:
- Target infrastructure
- Attack paths
- Vulnerability relationships
"""

import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class NodeType(str, Enum):
    """Types of nodes in the knowledge graph."""
    TARGET = "target"
    SUBDOMAIN = "subdomain"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    VULNERABILITY = "vulnerability"
    TECHNOLOGY = "technology"
    PORT = "port"
    SERVICE = "service"
    CREDENTIAL = "credential"
    FILE = "file"


class EdgeType(str, Enum):
    """Types of edges in the knowledge graph."""
    HAS_SUBDOMAIN = "has_subdomain"
    HAS_ENDPOINT = "has_endpoint"
    HAS_PARAMETER = "has_parameter"
    HAS_VULNERABILITY = "has_vulnerability"
    RUNS_ON = "runs_on"
    CONNECTS_TO = "connects_to"
    LEADS_TO = "leads_to"
    EXPOSES = "exposes"
    AUTHENTICATED_BY = "authenticated_by"


@dataclass
class Node:
    """A node in the knowledge graph."""
    id: str
    node_type: NodeType
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.node_type.value,
            "label": self.label,
            "properties": self.properties,
        }


@dataclass
class Edge:
    """An edge in the knowledge graph."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    properties: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source_id,
            "target": self.target_id,
            "type": self.edge_type.value,
            "properties": self.properties,
        }


class KnowledgeGraph:
    """
    In-memory knowledge graph for attack surface mapping.
    
    Used for:
    - Visualizing target infrastructure
    - Finding attack paths
    - Prioritizing targets
    """
    
    def __init__(self):
        self._nodes: Dict[str, Node] = {}
        self._edges: List[Edge] = []
        self._adjacency: Dict[str, Set[str]] = defaultdict(set)
        self._reverse_adjacency: Dict[str, Set[str]] = defaultdict(set)
    
    # ==================== Node Operations ====================
    
    def add_node(
        self,
        node_id: str,
        node_type: NodeType,
        label: str,
        properties: Dict[str, Any] = None
    ) -> Node:
        """Add a node to the graph."""
        node = Node(
            id=node_id,
            node_type=node_type,
            label=label,
            properties=properties or {},
        )
        self._nodes[node_id] = node
        return node
    
    def get_node(self, node_id: str) -> Optional[Node]:
        """Get a node by ID."""
        return self._nodes.get(node_id)
    
    def get_nodes_by_type(self, node_type: NodeType) -> List[Node]:
        """Get all nodes of a specific type."""
        return [n for n in self._nodes.values() if n.node_type == node_type]
    
    def update_node(self, node_id: str, properties: Dict[str, Any]):
        """Update node properties."""
        if node_id in self._nodes:
            self._nodes[node_id].properties.update(properties)
    
    def remove_node(self, node_id: str):
        """Remove a node and its edges."""
        if node_id in self._nodes:
            del self._nodes[node_id]
            
            # Remove edges
            self._edges = [
                e for e in self._edges 
                if e.source_id != node_id and e.target_id != node_id
            ]
            
            # Update adjacency
            del self._adjacency[node_id]
            del self._reverse_adjacency[node_id]
            
            for adj in self._adjacency.values():
                adj.discard(node_id)
            for adj in self._reverse_adjacency.values():
                adj.discard(node_id)
    
    # ==================== Edge Operations ====================
    
    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        properties: Dict[str, Any] = None
    ) -> Optional[Edge]:
        """Add an edge between two nodes."""
        if source_id not in self._nodes or target_id not in self._nodes:
            logger.warning(f"Cannot add edge: nodes not found")
            return None
        
        edge = Edge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            properties=properties or {},
        )
        
        self._edges.append(edge)
        self._adjacency[source_id].add(target_id)
        self._reverse_adjacency[target_id].add(source_id)
        
        return edge
    
    def get_edges(
        self,
        source_id: str = None,
        target_id: str = None,
        edge_type: EdgeType = None
    ) -> List[Edge]:
        """Get edges with optional filters."""
        edges = self._edges
        
        if source_id:
            edges = [e for e in edges if e.source_id == source_id]
        if target_id:
            edges = [e for e in edges if e.target_id == target_id]
        if edge_type:
            edges = [e for e in edges if e.edge_type == edge_type]
        
        return edges
    
    def get_neighbors(self, node_id: str) -> List[Node]:
        """Get all neighbors of a node."""
        neighbor_ids = self._adjacency.get(node_id, set())
        return [self._nodes[nid] for nid in neighbor_ids if nid in self._nodes]
    
    # ==================== Attack Path Analysis ====================
    
    def find_attack_paths(
        self,
        start_id: str,
        end_type: NodeType = NodeType.VULNERABILITY,
        max_depth: int = 5
    ) -> List[List[str]]:
        """
        Find all paths from start node to nodes of end type.
        
        Args:
            start_id: Starting node ID
            end_type: Target node type
            max_depth: Maximum path length
        
        Returns:
            List of paths (each path is list of node IDs)
        """
        paths = []
        
        def dfs(current_id: str, path: List[str], visited: Set[str]):
            if len(path) > max_depth:
                return
            
            current_node = self._nodes.get(current_id)
            if not current_node:
                return
            
            if current_node.node_type == end_type:
                paths.append(path.copy())
                return
            
            for neighbor_id in self._adjacency.get(current_id, []):
                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    path.append(neighbor_id)
                    dfs(neighbor_id, path, visited)
                    path.pop()
                    visited.remove(neighbor_id)
        
        visited = {start_id}
        dfs(start_id, [start_id], visited)
        
        return paths
    
    def find_shortest_path(
        self,
        start_id: str,
        end_id: str
    ) -> Optional[List[str]]:
        """Find shortest path between two nodes using BFS."""
        from collections import deque
        
        if start_id not in self._nodes or end_id not in self._nodes:
            return None
        
        queue = deque([(start_id, [start_id])])
        visited = {start_id}
        
        while queue:
            current, path = queue.popleft()
            
            if current == end_id:
                return path
            
            for neighbor in self._adjacency.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        
        return None
    
    def get_high_value_targets(self) -> List[Node]:
        """
        Identify high-value targets based on graph analysis.
        
        Criteria:
        - Nodes with many vulnerabilities
        - Nodes on multiple attack paths
        - Nodes with sensitive properties
        """
        scores = {}
        
        for node_id, node in self._nodes.items():
            score = 0
            
            # Count connected vulnerabilities
            vuln_edges = [
                e for e in self._edges 
                if e.source_id == node_id and e.edge_type == EdgeType.HAS_VULNERABILITY
            ]
            score += len(vuln_edges) * 10
            
            # Count incoming edges (more connected = more important)
            score += len(self._reverse_adjacency.get(node_id, [])) * 2
            
            # Check for sensitive keywords
            label_lower = node.label.lower()
            if any(kw in label_lower for kw in ["admin", "api", "auth", "payment"]):
                score += 20
            
            scores[node_id] = score
        
        # Sort by score
        sorted_nodes = sorted(
            self._nodes.values(),
            key=lambda n: scores.get(n.id, 0),
            reverse=True
        )
        
        return sorted_nodes[:10]  # Top 10
    
    # ==================== Import/Export ====================
    
    def to_dict(self) -> Dict[str, Any]:
        """Export graph to dictionary."""
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
        }
    
    def from_dict(self, data: Dict[str, Any]):
        """Import graph from dictionary."""
        self._nodes.clear()
        self._edges.clear()
        self._adjacency.clear()
        self._reverse_adjacency.clear()
        
        for node_data in data.get("nodes", []):
            self.add_node(
                node_id=node_data["id"],
                node_type=NodeType(node_data["type"]),
                label=node_data["label"],
                properties=node_data.get("properties", {}),
            )
        
        for edge_data in data.get("edges", []):
            self.add_edge(
                source_id=edge_data["source"],
                target_id=edge_data["target"],
                edge_type=EdgeType(edge_data["type"]),
                properties=edge_data.get("properties", {}),
            )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get graph statistics."""
        type_counts = defaultdict(int)
        for node in self._nodes.values():
            type_counts[node.node_type.value] += 1
        
        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "node_types": dict(type_counts),
        }


# Singleton
_graph: Optional[KnowledgeGraph] = None


def get_knowledge_graph() -> KnowledgeGraph:
    """Get the global knowledge graph."""
    global _graph
    if _graph is None:
        _graph = KnowledgeGraph()
    return _graph
