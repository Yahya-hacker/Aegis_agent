#!/usr/bin/env python3
"""
AEGIS OMEGA PROTOCOL - Knowledge Graph Module
==============================================

Implements Graph-Native KTV Loop with Attack Graph modeling:
- Nodes: Assets, Technologies, Credentials, Vulnerabilities
- Edges: Probabilistic attack paths with confidence scores
- Traversal: Graph-based testing and validation

This module enables neuro-symbolic reasoning for penetration testing.
"""

import asyncio
import logging
import json
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

try:
    import networkx as nx
except ImportError:
    nx = None
    logging.warning("NetworkX not available, using fallback graph implementation")

logger = logging.getLogger(__name__)


class NodeType(Enum):
    """Types of nodes in the knowledge graph"""
    ASSET = "asset"              # Web applications, APIs, services
    TECHNOLOGY = "technology"     # Tech stack components (PHP, MySQL, etc.)
    CREDENTIAL = "credential"     # Discovered credentials
    VULNERABILITY = "vulnerability"  # Confirmed vulnerabilities
    ENDPOINT = "endpoint"         # Specific URLs or API endpoints
    PARAMETER = "parameter"       # Input parameters
    DATA = "data"                 # Sensitive data types


class EdgeType(Enum):
    """Types of edges (relationships) in the graph"""
    USES = "uses"                 # Asset uses Technology
    CONTAINS = "contains"         # Asset contains Endpoint
    VULNERABLE_TO = "vulnerable_to"  # Endpoint vulnerable to attack
    LEADS_TO = "leads_to"         # Attack leads to access
    EXPOSES = "exposes"           # Vulnerability exposes Data
    AUTHENTICATES = "authenticates"  # Credential authenticates Asset
    DEPENDS_ON = "depends_on"     # Technology depends on another


@dataclass
class GraphNode:
    """Represents a node in the knowledge graph"""
    id: str
    node_type: NodeType
    label: str
    description: str
    confidence: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "id": self.id,
            "node_type": self.node_type.value,
            "label": self.label,
            "description": self.description,
            "confidence": self.confidence,
            "properties": self.properties,
            "created_at": self.created_at.isoformat(),
            "last_updated": self.last_updated.isoformat()
        }


@dataclass
class GraphEdge:
    """Represents an edge (relationship) in the knowledge graph"""
    id: str
    source_id: str
    target_id: str
    edge_type: EdgeType
    label: str
    confidence: float = 0.5  # Probabilistic confidence for attack paths
    properties: Dict[str, Any] = field(default_factory=dict)
    attack_vector: Optional[str] = None  # e.g., "SQLi", "XSS", "Path Traversal"
    created_at: datetime = field(default_factory=datetime.now)
    validated: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "label": self.label,
            "confidence": self.confidence,
            "properties": self.properties,
            "attack_vector": self.attack_vector,
            "created_at": self.created_at.isoformat(),
            "validated": self.validated
        }


@dataclass
class AttackPath:
    """Represents a potential attack path through the graph"""
    id: str
    path: List[str]  # List of node IDs
    edges: List[str]  # List of edge IDs
    total_confidence: float  # Product of edge confidences
    attack_vector: str
    description: str
    tested: bool = False
    successful: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class KnowledgeGraph:
    """
    Knowledge Graph for Attack Surface Mapping.
    
    This graph stores:
    - Confirmed facts as nodes with high confidence
    - Hypotheses as edges with probabilistic confidence
    - Attack paths as traversals to be tested
    
    Example Attack Graph:
    Node(Web) --[Vuln: SQLi, Conf: 0.9]--> Node(DB) --[Access: Dump, Conf: 0.7]--> Node(AdminHash)
    """
    
    def __init__(self, persist_path: Optional[Path] = None):
        """
        Initialize the knowledge graph.
        
        Args:
            persist_path: Optional path to persist graph state
        """
        self.persist_path = persist_path or Path("data/knowledge_graph.json")
        
        # Use NetworkX if available for advanced graph algorithms
        if nx:
            self._graph = nx.DiGraph()
            self._use_networkx = True
        else:
            self._use_networkx = False
            self._nodes: Dict[str, GraphNode] = {}
            self._edges: Dict[str, GraphEdge] = {}
            self._adjacency: Dict[str, List[str]] = {}  # node_id -> [edge_ids]
        
        self._node_counter = 0
        self._edge_counter = 0
        self._path_counter = 0
        self._attack_paths: Dict[str, AttackPath] = {}
        
        # Load persisted state if exists
        self._load_state()
        
        logger.info("🧠 Knowledge Graph initialized")
    
    def add_node(self, node_type: NodeType, label: str, description: str,
                 confidence: float = 1.0, properties: Optional[Dict] = None) -> GraphNode:
        """
        Add a node to the graph.
        
        Args:
            node_type: Type of the node
            label: Short label for the node
            description: Detailed description
            confidence: Confidence level (0.0-1.0)
            properties: Additional properties
            
        Returns:
            The created GraphNode
        """
        self._node_counter += 1
        node_id = f"n_{node_type.value}_{self._node_counter}"
        
        node = GraphNode(
            id=node_id,
            node_type=node_type,
            label=label,
            description=description,
            confidence=confidence,
            properties=properties or {}
        )
        
        if self._use_networkx:
            self._graph.add_node(node_id, **node.to_dict())
        else:
            self._nodes[node_id] = node
            self._adjacency[node_id] = []
        
        logger.info(f"📍 Graph: Added node [{node_type.value}] {label} (conf: {confidence:.0%})")
        
        self._save_state()
        return node
    
    def add_edge(self, source_id: str, target_id: str, edge_type: EdgeType,
                 label: str, confidence: float = 0.5, 
                 attack_vector: Optional[str] = None,
                 properties: Optional[Dict] = None) -> GraphEdge:
        """
        Add an edge (relationship) to the graph.
        
        Args:
            source_id: Source node ID
            target_id: Target node ID
            edge_type: Type of relationship
            label: Description of the relationship
            confidence: Probabilistic confidence (0.0-1.0)
            attack_vector: Attack technique if applicable
            properties: Additional properties
            
        Returns:
            The created GraphEdge
        """
        self._edge_counter += 1
        edge_id = f"e_{edge_type.value}_{self._edge_counter}"
        
        edge = GraphEdge(
            id=edge_id,
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            label=label,
            confidence=confidence,
            attack_vector=attack_vector,
            properties=properties or {}
        )
        
        if self._use_networkx:
            self._graph.add_edge(source_id, target_id, **edge.to_dict())
        else:
            self._edges[edge_id] = edge
            if source_id in self._adjacency:
                self._adjacency[source_id].append(edge_id)
        
        vector_str = f" [{attack_vector}]" if attack_vector else ""
        logger.info(f"🔗 Graph: Added edge{vector_str} {source_id} --[{label}, {confidence:.0%}]--> {target_id}")
        
        self._save_state()
        return edge
    
    def update_edge_confidence(self, edge_id: str, new_confidence: float,
                               validated: bool = False) -> None:
        """
        Update the confidence of an edge after testing.
        
        Args:
            edge_id: Edge to update
            new_confidence: New confidence value
            validated: Whether this edge has been validated
        """
        if self._use_networkx:
            for u, v, data in self._graph.edges(data=True):
                if data.get("id") == edge_id:
                    data["confidence"] = new_confidence
                    data["validated"] = validated
                    break
        else:
            if edge_id in self._edges:
                self._edges[edge_id].confidence = new_confidence
                self._edges[edge_id].validated = validated
                self._edges[edge_id].last_updated = datetime.now()
        
        logger.info(f"📊 Graph: Updated edge {edge_id} confidence to {new_confidence:.0%}")
        self._save_state()
    
    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get a node by ID"""
        if self._use_networkx:
            if node_id in self._graph.nodes:
                data = self._graph.nodes[node_id]
                return GraphNode(
                    id=node_id,
                    node_type=NodeType(data["node_type"]),
                    label=data["label"],
                    description=data["description"],
                    confidence=data["confidence"],
                    properties=data.get("properties", {})
                )
            return None
        else:
            return self._nodes.get(node_id)
    
    def get_nodes_by_type(self, node_type: NodeType) -> List[GraphNode]:
        """Get all nodes of a specific type"""
        nodes = []
        
        if self._use_networkx:
            for node_id, data in self._graph.nodes(data=True):
                if data.get("node_type") == node_type.value:
                    nodes.append(GraphNode(
                        id=node_id,
                        node_type=node_type,
                        label=data["label"],
                        description=data["description"],
                        confidence=data["confidence"],
                        properties=data.get("properties", {})
                    ))
        else:
            for node in self._nodes.values():
                if node.node_type == node_type:
                    nodes.append(node)
        
        return nodes
    
    def find_attack_paths(self, source_type: NodeType = NodeType.ENDPOINT,
                          target_type: NodeType = NodeType.DATA,
                          min_confidence: float = 0.3) -> List[AttackPath]:
        """
        Find all potential attack paths from source to target.
        
        Args:
            source_type: Type of source nodes (e.g., ENDPOINT)
            target_type: Type of target nodes (e.g., DATA, CREDENTIAL)
            min_confidence: Minimum path confidence threshold
            
        Returns:
            List of potential attack paths
        """
        attack_paths = []
        source_nodes = self.get_nodes_by_type(source_type)
        target_nodes = self.get_nodes_by_type(target_type)
        
        if self._use_networkx:
            for source in source_nodes:
                for target in target_nodes:
                    try:
                        # Find all simple paths
                        for path in nx.all_simple_paths(
                            self._graph, source.id, target.id, cutoff=5
                        ):
                            # Calculate path confidence
                            edge_ids = []
                            path_confidence = 1.0
                            attack_vectors = []
                            
                            for i in range(len(path) - 1):
                                edge_data = self._graph.edges[path[i], path[i+1]]
                                edge_ids.append(edge_data.get("id", ""))
                                path_confidence *= edge_data.get("confidence", 0.5)
                                
                                if edge_data.get("attack_vector"):
                                    attack_vectors.append(edge_data["attack_vector"])
                            
                            if path_confidence >= min_confidence:
                                self._path_counter += 1
                                attack_path = AttackPath(
                                    id=f"path_{self._path_counter}",
                                    path=path,
                                    edges=edge_ids,
                                    total_confidence=path_confidence,
                                    attack_vector=", ".join(attack_vectors) if attack_vectors else "Unknown",
                                    description=f"Attack path from {source.label} to {target.label}"
                                )
                                attack_paths.append(attack_path)
                                self._attack_paths[attack_path.id] = attack_path
                    
                    except nx.NetworkXNoPath:
                        continue
        else:
            # Fallback: simple BFS-based path finding
            attack_paths = self._find_paths_bfs(source_nodes, target_nodes, min_confidence)
        
        # Sort by confidence (descending)
        attack_paths.sort(key=lambda p: p.total_confidence, reverse=True)
        
        logger.info(f"🎯 Graph: Found {len(attack_paths)} attack paths (min conf: {min_confidence:.0%})")
        
        return attack_paths
    
    def _find_paths_bfs(self, sources: List[GraphNode], targets: List[GraphNode],
                        min_confidence: float) -> List[AttackPath]:
        """Fallback BFS-based path finding without NetworkX"""
        paths = []
        target_ids = {t.id for t in targets}
        
        for source in sources:
            # BFS
            queue = [(source.id, [source.id], [], 1.0)]
            visited = set()
            
            while queue:
                current_id, path, edges, confidence = queue.pop(0)
                
                if current_id in target_ids:
                    self._path_counter += 1
                    attack_path = AttackPath(
                        id=f"path_{self._path_counter}",
                        path=path,
                        edges=edges,
                        total_confidence=confidence,
                        attack_vector="Unknown",
                        description=f"Attack path to target"
                    )
                    paths.append(attack_path)
                    continue
                
                if current_id in visited or len(path) > 5:
                    continue
                
                visited.add(current_id)
                
                # Get outgoing edges
                for edge_id in self._adjacency.get(current_id, []):
                    edge = self._edges.get(edge_id)
                    if edge:
                        new_conf = confidence * edge.confidence
                        if new_conf >= min_confidence:
                            queue.append((
                                edge.target_id,
                                path + [edge.target_id],
                                edges + [edge_id],
                                new_conf
                            ))
        
        return paths
    
    def get_graph_state(self) -> Dict[str, Any]:
        """Get current graph state summary"""
        if self._use_networkx:
            node_count = self._graph.number_of_nodes()
            edge_count = self._graph.number_of_edges()
            
            node_types = {}
            for _, data in self._graph.nodes(data=True):
                nt = data.get("node_type", "unknown")
                node_types[nt] = node_types.get(nt, 0) + 1
        else:
            node_count = len(self._nodes)
            edge_count = len(self._edges)
            
            node_types = {}
            for node in self._nodes.values():
                nt = node.node_type.value
                node_types[nt] = node_types.get(nt, 0) + 1
        
        return {
            "total_nodes": node_count,
            "total_edges": edge_count,
            "node_types": node_types,
            "attack_paths_found": len(self._attack_paths),
            "validated_paths": len([p for p in self._attack_paths.values() if p.tested])
        }
    
    def format_for_llm(self) -> str:
        """Format graph state for LLM consumption in prompts"""
        state = self.get_graph_state()
        
        lines = [
            f"[GRAPH STATE] Nodes: {state['total_nodes']}, Edges: {state['total_edges']}",
            f"[NODE TYPES] {', '.join(f'{k}: {v}' for k, v in state['node_types'].items())}",
            f"[ATTACK PATHS] Found: {state['attack_paths_found']}, Validated: {state['validated_paths']}"
        ]
        
        # Add top attack paths
        top_paths = sorted(
            self._attack_paths.values(),
            key=lambda p: p.total_confidence,
            reverse=True
        )[:3]
        
        if top_paths:
            lines.append("[TOP ATTACK PATHS]")
            for path in top_paths:
                status = "✓ Tested" if path.tested else "? Untested"
                lines.append(f"  - {path.description} (conf: {path.total_confidence:.0%}) [{status}]")
        
        return "\n".join(lines)
    
    def _save_state(self) -> None:
        """Persist graph state to disk"""
        try:
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
            
            state = {
                "nodes": [],
                "edges": [],
                "attack_paths": [],
                "counters": {
                    "node": self._node_counter,
                    "edge": self._edge_counter,
                    "path": self._path_counter
                }
            }
            
            if self._use_networkx:
                for node_id, data in self._graph.nodes(data=True):
                    state["nodes"].append(data)
                for u, v, data in self._graph.edges(data=True):
                    state["edges"].append(data)
            else:
                state["nodes"] = [n.to_dict() for n in self._nodes.values()]
                state["edges"] = [e.to_dict() for e in self._edges.values()]
            
            for path in self._attack_paths.values():
                state["attack_paths"].append({
                    "id": path.id,
                    "path": path.path,
                    "edges": path.edges,
                    "total_confidence": path.total_confidence,
                    "attack_vector": path.attack_vector,
                    "description": path.description,
                    "tested": path.tested,
                    "successful": path.successful
                })
            
            with open(self.persist_path, 'w') as f:
                json.dump(state, f, indent=2)
        
        except Exception as e:
            logger.error(f"Error saving graph state: {e}")
    
    def _load_state(self) -> None:
        """Load graph state from disk"""
        if not self.persist_path.exists():
            return
        
        try:
            with open(self.persist_path, 'r') as f:
                state = json.load(f)
            
            self._node_counter = state.get("counters", {}).get("node", 0)
            self._edge_counter = state.get("counters", {}).get("edge", 0)
            self._path_counter = state.get("counters", {}).get("path", 0)
            
            # Restore nodes
            for node_data in state.get("nodes", []):
                node_id = node_data["id"]
                if self._use_networkx:
                    self._graph.add_node(node_id, **node_data)
                else:
                    self._nodes[node_id] = GraphNode(
                        id=node_id,
                        node_type=NodeType(node_data["node_type"]),
                        label=node_data["label"],
                        description=node_data["description"],
                        confidence=node_data["confidence"],
                        properties=node_data.get("properties", {})
                    )
                    self._adjacency[node_id] = []
            
            # Restore edges
            for edge_data in state.get("edges", []):
                if self._use_networkx:
                    self._graph.add_edge(
                        edge_data["source_id"],
                        edge_data["target_id"],
                        **edge_data
                    )
                else:
                    edge = GraphEdge(
                        id=edge_data["id"],
                        source_id=edge_data["source_id"],
                        target_id=edge_data["target_id"],
                        edge_type=EdgeType(edge_data["edge_type"]),
                        label=edge_data["label"],
                        confidence=edge_data["confidence"],
                        attack_vector=edge_data.get("attack_vector"),
                        properties=edge_data.get("properties", {})
                    )
                    self._edges[edge.id] = edge
                    if edge.source_id in self._adjacency:
                        self._adjacency[edge.source_id].append(edge.id)
            
            # Restore attack paths
            for path_data in state.get("attack_paths", []):
                self._attack_paths[path_data["id"]] = AttackPath(
                    id=path_data["id"],
                    path=path_data["path"],
                    edges=path_data["edges"],
                    total_confidence=path_data["total_confidence"],
                    attack_vector=path_data["attack_vector"],
                    description=path_data["description"],
                    tested=path_data.get("tested", False),
                    successful=path_data.get("successful", False)
                )
            
            logger.info(f"📂 Graph: Loaded {len(state.get('nodes', []))} nodes, {len(state.get('edges', []))} edges")
        
        except Exception as e:
            logger.error(f"Error loading graph state: {e}")
    
    def clear(self) -> None:
        """Clear the graph"""
        if self._use_networkx:
            self._graph.clear()
        else:
            self._nodes.clear()
            self._edges.clear()
            self._adjacency.clear()
        
        self._attack_paths.clear()
        self._node_counter = 0
        self._edge_counter = 0
        self._path_counter = 0
        
        if self.persist_path.exists():
            self.persist_path.unlink()
        
        logger.info("🗑️ Graph: Cleared all data")


# Global instance
_knowledge_graph: Optional[KnowledgeGraph] = None


def get_knowledge_graph() -> KnowledgeGraph:
    """Get the global knowledge graph instance"""
    global _knowledge_graph
    if _knowledge_graph is None:
        _knowledge_graph = KnowledgeGraph()
    return _knowledge_graph
