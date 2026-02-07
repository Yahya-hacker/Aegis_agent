"""
Nexus v2.0 - Data Layer
=======================

Storage and knowledge management.
"""

from nexus.data.database import (
    Database,
    VulnerabilityRecord,
    get_database,
)
from nexus.data.knowledge_graph import (
    KnowledgeGraph,
    Node,
    Edge,
    NodeType,
    EdgeType,
    get_knowledge_graph,
)

__all__ = [
    # Database
    "Database",
    "VulnerabilityRecord",
    "get_database",
    # Knowledge Graph
    "KnowledgeGraph",
    "Node",
    "Edge",
    "NodeType",
    "EdgeType",
    "get_knowledge_graph",
]
