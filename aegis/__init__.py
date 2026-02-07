# aegis/__init__.py
"""
Aegis AI - Autonomous Penetration Testing Agent

Core package exports.
"""

# Core agent (AegisOmega - enhanced hybrid)
from aegis.agent import AegisOmega, get_agent

# LLM interface
from aegis.llm import LLMEngine, get_llm

# State management
from aegis.state import AppState, get_app_state, OperationMode, MissionConfig

# Omega Protocol components
from aegis.knowledge_graph import KnowledgeGraph, get_knowledge_graph, NodeType, EdgeType
from aegis.epistemic_priority import EpistemicPriorityManager, get_epistemic_manager, EpistemicMode
from aegis.adversarial_swarm import AdversarialSwarm, get_adversarial_swarm, SwarmPersona
from aegis.virtual_sandbox import VirtualSandbox, get_virtual_sandbox
from aegis.hive_mind import HiveMind, get_hive_mind
from aegis.omega_protocol import OmegaProtocol, get_omega_protocol

__all__ = [
    # Core
    'AegisOmega',
    'get_agent',
    'LLMEngine', 
    'get_llm',
    'AppState',
    'get_app_state',
    'OperationMode',
    'MissionConfig',
    # Omega Protocol
    'KnowledgeGraph',
    'get_knowledge_graph',
    'NodeType',
    'EdgeType',
    'EpistemicPriorityManager',
    'get_epistemic_manager',
    'EpistemicMode',
    'AdversarialSwarm',
    'get_adversarial_swarm',
    'SwarmPersona',
    'VirtualSandbox',
    'get_virtual_sandbox',
    'HiveMind',
    'get_hive_mind',
    'OmegaProtocol',
    'get_omega_protocol',
]

__version__ = "2.0.0"


