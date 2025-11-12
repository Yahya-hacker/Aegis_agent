"""
Aegis AI Agents Package (v6.0 - Multi-LLM)
"""

from .enhanced_ai_core import EnhancedAegisAI
from .multi_llm_orchestrator import MultiLLMOrchestrator
from .conversational_agent import AegisConversation
from .scanner import AegisScanner
from .learning_engine import AegisLearningEngine
from .field_tester import AegisFieldTester

# Legacy import for backwards compatibility (deprecated)
try:
    from .ai_core import AegisAI
except SyntaxError:
    # Old ai_core.py is incomplete, use enhanced version
    AegisAI = EnhancedAegisAI

__all__ = [
    'EnhancedAegisAI',
    'MultiLLMOrchestrator',
    'AegisConversation', 
    'AegisScanner',
    'AegisLearningEngine',
    'AegisFieldTester',
    'AegisAI',  # Legacy support
]
