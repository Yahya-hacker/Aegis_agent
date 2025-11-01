"""
Aegis AI Agents Package (v2.0 - Autonome)
"""

from .ai_core import AegisAI
from .conversational_agent import AegisConversation
from .scanner import AegisScanner

# Ces fichiers sont gardés pour une utilisation future (apprentissage, etc.)
from .learning_engine import AegisLearningEngine
from .field_tester import AegisFieldTester

__all__ = [
    'AegisAI',
    'AegisConversation', 
    'AegisScanner',
    'AegisLearningEngine',
    'AegisFieldTester'
]
