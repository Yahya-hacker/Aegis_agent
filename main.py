#!/usr/bin/env python3
"""
AEGIS AI - AGENT AUTONOME DE PENTEST (v2.0)
Point d'entrée principal
"""

import asyncio
import sys
import os
import logging
from pathlib import Path

# Pour le env
from dotenv import load_dotenv
load_dotenv() # Charge les variables du fichier .env

# Configuration du logging (très important pour le debug) 
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('aegis_agent.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
                                             
logger = logging.getLogger(__name__)

# Ajoute la racine du projet au PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent))

async def main():
    """Point d'entrée principal pour la nouvelle architecture autonome."""
    
    # Importer les NOUVEAUX composants
    try:
        from agents.enhanced_ai_core import EnhancedAegisAI
        from agents.conversational_agent import AegisConversation
        from agents.learning_engine import AegisLearningEngine
        from utils.keep_alive import start_keep_alive, stop_keep_alive
        from utils.dynamic_tool_loader import get_tool_loader
    except ImportError as e:
        logger.error(f"Erreur d'importation critique : {e}")
        print(f"❌ Erreur: Assurez-vous que vos fichiers sont dans le dossier 'agents'.")
        sys.exit(1)

    print("🚀 Démarrage de l'Agent Autonome Aegis AI avec Multi-LLM...")
    print("📋 LLMs configurés:")
    print("   • Llama 70B: Planification stratégique et triage")
    print("   • Mixtral 8x7B: Analyse de vulnérabilités et exploitation")
    print("   • Qwen-coder: Analyse de code et génération de payloads")

    # Run Dependency Checks
    from utils.dependency_check import check_dependencies
    if not check_dependencies():
        print("❌ Startup Aborted due to missing dependencies.")
        sys.exit(1)
    
    # TASK 3: Initialize dynamic tool loader
    print("\n🔧 Initializing dynamic tool arsenal...")
    tool_loader = get_tool_loader()
    stats = tool_loader.get_statistics()
    print(f"   • {stats['available_tools']}/{stats['total_tools']} tools available")
    print(f"   • {stats['intrusive_tools']} intrusive tools")
    print(f"   • {stats['non_intrusive_tools']} non-intrusive tools")
    print(f"   • Categories: {', '.join(stats['categories'])}")
    
    # Start keep-alive mechanism to prevent terminal from sleeping
    keep_alive = start_keep_alive(interval=60)
    print("\n🔋 Keep-alive mechanism activated (prevents terminal sleep)")
    
    # Initialize components
    learning_engine = None
    ai_core = None
    conversation = None
    
    try:
        # 1. Initialiser le moteur d'apprentissage
        learning_engine = AegisLearningEngine()
        
        # 2. Initialiser le Cerveau Multi-LLM (EnhancedAegisAI)
        ai_core = EnhancedAegisAI(learning_engine)
        await ai_core.initialize()
        
        # 3. Initialiser l'Orchestrateur (AegisConversation)
        # On injecte le cerveau dans l'orchestrateur
        conversation = AegisConversation(ai_core)
        
        # 4. Démarrer la boucle de conversation
        # C'est l'orchestrateur qui prend le contrôle
        await conversation.start()
        
    except KeyboardInterrupt:
        print("\n\n🛡️  Session Aegis AI terminée par l'utilisateur.")
    except Exception as e:
        logger.error(f"❌ Erreur critique au démarrage : {e}", exc_info=True)
        print(f"❌ Une erreur fatale est survenue: {e}")
        print("💡 Vérifiez le fichier 'aegis_agent.log' pour les détails.")
        return 1  # Return error code
    finally:
        # Cleanup: Stop keep-alive mechanism
        try:
            stop_keep_alive()
            print("🔋 Keep-alive mechanism stopped")
        except Exception as e:
            logger.error(f"Error stopping keep-alive: {e}")
        
        # Cleanup: Close database connections
        try:
            from utils.database_manager import get_database
            db = get_database()
            db.close()
            logger.info("Database connection closed")
        except Exception as e:
            logger.error(f"Error closing database: {e}")
        
        # Cleanup: Save any pending patterns
        try:
            if learning_engine:
                learning_engine.analyze_patterns()
                logger.info("Learning patterns saved")
        except Exception as e:
            logger.error(f"Error saving patterns: {e}")
        
        print("\n🛡️  Cleanup complete. Aegis AI shutting down gracefully.")
    
    return 0  # Success

if __name__ == "__main__":
    # S'assurer que webdriver-manager a les permissions (si besoin)
    # os.environ['WDM_SSL_VERIFY'] = '0' # Décommentez si vous avez des erreurs SSL
    
    asyncio.run(main())
