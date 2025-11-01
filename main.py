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
        from agents.ai_core import AegisAI
        from agents.conversational_agent import AegisConversation
    except ImportError as e:
        logger.error(f"Erreur d'importation critique : {e}")
        print(f"❌ Erreur: Assurez-vous que vos fichiers (ai_core.py, conversational_agent.py) sont dans le dossier 'agents'.")
        sys.exit(1)

    print("🚀 Démarrage de l'Agent Autonome Aegis AI...")
    
    try:
        # 1. Initialiser le Cerveau (AegisAI)
        # C'est l'étape qui charge le modèle Dolphin-Mistral sur le GPU
        ai_core = AegisAI()
        await ai_core.initialize()
        
        # 2. Initialiser l'Orchestrateur (AegisConversation)
        # On injecte le cerveau dans l'orchestrateur
        conversation = AegisConversation(ai_core)
        
        # 3. Démarrer la boucle de conversation
        # C'est l'orchestrateur qui prend le contrôle
        await conversation.start()
        
    except KeyboardInterrupt:
        print("\n\n🛡️  Session Aegis AI terminée par l'utilisateur.")
    except Exception as e:
        logger.error(f"❌ Erreur critique au démarrage : {e}", exc_info=True)
        print(f"❌ Une erreur fatale est survenue: {e}")
        print("💡 Vérifiez le fichier 'aegis_agent.log' pour les détails.")
        sys.exit(1)

if __name__ == "__main__":
    # S'assurer que webdriver-manager a les permissions (si besoin)
    # os.environ['WDM_SSL_VERIFY'] = '0' # Décommentez si vous avez des erreurs SSL
    
    asyncio.run(main())
