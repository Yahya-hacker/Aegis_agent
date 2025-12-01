#!/usr/bin/env python3
"""
AEGIS AI - AGENT AUTONOME DE PENTEST (V8)
Point d'entrée principal avec logging robuste et gestion d'erreurs améliorée
"""

import asyncio
import sys
import os
import logging
from pathlib import Path

# Pour le env
from dotenv import load_dotenv
load_dotenv()  # Charge les variables du fichier .env

# Obtenir le répertoire du script pour des chemins robustes
SCRIPT_DIR = Path(__file__).parent.resolve()

# S'assurer que le répertoire logs existe
LOGS_DIR = SCRIPT_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

# Configuration du logging (très important pour le debug)
# Utiliser un chemin relatif au script, pas au CWD
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOGS_DIR / 'aegis_agent.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
                                             
logger = logging.getLogger(__name__)

# Ajoute la racine du projet au PYTHONPATH
sys.path.insert(0, str(SCRIPT_DIR))

async def main():
    """Point d'entrée principal pour la nouvelle architecture autonome."""
    
    # Importer les NOUVEAUX composants
    try:
        from agents.enhanced_ai_core import EnhancedAegisAI
        from agents.conversational_agent import AegisConversation
        from agents.learning_engine import AegisLearningEngine
        from utils.keep_alive import start_keep_alive, stop_keep_alive
        from utils.dynamic_tool_loader import get_tool_loader_async
    except ImportError as e:
        logger.error(f"Erreur d'importation critique : {e}")
        print(f"❌ Erreur: Assurez-vous que vos fichiers sont dans le dossier 'agents'.")
        sys.exit(1)

    print("🚀 Démarrage de l'Agent Autonome Aegis AI avec Multi-LLM...")
    print("📋 LLMs configurés:")
    print("   • Llama 70B: Planification stratégique et triage")
    print("   • Mixtral 8x7B: Analyse de vulnérabilités et exploitation")
    print("   • Qwen-coder: Analyse de code et génération de payloads")

    # Exécuter les vérifications de dépendances
    from utils.dependency_check import check_dependencies
    if not check_dependencies():
        print("❌ Démarrage annulé en raison de dépendances manquantes.")
        sys.exit(1)
    
    # TÂCHE 3: Initialiser le chargeur d'outils dynamique
    print("\n🔧 Initialisation de l'arsenal d'outils dynamique...")
    tool_loader = await get_tool_loader_async()
    stats = tool_loader.get_statistics()
    print(f"   • {stats['available_tools']}/{stats['total_tools']} outils disponibles")
    print(f"   • {stats['intrusive_tools']} outils intrusifs")
    print(f"   • {stats['non_intrusive_tools']} outils non intrusifs")
    print(f"   • Catégories: {', '.join(stats['categories'])}")
    
    # Démarrer le mécanisme keep-alive pour empêcher le terminal de dormir
    keep_alive = start_keep_alive(interval=60)
    print("\n🔋 Mécanisme keep-alive activé (empêche la mise en veille du terminal)")
    
    # Initialiser les composants
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
        print(f"💡 Vérifiez le fichier '{LOGS_DIR / 'aegis_agent.log'}' pour les détails.")
        return 1  # Retourner un code d'erreur
    finally:
        # Nettoyage: Arrêter le mécanisme keep-alive
        try:
            stop_keep_alive()
            print("🔋 Mécanisme keep-alive arrêté")
        except Exception as e:
            logger.error(f"Erreur lors de l'arrêt du keep-alive: {e}")
        
        # Nettoyage: Fermer les connexions à la base de données
        try:
            from utils.database_manager import get_database
            db = get_database()
            db.close()
            logger.info("Connexion à la base de données fermée")
        except Exception as e:
            logger.error(f"Erreur lors de la fermeture de la base de données: {e}")
        
        # Nettoyage: Sauvegarder les patterns en attente
        try:
            if learning_engine:
                learning_engine.analyze_patterns()
                logger.info("Patterns d'apprentissage sauvegardés")
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des patterns: {e}")
        
        print("\n🛡️  Nettoyage terminé. Aegis AI s'arrête proprement.")
    
    return 0  # Succès

if __name__ == "__main__":
    # S'assurer que webdriver-manager a les permissions (si besoin)
    # os.environ['WDM_SSL_VERIFY'] = '0' # Décommentez si vous avez des erreurs SSL
    
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n🛡️  Aegis AI interrompu par l'utilisateur.")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Erreur fatale non gérée: {e}", exc_info=True)
        print(f"\n❌ Erreur fatale non gérée: {e}")
        print(f"💡 Consultez le fichier '{LOGS_DIR / 'aegis_agent.log'}' pour plus de détails.")
        sys.exit(1)
