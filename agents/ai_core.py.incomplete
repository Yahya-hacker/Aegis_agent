# agents/ai_core.py
# --- VERSION MISE À JOUR (v5.0 - API Llama 3 70B) ---

import asyncio
import json
import re
import os
import aiohttp
from typing import Dict, List, Any
import logging
from agents.learning_engine import AegisLearningEngine

logger = logging.getLogger(__name__)

class AegisAI:
    """
    Cerveau IA avancé v5.0 - Propulsé par API Externe (Llama 3 70B)
    Capacités : Triage Conversationnel (Niveau 1)
               Exécution Autonome (Niveau 2)
               Auto-Apprentissage
    """
    
    def __init__(self, learning_engine: AegisLearningEngine):
        self.model_name = "NousResearch/Nous-Hermes-2-Llama-3-70B" # Le cerveau puissant
        self.api_url = "https://api.together.xyz/v1/chat/completions"
        self.api_key = None # Sera chargé depuis les variables d'environnement
        self.is_initialized = False
        self.learning_engine = learning_engine
        self.learned_patterns = ""
    
    async def initialize(self):
        """Initialise le Cerveau API ET charge les leçons apprises."""
        try:
            logger.info(f"🤖 Initialisation du cerveau API : {self.model_name}...")
            
            # --- CHARGEMENT DE LA CLÉ API ---
            self.api_key = os.environ.get("TOGETHER_API_KEY")
            if not self.api_key:
                logger.error("❌ Variable d'environnement TOGETHER_API_KEY non définie.")
                raise ValueError("TOGETHER_API_KEY doit être définie pour utiliser l'IA.")
            
            logger.info("✅ Clé API chargée.")

            # --- CHARGEMENT DE LA MÉMOIRE (APPRENTISSAGE) ---
            logger.info("🧠 Chargement des leçons des missions précédentes...")
            # Note: L'original `load_learned_patterns` n'est pas async, nous l'adaptons.
            # (Si `learning_engine.load_learned_patterns` est synchrone, gardez-le ainsi)
            
            # (Votre code original utilisait run_in_executor, gardons cette logique)
            loop = asyncio.get_event_loop()
            self.learned_patterns = await loop.run_in_executor(
                None, self.learning_engine.load_learned_patterns
            )
            
            self.is_initialized = True
            logger.info("✅ Cerveau IA (API) prêt et leçons chargées.")
            
        except Exception as e:
            logger.error(f"❌ Échec de l'initialisation de l'IA : {e}", exc_info=True)
            raise

    # --- NIVEAU 1 : AGENT DE TRIAGE (Conversationnel) ---
    async def triage_mission(self, conversation_history: List[Dict]) -> Dict:
        """
        Analyse la conversation naturelle et détermine si la mission est prête.
        (REFACTORISÉ POUR L'API)
        """
        if not self.is_initialized:
            return {"response_type": "error", "text": "IA non initialisée."}

        # Définir le prompt système (anciennement _create_triage_prompt)
        system_prompt = """<|im_start|>system
Tu es Aegis AI, un planificateur de mission de cybersécurité. Ton but est de dialoguer avec l'utilisateur pour collecter TOUTES les informations nécessaires avant de lancer une mission.

Les informations requises sont :
1.  **LA CIBLE** (ex: "example.com", "192.168.1.1", ou un fichier comme "image.png").
2.  **LES RÈGLES** (ex: "scope", "out-of-scope", "ne pas faire de DDoS", "c'est un CTF").

TA TÂCHE :
- Analyse la conversation.
- Si une information manque (cible ou règles), pose une question CLAIRE et COURTE à l'utilisateur.
- Si l'utilisateur te donne une information, accuse réception et demande la suite (ex: "OK, cible 'example.com' reçue. Quelles sont les règles du scope ?").
- **NE LANCE PAS DE SCAN TOI-MÊME.**

- **UNE FOIS QUE TU AS TOUTES LES INFORMATIONS (CIBLE + RÈGLES)**, ne pose plus de question. Réponds *uniquement* avec l'objet JSON suivant pour démarrer la mission :
```json
{
  "response_type": "start_mission",
  "target": "[la cible principale]",
  "rules": "[résumé de toutes les règles et instructions]"
}
