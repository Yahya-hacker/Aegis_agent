# agents/ai_core.py
# --- VERSION MODIFIÉE (v4.0 - Conversationnel) ---

import torch
import asyncio
import json
import re
from typing import Dict, List, Any
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
import logging
from agents.learning_engine import AegisLearningEngine

logger = logging.getLogger(__name__)

class AegisAI:
    """
    Cerveau IA avancé v4.0
    Capacités : Triage Conversationnel, Exécution Autonome, Auto-Apprentissage
    """
    
    def __init__(self, learning_engine: AegisLearningEngine, model_name: str = "ehartford/dolphin-2.2.1-mistral-7b"):
        self.model_name = model_name
        self.model = None
        self.tokenizer = None
        self.is_initialized = False
        self.learning_engine = learning_engine
        self.learned_patterns = ""
    
    async def initialize(self):
        """Initialise le modèle IA ET charge les leçons apprises."""
        try:
            logger.info(f"🤖 Chargement du modèle : {self.model_name}...")
            
            quantization_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_use_double_quant=True,
                bnb_4bit_quant_type="nf4",
            )
            
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_name, trust_remote_code=True
            )
            
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                quantization_config=quantization_config,
                device_map="auto",
                torch_dtype=torch.float16,
                trust_remote_code=True,
                low_cpu_mem_usage=True
            )
            
            self.is_initialized = True
            logger.info("✅ Modèle Dolphin-Mistral chargé avec succès !")

            logger.info("🧠 Chargement des leçons des missions précédentes...")
            loop = asyncio.get_event_loop()
            self.learned_patterns = await loop.run_in_executor(None, self.learning_engine.load_learned_patterns)
            logger.info("✅ Leçons chargées dans la mémoire de l'IA.")
            
        except Exception as e:
            logger.error(f"❌ Échec du chargement du modèle IA : {e}", exc_info=True)
            raise

    # --- NIVEAU 1 : AGENT DE TRIAGE (Conversationnel) ---

    async def triage_mission(self, conversation_history: List[Dict]) -> Dict:
        """
        Analyse la conversation naturelle et détermine si la mission est prête.
        Répond par une question (langage naturel) ou un signal de démarrage (JSON).
        """
        if not self.is_initialized:
            return {"response_type": "error", "text": "IA non initialisée."}

        prompt = self._create_triage_prompt(conversation_history)
        response_str = self._generate_response(prompt, max_tokens=512)
        
        try:
            # Tenter d'abord de trouver un JSON (signal de démarrage)
            match = re.search(r'\{.*\}', response_str, re.DOTALL)
            if match:
                json_str = match.group(0)
                action = json.loads(json_str)
                if action.get("response_type") == "start_mission":
                    return action
            
            # Si ce n'est pas un JSON de démarrage, c'est une question
            return {"response_type": "question", "text": response_str}
            
        except Exception as e:
            logger.error(f"Échec du parsing de l'action de triage: {e} - Réponse: {response_str}")
            return {"response_type": "question", "text": "Je suis confus. Pouvez-vous reformuler ?"}

    def _create_triage_prompt(self, conversation_history: List[Dict]) -> str:
        """
        Prompt pour l'agent de Triage (Niveau 1).
        """
        history_str = "\n".join([f"{h['role']}: {h['content']}" for h in conversation_history])
        
        system_prompt = """<|im_start|>system
Tu es Aegis AI, un planificateur de mission de cybersécurité. Ton but est de dialoguer avec l'utilisateur pour collecter TOUTES les informations nécessaires avant de lancer une mission de pentest.

Les informations requises sont :
1.  **LA CIBLE** (ex: "example.com", "192.168.1.1", ou un fichier comme "image.png").
2.  **LES RÈGLES** (ex: "scope", "out-of-scope", "ne pas faire de DDoS").

TA TÂCHE :
- Analyse la conversation.
- Si une information manque (cible ou règles), pose une question CLAIRE à l'utilisateur.
- Si l'utilisateur te donne une information, accuse réception et demande la suite.
- **NE LANCE PAS DE SCAN TOI-MÊME.**

- **UNE FOIS QUE TU AS TOUTES LES INFORMATIONS (CIBLE + RÈGLES)**, ne pose plus de question. Réponds *uniquement* avec l'objet JSON suivant pour démarrer la mission :
```json
{
  "response_type": "start_mission",
  "target": "[la cible principale]",
  "rules": "[résumé de toutes les règles]"
}
