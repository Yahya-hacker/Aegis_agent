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
    Capacités : Triage Conversationnel (Niveau 1)
               Exécution Autonome (Niveau 2)
               Auto-Apprentissage
    """
    
    def __init__(self, learning_engine: AegisLearningEngine, model_name: str = "ehartford/dolphin-2.2.1-mistral-7b"):
        self.model_name = model_name
        self.model = None
        self.tokenizer = None
        self.is_initialized = False
        self.learning_engine = learning_engine
        self.learned_patterns = "" # La mémoire des leçons apprises
    
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

            # --- CHARGEMENT DE LA MÉMOIRE (APPRENTISSAGE) ---
            logger.info("🧠 Chargement des leçons des missions précédentes...")
            loop = asyncio.get_event_loop()
            self.learned_patterns = await loop.run_in_executor(None, self.learning_engine.load_learned_patterns)
            logger.info("✅ Leçons chargées dans la mémoire de l'IA.")
            
        except Exception as e:
            logger.error(f"❌ Échec du chargement du modèle IA : {e}", exc_info=True)
            raise

    # --- NIVEAU 1 : AGENT DE TRIAGE (Conversationnel) ---
    # NOUVELLE FONCTION
    async def triage_mission(self, conversation_history: List[Dict]) -> Dict:
        """
        Analyse la conversation naturelle et détermine si la mission est prête.
        Répond par une question (langage naturel) ou un signal de démarrage (JSON).
        """
        if not self.is_initialized:
            return {"response_type": "error", "text": "IA non initialisée."}

        prompt = self._create_triage_prompt(conversation_history)
        # Utiliser moins de tokens pour une réponse de triage rapide
        response_str = self._generate_response(prompt, max_tokens=256)
        
        try:
            # Tenter d'abord de trouver un JSON (signal de démarrage)
            match = re.search(r'\{.*\}', response_str, re.DOTALL)
            if match:
                json_str = match.group(0)
                action = json.loads(json_str)
                # S'assurer que c'est bien le bon signal
                if action.get("response_type") == "start_mission":
                    logger.info("Agent de Triage a validé la mission, passage au Niveau 2.")
                    return action
            
            # Si ce n'est pas un JSON de démarrage, c'est une question
            # Nettoyer la réponse au cas où le modèle ajouterait <|im_end|>
            response_text = response_str.split('<|im_end|>')[0].strip()
            return {"response_type": "question", "text": response_text}
            
        except Exception as e:
            logger.error(f"Échec du parsing de l'action de triage: {e} - Réponse: {response_str}")
            return {"response_type": "question", "text": "Je suis confus. Pouvez-vous reformuler ?"}

    # NOUVELLE FONCTION
    def _create_triage_prompt(self, conversation_history: List[Dict]) -> str:
        """
        Prompt pour l'agent de Triage (Niveau 1).
        Objectif : Obtenir Cible et Règles.
        """
        history_str = "\n".join([f"{h['role']}: {h['content']}" for h in conversation_history])
        
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
````

\<|im\_end|\>"""

```
    user_prompt = f"""<|im_start|>user
```

Voici notre conversation jusqu'à présent :
{history\_str}

Quelle est ta prochaine réponse ? (Soit une question pour obtenir plus d'infos, soit le JSON de démarrage si tu as TOUT)
\<|im\_end|\>
\<|im\_start|\>assistant
"""
return system\_prompt + user\_prompt

```
# --- NIVEAU 2 : AGENT EXÉCUTEUR (Autonome) ---
# (Fonction existante - pas de changement)
def get_next_action(self, bbp_rules: str, history: List[Dict]) -> Dict:
    """Le 'cerveau' Exécuteur (v3.0). Ne parle qu'en JSON."""
    if not self.is_initialized:
        return {"error": "AI model not initialized"}

    prompt = self._create_reasoning_prompt(bbp_rules, history, self.learned_patterns)
    response_str = self._generate_response(prompt, max_tokens=1024)
    
    try:
        match = re.search(r'\{.*\}', response_str, re.DOTALL)
        if not match:
            logger.error(f"Aucun JSON trouvé dans la réponse (Niveau 2): {response_str}")
            return {"tool": "system", "action": "ask_user_for_help", "message": "Réponse IA invalide."}
            
        json_str = match.group(0)
        action = json.loads(json_str)
        return action
    except Exception as e:
        logger.error(f"Échec du parsing de l'action IA (Niveau 2): {e} - Réponse: {response_str}")
        return {"tool": "system", "action": "ask_user_for_help", "message": "Je suis confus."}

# (Fonction existante - pas de changement)
def _create_reasoning_prompt(self, bbp_rules: str, history: List[Dict], learned_patterns: str) -> str:
    
    Le prompt Exécuteur (v3.0). Lit les leçons et les règles, sort du JSON.
        
    history_str_parts = []
    for h in history:
        content = h['content']
        if isinstance(content, (list, dict)):
            content_str = json.dumps(content)
            if len(content_str) > 500:
                content = f"Résultat volumineux tronqué : {content_str[:500]}..."
        history_str_parts.append(f"- {h['type']}: {content}")
    history_str = "\n".join(history_str_parts)
    
    system_prompt = f"""<|im_start|>system

Tu es Aegis AI, un agent de pentest expert (Mode Exécuteur). Tu es en mission.
Tu ne parles *pas* à l'utilisateur. Tu ne génères *que* des actions JSON.
Tu dois analyser l'historique de la mission, les règles, et tes leçons apprises pour décider de la prochaine action outil.

### LEÇONS DES MISSIONS PRÉCÉDENTES (Ta Mémoire)

{learned\_patterns}

### RÈGLES DU BUG BOUNTY (À RESPECTER IMPÉRATIVEMENT)

{bbp\_rules}

### OUTILS DISPONIBLES (Réponds *uniquement* avec ce format JSON)

#### Phase 1: Reconnaissance

  - {{"tool": "subdomain\_enumeration", "args": {{"domain": "..."}}}}
  - {{"tool": "port\_scanning", "args": {{"target": "..."}}}}
  - {{"tool": "nmap\_scan", "args": {{"target": "...", "ports": "80,443,..."}}}}
  - {{"tool": "url\_discovery", "args": {{"domain": "..."}}}}
  - {{"tool": "tech\_detection", "args": {{"target": "..."}}}}

#### Phase 2: Analyse de Vulnérabilités

  - {{"tool": "vulnerability\_scan", "args": {{"target": "..."}}}} -\> (Nuclei)
  - {{"tool": "run\_sqlmap", "args": {{"target": "..."}}}} -\> (Sqlmap)
  - {{"tool": "fetch\_url", "args": {{"target": "..."}}}} -\> (Test IDOR)
  - {{"tool": "discover\_interactables", "args": {{"target": "..."}}}} -\> (Selenium "Regarder")
  - {{"tool": "test\_form\_payload", "args": {{"target": "...", "form\_identifier": "...", "input\_payloads": {{...}}}}}} -\> (Selenium "Tester")

#### Phase 3: Système

  - {{"tool": "ask\_user\_for\_approval", "args": {{"message": "..."}}}} -\> OBLIGATOIRE si une règle est ambiguë.

  - {{"tool": "finish\_mission", "args": {{"reason": "..."}}}}
    \<|im\_end|\>"""

      user_prompt = f"""<|im_start|>user

### HISTORIQUE DES ACTIONS ET OBSERVATIONS (Mission Actuelle)

{history\_str}

### TA TÂCHE

Analyse l'historique, les règles, ET tes leçons apprises. Quelle est la prochaine action JSON ?
Pense étape par étape :

1.  **Observation** : Qu'est-ce que je viens d'apprendre ?
2.  **Mémoire (Leçons)** : Est-ce un faux positif connu ?
3.  **Règles** : Est-ce que j'enfreins une règle ?
4.  **Hypothèse** : Quelle est l'action JSON la plus logique ?

Réponds *uniquement* avec un seul objet JSON.
\<|im\_end|\>
\<|im\_start|\>assistant
"""
return system\_prompt + user\_prompt

# (Fonction existante - pas de changement)
def _generate_response(self, prompt: str, max_tokens: int = 1024) -> str:
    """Génère une réponse brute du modèle."""
    try:
        inputs = self.tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=4096
        ).to(self.model.device)
        
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_tokens,
                do_sample=True,
                temperature=0.7,
                top_p=0.9,
                pad_token_id=self.tokenizer.pad_token_id,
                eos_token_id=self.tokenizer.eos_token_id,
                repetition_penalty=1.1
            )
        
        response = self.tokenizer.decode(
            outputs[0][len(inputs["input_ids"][0]):],
            skip_special_tokens=True
        )
        return response.strip()
        
    except Exception as e:
        logger.error(f"Erreur de génération IA : {e}")
        return f"{'error': 'Erreur de génération'}"
    
