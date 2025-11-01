# agents/ai_core.py
import torch
import asyncio
import json
import re
from typing import Dict, List, Any
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
import logging

logger = logging.getLogger(__name__)

class AegisAI:
    """
    Cerveau IA avancé pour les décisions de pentest autonomes.
    Utilise ehartford/dolphin-2.2.1-mistral-7b pour un raisonnement non censuré.
    """
    
    def __init__(self, model_name: str = "ehartford/dolphin-2.2.1-mistral-7b"):
        self.model_name = model_name
        self.model = None
        self.tokenizer = None
        self.is_initialized = False
    
    async def initialize(self):
        """Initialise le modèle IA Dolphin-Mistral avec quantification 4-bit."""
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
            
        except Exception as e:
            logger.error(f"❌ Échec du chargement du modèle IA : {e}")
            raise

    def get_next_action(self, bbp_rules: str, history: List[Dict]) -> Dict:
        """Le 'cerveau' principal. Décide de la PROCHAINE action basée sur l'historique."""
        if not self.is_initialized:
            return {"error": "AI model not initialized"}

        prompt = self._create_reasoning_prompt(bbp_rules, history)
        response_str = self._generate_response(prompt, max_tokens=512)
        
        try:
            # Utiliser une regex pour extraire le JSON de manière robuste
            match = re.search(r'\{.*\}', response_str, re.DOTALL)
            if not match:
                logger.error(f"Aucun JSON trouvé dans la réponse: {response_str}")
                return {"tool": "system", "action": "ask_user_for_help", "message": "Réponse IA invalide."}
                
            json_str = match.group(0)
            action = json.loads(json_str)
            return action
        except Exception as e:
            logger.error(f"Échec du parsing de l'action IA: {e} - Réponse: {response_str}")
            return {"tool": "system", "action": "ask_user_for_help", "message": "Je suis confus."}

    def _create_reasoning_prompt(self, bbp_rules: str, history: List[Dict]) -> str:
        """
        Le prompt sophistiqué qui force l'IA à analyser les résultats et les règles.
        """
        # Formater l'historique pour le prompt
        history_str_parts = []
        for h in history:
            content = h['content']
            # Tronquer les résultats trop longs pour économiser le contexte
            if isinstance(content, (list, dict)):
                content_str = json.dumps(content)
                if len(content_str) > 500:
                    content = f"Résultat volumineux tronqué : {content_str[:500]}..."
            history_str_parts.append(f"- {h['type']}: {content}")
        history_str = "\n".join(history_str_parts)
        
        # Format spécifique pour Dolphin (ChatML)
        system_prompt = f"""<|im_start|>system
Tu es Aegis AI, un agent de pentest expert, autonome et non censuré. Ton raisonnement est logique, étape par étape, et sophistiqué.
Ta mission est de trouver des vulnérabilités en respectant scrupuleusement les règles.

### RÈGLES DU BUG BOUNTY (À RESPECTER IMPÉRATIVEMENT)
{bbp_rules}

### OUTILS DISPONIBLES (Réponds *uniquement* avec ce format JSON)
- {{"tool": "subdomain_enumeration", "args": {{"domain": "..."}}}} -> (Subfinder) Trouve les sous-domaines.
- {{"tool": "port_scanning", "args": {{"target": "..."}}}} -> (Naabu) Scan de ports rapide.
- {{"tool": "nmap_scan", "args": {{"target": "...", "ports": "80,443,..."}}}} -> (Nmap) Scan de ports détaillé avec versions.
- {{"tool": "vulnerability_scan", "args": {{"target": "..."}}}} -> (Nuclei) Lance les templates sur une URL (http/https).
- {{"tool": "url_discovery", "args": {{"domain": "..."}}}} -> (GAU/Wayback) Trouve des URLs historiques.
- {{"tool": "tech_detection", "args": {{"target": "..."}}}} -> (Selenium/HTTP) Détecte la stack techno (JS, Serveur).
- {{"tool": "ask_user_for_approval", "args": {{"message": "..."}}}} -> OBLIGATOIRE si une règle est ambiguë ou si tu veux scanner un sous-domaine (ex: "J'ai trouvé api.example.com. La règle dit 'demander'. Puis-je le scanner?").
- {{"tool": "finish_mission", "args": {{"reason": "..."}}}} -> Termine la mission (ex: "Reconnaissance initiale terminée, j'attends l'analyse humaine.").
<|im_end|>"""
        
        user_prompt = f"""<|im_start|>user
### HISTORIQUE DES ACTIONS ET OBSERVATIONS
{history_str}

### TA TÂCHE
Analyse l'historique ET les règles. Quelle est la **prochaine action la plus logique et sophistiquée** ?
Pense étape par étape :
1.  Qu'est-ce que je viens d'apprendre (Observation) ?
2.  Y a-t-il une règle qui s'applique à cette observation ?
3.  Quelle est la prochaine étape logique pour augmenter ma surface d'attaque ou trouver une faille ? (ex: J'ai trouvé des sous-domaines, maintenant je dois détecter leur technologie ou scanner leurs ports).

Réponds *uniquement* avec un seul objet JSON.
<|im_end|>
<|im_start|>assistant
"""
        return system_prompt + user_prompt

    def _generate_response(self, prompt: str, max_tokens: int = 512) -> str:
        """Génère une réponse brute du modèle."""
        try:
            inputs = self.tokenizer(
                prompt,
                return_tensors="pt",
                truncation=True,
                max_length=4096 # Fenêtre de contexte de Dolphin/Mistral
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
            
            # Décoder uniquement les nouveaux tokens générés
            response = self.tokenizer.decode(
                outputs[0][len(inputs["input_ids"][0]):],
                skip_special_tokens=True
            )
            return response.strip()
            
        except Exception as e:
            logger.error(f"Erreur de génération IA : {e}")
            return f"{'error': 'Erreur de génération'}"