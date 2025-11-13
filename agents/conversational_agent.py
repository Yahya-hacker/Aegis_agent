# agents/conversational_agent.py
# --- VERSION MODIFIÉE ET CORRIGÉE ---

import asyncio
import re
import json
from typing import Dict, List, Any
import logging
from agents.field_tester import AegisFieldTester # <-- IMPORT AJOUTÉ
from agents.learning_engine import AegisLearningEngine
from utils.reasoning_display import get_reasoning_display

logger = logging.getLogger(__name__)

class AegisConversation:
    """
    Interface de conversation et orchestrateur de la BOUCLE D'AGENT AUTONOME.
    """
    
    def __init__(self, ai_core):
        self.ai_core = ai_core
        self.agent_memory = [] # Mémoire pour la boucle d'agent
        self.global_findings = [] # Stocke toutes les trouvailles
        # Initialize learning engine if not already present
        learning_engine = getattr(ai_core, 'learning_engine', None) or AegisLearningEngine()
        self.field_tester = AegisFieldTester(learning_engine) # <-- MODULE AJOUTÉ avec learning_engine
        self.reasoning_display = get_reasoning_display(verbose=True)
    
    async def start(self):
        """Démarre l'interface de conversation."""
        self._print_welcome()
        
        while True:
            try:
                user_input = await self._get_user_input()
                
                if user_input.lower() in ['quit', 'exit', 'bye']:
                    await self._handle_exit()
                    break
                elif user_input.lower() in ['help', '?']:
                    self._print_help()
                else:
                    # Lancer la boucle d'agent
                    await self.run_autonomous_loop(user_input)
                    
            except KeyboardInterrupt:
                await self._handle_exit()
                break
            except Exception as e:
                logger.error(f"Erreur de conversation : {e}", exc_info=True)
                print(f"❌ Erreur critique: {e}")
    
    async def _get_user_input(self) -> str:
        try:
            return input("\n🧑‍💻 VOUS: ").strip()
        except (EOFError, KeyboardInterrupt):
            raise

    def _extract_target(self, text: str) -> str:
        """Extrait le domaine cible."""
        url_pattern = r'https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        matches = re.findall(url_pattern, text)
        if matches:
            return next(m for m in matches[0] if m)
        return ""

    # --- NOUVELLE FONCTION POUR LES RÈGLES ---
    async def _get_bbp_rules(self) -> str:
        """Demande à l'utilisateur de coller les règles du BBP."""
        print("\n📜 Veuillez coller les règles du BBP (scope, out-of-scope, etc.).")
        print("   Appuyez sur Entrée deux fois (ligne vide) lorsque vous avez terminé.")
        
        rules = []
        while True:
            try:
                line = await self._get_user_input()
                if line == "":
                    break
                rules.append(line)
            except (EOFError, KeyboardInterrupt):
                break
        return "\n".join(rules)

    async def run_autonomous_loop(self, user_input: str):
        """
        C'EST LA BOUCLE D'AGENT PRINCIPALE.
        Penser -> Proposer -> Approuver -> Agir -> Observer
        """
        print("🤖 Aegis AI analyse la mission...")
        target = self._extract_target(user_input)
        
        if not target:
            print("❌ Cible non détectée. Essayez : 'scan example.com [règles]'")
            return
            
        # --- DÉBUT DE LA BOUCLE D'AGENT ---
        
        # !! AMÉLIORATION : Règles BBP dynamiques !!
        user_rules = await self._get_bbp_rules()
        if not user_rules:
            print("⚠️ Aucune règle fournie, l'agent fonctionnera en mode restreint.")
            user_rules = "Pas de règles fournies. Être très prudent."

        bbp_rules = f"""
        - CIBLE PRINCIPALE : {target}
        - INSTRUCTIONS UTILISATEUR : {user_input}
        - RÈGLES BBP OFFICIELLES :
        {user_rules}
        """
        
        print(f"📜 Règles chargées pour {target}.")
        
        from agents.scanner import AegisScanner
        scanner = AegisScanner(self.ai_core)
        
        # Initialise la mémoire de l'agent
        self.agent_memory = [
            {"type": "mission", "content": f"La mission est de scanner {target} en respectant les règles."},
        ]
        self.global_findings = []
        
        for step_count in range(20): # Limite à 20 étapes
            print("\n" + "="*70)
            print(f"🧠 ÉTAPE D'AGENT {step_count + 1}/20")
            
            # Show step start in reasoning display
            self.reasoning_display.show_thought(
                f"Starting autonomous step {step_count + 1} of 20",
                thought_type="planning",
                metadata={
                    "step": step_count + 1,
                    "total_steps": 20,
                    "memory_size": len(self.agent_memory),
                    "findings_count": len(self.global_findings)
                }
            )
            
            # 1. PENSER: L'IA décide de la prochaine action
            print("🧠 Aegis AI réfléchit...")
            self.reasoning_display.show_thought(
                "Agent is analyzing current state and determining next action",
                thought_type="analysis"
            )
            
            action = self.ai_core.get_next_action(bbp_rules, self.agent_memory)
            
            print(f"🤖 PROPOSITION IA : {action}")
            
            # 2. GÉRER LES ACTIONS SYSTÈME
            tool = action.get("tool")
            args = action.get("args", {})
            
            if tool == "finish_mission":
                print(f"🛡️ MISSION TERMINÉE : {args.get('reason')}")
                break
                
            if tool == "ask_user_for_approval":
                print(f"💡 REQUÊTE IA : {args.get('message')}")
                # Tombe directement dans l'approbation humaine
            
            if tool == "system" or not tool:
                print(f"⚠️ Alerte IA : {action.get('message', 'Action non valide')}")
                self.agent_memory.append({"type": "observation", "content": "J'ai généré une action invalide. Je dois réessayer."})
                continue 

            # 3. APPROBATION HUMAINE (Human-in-the-Loop)
            try:
                response = input("❓ Approuvez-vous cette action ? (o/n/q) : ").lower().strip()
            except EOFError:
                break
            
            if response in ['q', 'quit', 'exit']:
                print("🛑 Mission arrêtée par l'utilisateur.")
                break
                
            if response in ['o', 'oui', 'y', 'yes', '']:
                # 4. AGIR: Exécuter l'action
                print(f"🚀 Exécution : {tool}...")
                
                self.reasoning_display.show_thought(
                    f"Executing approved action: {tool}",
                    thought_type="execution",
                    metadata={"tool": tool, "args": args}
                )
                
                result = await scanner.execute_action(action)
                
                # 5. OBSERVER: Ajouter le résultat à la mémoire
                print(f"📝 Résultat : {result.get('status', 'error')}")
                
                if result.get("status") == "success":
                    data = result.get("data", "Aucune donnée retournée.")
                    
                    # Rendre l'observation lisible pour l'IA
                    observation = f"Action {tool} réussie."
                    if isinstance(data, list) and data:
                        observation += f" {len(data)} résultats trouvés."
                        self.global_findings.extend(data) # Ajouter à la liste globale
                        # Tronquer pour la mémoire de l'IA
                        if len(data) > 10:
                            observation += f" Voici les 10 premiers: {json.dumps(data[:10])}"
                        else:
                            observation += f" Résultats: {json.dumps(data)}"
                    elif isinstance(data, dict) and data:
                        observation += f" Résultats: {json.dumps(data)}"
                        self.global_findings.append(data) # Ajouter à la liste globale
                    else:
                        observation += " Aucun résultat trouvé."
                    
                    # Show observation in reasoning display
                    self.reasoning_display.show_thought(
                        observation,
                        thought_type="observation",
                        metadata={"action": tool, "status": "success", "results_count": len(data) if isinstance(data, list) else 1}
                    )
                        
                    self.agent_memory.append({"type": "observation", "content": observation})
                    
                else:
                    # Dire à l'IA qu'il y a eu une erreur
                    error_msg = result.get('error', 'Erreur inconnue')
                    
                    self.reasoning_display.show_thought(
                        f"Action {tool} failed: {error_msg}",
                        thought_type="error",
                        metadata={"action": tool, "error": error_msg}
                    )
                    
                    self.agent_memory.append({"type": "observation", "content": f"Action {tool} ÉCHOUÉE. Erreur: {error_msg}. Je dois essayer autre chose."})
                    
            else:
                print("❌ Action annulée par l'utilisateur.")
                
                self.reasoning_display.show_thought(
                    f"User rejected the proposed action: {tool}",
                    thought_type="decision",
                    metadata={"action": tool, "user_decision": "rejected"}
                )
                
                self.agent_memory.append({"type": "observation", "content": "L'utilisateur a REFUSÉ cette action. Je dois proposer un plan alternatif."})
        
        print("\n" + "="*70)
        print("Fin de la session de l'agent.")
        
        # --- AMÉLIORATION : Intégration du Field Tester ---
        if self.global_findings:
            print(f"\n🔍 L'agent a trouvé {len(self.global_findings)} éléments. Lancement du mode de vérification...")
            # Simplifier les 'findings' pour le field_tester
            simplified_findings = []
            for item in self.global_findings:
                if isinstance(item, dict):
                    simplified_findings.append({
                        "type": item.get("template-id", item.get("type", "Info")),
                        "target": item.get("host", item.get("location", target)),
                        "description": item.get("description", json.dumps(item))
                    })
            
            verified = await self.field_tester.enter_manual_mode(simplified_findings)
            print(f"✅ {len(verified)} vulnérabilités confirmées.")
        else:
            print("ℹ️ L'agent n'a trouvé aucune vulnérabilité exploitable.")

    # --- Fonctions utilitaires ---

    def _print_welcome(self):
        print("""
🛡️  AEGIS AI - AGENT AUTONOME DE PENTEST (v6.0 - Multi-LLM)
=============================================================
🤖 Cerveaux Multi-LLM via Together AI:
   • Llama 70B:     Planification stratégique et triage
   • Mixtral 8x7B:  Analyse vulnérabilités et exploitation
   • Qwen-coder:    Analyse code et génération de payloads
🛠️  Mode:   Autonome (Human-in-the-Loop)
🔥 Cap.:   Analyse règles, Raisonnement multi-agent, Auto-apprentissage

Exemples de commandes:
• "scan example.com"
• "bug bounty konghq.com"

Type 'help' pour commandes ou 'quit' pour sortir.
        """)
    
    def _print_help(self):
        print("""
📖 AEGIS AI COMMANDS:
====================
AUTONOMOUS SCAN:
• "scan [target]"
  -> Lance la boucle d'agent autonome. L'agent vous demandera
     de coller les règles BBP, puis proposera des actions
     étape par étape pour votre approbation.

QUICK ACTIONS:
• "help" - Affiche ce message
• "quit" - Quitte Aegis AI
        """)
    
    async def _handle_exit(self):
        print("\n🛡️ Session Aegis AI terminée.")
