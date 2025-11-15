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
            
            # PHASE 4 TASK 8: Check for tool installation confirmation requests
            if isinstance(action, dict) and action.get("confirmation_required"):
                confirmation_type = action.get("action", "unknown")
                
                if confirmation_type == "install_tool":
                    # Tool installation request
                    print("\n" + "="*70)
                    print(action.get("message", ""))
                    print("="*70)
                    
                    try:
                        user_response = input("\n❓ Do you approve this tool installation? (y/n): ").lower().strip()
                    except EOFError:
                        user_response = 'n'
                    
                    if user_response in ['y', 'yes', 'o', 'oui']:
                        print("✅ Installation approved. Executing...")
                        
                        # Execute the installation
                        from tools.tool_installer import get_tool_installer
                        installer = get_tool_installer()
                        
                        install_result = await installer._execute_install(
                            repo_url=action.get("repo_url"),
                            package_name=action.get("package_name")
                        )
                        
                        # Add result to agent memory
                        if install_result.get("status") == "success":
                            observation = f"Tool installation successful: {install_result.get('message')}"
                            print(f"✅ {observation}")
                        else:
                            observation = f"Tool installation failed: {install_result.get('error', 'Unknown error')}"
                            print(f"❌ {observation}")
                        
                        self.agent_memory.append({"type": "observation", "content": observation})
                        continue
                    else:
                        print("❌ Installation rejected by user.")
                        self.agent_memory.append({
                            "type": "observation",
                            "content": "User rejected the tool installation request. I should try a different approach."
                        })
                        continue
            
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

            # 3. APPROBATION HUMAINE (Human-in-the-Loop) with TASK 4: Semi-Autonomous Mode
            # Check if tool is intrusive
            from utils.dynamic_tool_loader import get_tool_loader
            tool_loader = get_tool_loader()
            is_intrusive = tool_loader.is_tool_intrusive(tool)
            
            # TASK 4: Auto-approve non-intrusive tools
            if not is_intrusive:
                print(f"✅ Action auto-approuvée (Reconnaissance non-intrusive)")
                response = 'o'  # Auto-approve
            else:
                # Intrusive tool: ask for approval
                print(f"⚠️ ATTENTION: Action INTRUSIVE détectée!")
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
                
                # Check if we should avoid this action based on learning
                learning_engine = getattr(self.ai_core, 'learning_engine', None)
                if learning_engine:
                    target_for_check = args.get('domain') or args.get('target') or args.get('url', 'unknown')
                    should_avoid, avoid_reason = learning_engine.should_avoid_action(tool, target_for_check)
                    if should_avoid:
                        print(f"⚠️ Warning: {avoid_reason}")
                        print(f"   Proceeding anyway as you approved it.")
                
                result = await scanner.execute_action(action)
                
                # 5. OBSERVER: Ajouter le résultat à la mémoire
                print(f"📝 Résultat : {result.get('status', 'error')}")
                
                if result.get("status") == "success":
                    data = result.get("data", "Aucune donnée retournée.")
                    
                    # Record successful action for learning
                    if learning_engine:
                        target_for_record = args.get('domain') or args.get('target') or args.get('url', 'unknown')
                        result_summary = f"{len(data)} items" if isinstance(data, list) else "data received"
                        learning_engine.record_successful_action(tool, target_for_record, result_summary)
                    
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
                    
                    # Record failed attempt for learning
                    if learning_engine:
                        target_for_record = args.get('domain') or args.get('target') or args.get('url', 'unknown')
                        learning_engine.record_failed_attempt(tool, target_for_record, error_msg)
                    
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
            print(f"\n🔍 L'agent a trouvé {len(self.global_findings)} éléments.")
            
            # ENHANCEMENT: Use vulnerability analyzer for comprehensive assessment
            from utils.vulnerability_analyzer import get_vulnerability_analyzer
            analyzer = get_vulnerability_analyzer()
            
            # Analyze and prioritize findings
            print("\n📊 Analyzing and prioritizing vulnerabilities...")
            analyzed_findings = analyzer.prioritize_findings(self.global_findings)
            
            # PHASE 3 TASK 5: AI-Enhanced Triage
            # Apply AI triage to each finding for context-aware prioritization
            print("\n🧠 Applying AI-enhanced triage...")
            ai_triaged_findings = []
            mission_context = f"""
Target: {target}
Mission Rules: {bbp_rules}
Total Findings: {len(analyzed_findings)}
Agent completed {step_count} autonomous steps
            """
            
            for idx, finding in enumerate(analyzed_findings, 1):
                print(f"  Triaging finding {idx}/{len(analyzed_findings)}: {finding.get('type', 'unknown')}", end="")
                try:
                    # Apply AI triage using the Reasoning LLM
                    triaged_finding = await self.ai_core.contextual_triage(finding, mission_context)
                    ai_triaged_findings.append(triaged_finding)
                    
                    # Show AI assessment if available
                    if triaged_finding.get('ai_triaged'):
                        ai_priority = triaged_finding['ai_triage'].get('priority', 'unknown')
                        print(f" → AI Priority: {ai_priority}")
                    else:
                        print(f" → AI triage failed, using original assessment")
                        
                except Exception as e:
                    logger.warning(f"Failed to triage finding {idx}: {e}")
                    ai_triaged_findings.append(finding)
                    print(f" → Error, using original assessment")
            
            # Use AI-triaged findings for subsequent steps
            analyzed_findings = ai_triaged_findings
            
            # Show statistics
            stats = analyzer.get_statistics(self.global_findings)
            print(f"\n📈 Vulnerability Statistics:")
            print(f"   Total findings: {stats['total']}")
            print(f"   Average risk score: {stats['average_risk_score']}/10")
            if stats['by_severity']:
                print(f"   By severity: {stats['by_severity']}")
            
            # Generate report
            report = analyzer.generate_report(self.global_findings)
            
            # Save report to file
            from pathlib import Path
            report_dir = Path("data/reports")
            report_dir.mkdir(exist_ok=True, parents=True)
            
            import time
            report_file = report_dir / f"vuln_report_{int(time.time())}.md"
            with open(report_file, 'w') as f:
                f.write(report)
            
            print(f"\n📄 Vulnerability report saved to: {report_file}")
            
            # Launch field tester for manual verification
            print(f"\n🔍 Lancement du mode de vérification...")
            # Simplifier les 'findings' pour le field_tester
            simplified_findings = []
            for item in analyzed_findings:
                # Use analyzed findings with enhanced information
                simplified_findings.append({
                    "type": item.get('type', 'Unknown'),
                    "target": item.get('url', item.get('target', target)),
                    "description": item.get('description', ''),
                    "severity": item.get('analysis', {}).get('severity', 'info'),
                    "priority": item.get('analysis', {}).get('priority', 'P4-Info'),
                    "risk_score": item.get('analysis', {}).get('risk_score', 0.0)
                })
            
            verified = await self.field_tester.enter_manual_mode(simplified_findings)
            print(f"✅ {len(verified)} vulnérabilités confirmées.")
        else:
            print("ℹ️ L'agent n'a trouvé aucune vulnérabilité exploitable.")

    # --- Fonctions utilitaires ---

    def _print_welcome(self):
        print("""
🛡️  AEGIS AI - AGENT AUTONOME DE PENTEST (v7.0 - Multi-LLM)
=============================================================
🤖 Cerveaux Multi-LLM via OpenRouter API:
   • Hermes 3 Llama 70B:     Planification stratégique et triage
   • Dolphin 3.0 Mistral 24B: Analyse vulnérabilités et exploitation
   • Qwen 2.5 72B:           Analyse code et génération de payloads
🛠️  Mode:   Semi-Autonome (Recon auto-approuvée, Exploitation sur approbation)
🔥 Cap.:   Session authentifiée, Base de données stratégique, Auto-apprentissage

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
