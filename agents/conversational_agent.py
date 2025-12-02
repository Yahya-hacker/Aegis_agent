# agents/conversational_agent.py
# --- MODIFIED AND CORRECTED VERSION ---

import asyncio
import re
import json
from typing import Dict, List, Any
import logging
from agents.field_tester import AegisFieldTester # <-- IMPORT ADDED
from agents.learning_engine import AegisLearningEngine
from utils.reasoning_display import get_reasoning_display

logger = logging.getLogger(__name__)

class AegisConversation:
    """
    Conversation interface and AUTONOMOUS AGENT LOOP orchestrator.
    """
    
    def __init__(self, ai_core):
        self.ai_core = ai_core
        self.agent_memory = [] # Memory for agent loop
        self.global_findings = [] # Stores all findings
        # Initialize learning engine if not already present
        learning_engine = getattr(ai_core, 'learning_engine', None) or AegisLearningEngine()
        self.field_tester = AegisFieldTester(learning_engine) # <-- MODULE ADDED with learning_engine
        self.reasoning_display = get_reasoning_display(verbose=True)
    
    async def start(self):
        """Starts the conversation interface."""
        self._print_welcome()
        
        # Conversation history for triage_mission
        conversation_history = []
        
        while True:
            try:
                user_input = await self._get_user_input()
                
                if user_input.lower() in ['quit', 'exit', 'bye']:
                    await self._handle_exit()
                    break
                elif user_input.lower() in ['help', '?']:
                    self._print_help()
                else:
                    # Add user input to conversation history
                    conversation_history.append({
                        "role": "user",
                        "content": user_input
                    })
                    
                    # Use triage_mission to determine if we're ready to start
                    triage_result = await self.ai_core.triage_mission(conversation_history)
                    
                    if triage_result.get("response_type") == "question":
                        # AI needs more information - print question and continue loop
                        ai_question = triage_result.get("text", "Please provide more information.")
                        print(f"\n🤖 Aegis AI: {ai_question}")
                        
                        # Add AI response to conversation history
                        conversation_history.append({
                            "role": "assistant",
                            "content": ai_question
                        })
                        
                    elif triage_result.get("response_type") == "start_mission":
                        # AI has all information - extract and start mission
                        target = triage_result.get("target", "")
                        rules = triage_result.get("rules", "")
                        
                        if not target:
                            print("❌ Error: Target not extracted by triage.")
                            continue
                        
                        print(f"\n✅ Mission ready to start!")
                        print(f"   Target: {target}")
                        print(f"   Rules: {rules[:100]}...")
                        
                        # Start the autonomous loop with extracted information
                        await self.run_autonomous_loop_with_triage(target, rules)
                        
                        # Clear conversation history after mission completes
                        conversation_history = []
                        
                    elif triage_result.get("response_type") == "error":
                        error_msg = triage_result.get("text", "Unknown error")
                        print(f"❌ Triage error: {error_msg}")
                        
                        # Add error to conversation history
                        conversation_history.append({
                            "role": "assistant",
                            "content": f"Error: {error_msg}"
                        })
                    else:
                        print(f"⚠️ Unexpected response type: {triage_result.get('response_type')}")
                    
            except KeyboardInterrupt:
                await self._handle_exit()
                break
            except Exception as e:
                logger.error(f"Conversation error : {e}", exc_info=True)
                print(f"❌ Critical error: {e}")
    
    async def _get_user_input(self) -> str:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, lambda: input("\n🧑‍💻 YOU: ").strip())
        except (EOFError, KeyboardInterrupt):
            raise

    def _extract_target(self, text: str) -> str:
        """Extracts the target domain."""
        url_pattern = r'https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        matches = re.findall(url_pattern, text)
        if matches:
            return next(m for m in matches[0] if m)
        return ""

    async def run_autonomous_loop_with_triage(self, target: str, rules: str):
        """
        THIS IS THE MAIN AGENT LOOP (refactored to use triage_mission).
        Think -> Propose -> Approve -> Act -> Observe
        
        Args:
            target: Target extracted by triage_mission
            rules: Rules/scope extracted by triage_mission
        """
        print(f"\n🤖 Aegis AI starting autonomous mission for {target}...")
        
        # --- START OF AGENT LOOP ---
        
        bbp_rules = f"""
        - MAIN TARGET : {target}
        - OFFICIAL BBP RULES :
        {rules}
        """
        
        print(f"📜 Rules loaded for {target}.")
        
        from agents.scanner import AegisScanner
        scanner = AegisScanner(self.ai_core)
        
        # Initializes agent memory
        self.agent_memory = [
            {"type": "mission", "content": f"The mission is to scan {target} while respecting the rules."},
        ]
        self.global_findings = []

        # --- PHASE 0: VISUAL RECONNAISSANCE & INITIAL PLANNING ---
        print("\n" + "="*70)
        print("👁️ PHASE 0: VISUAL RECONNAISSANCE & INITIAL PLANNING")
        print("="*70)
        
        # 1. Take Screenshot & Analyze
        print("📸 Screenshot capture and structural analysis...")
        self.reasoning_display.show_thought(
            "Performing initial visual reconnaissance to understand target structure",
            thought_type="observation"
        )
        
        # Create a visual recon action
        visual_action = {
            "tool": "capture_screenshot_som",
            "args": {
                "url": target,
                "full_page": False
            }
        }
        
        visual_result = await scanner.execute_action(visual_action)
        
        if visual_result.get("status") == "success":
            print("✅ Visual analysis completed.")
            # We don't print the full base64 or mapping, just a summary
            element_count = len(visual_result.get("element_mapping", {}))
            print(f"   • {element_count} interactive elements identified")
            
            # Add to memory
            self.agent_memory.append({
                "type": "observation", 
                "content": f"Initial Visual Analysis of {target}: Found {element_count} interactive elements. Screenshot captured."
            })
            
            # 2. Generate Customized Plan
            print("📝 Generating customized plan...")
            self.reasoning_display.show_thought(
                "Generating customized mission plan based on visual analysis and rules",
                thought_type="planning"
            )
            
            # Inject a specific instruction for the first step to force planning
            self.agent_memory.append({
                "type": "system_instruction",
                "content": f"""
                BASED ON THE VISUAL ANALYSIS OF {target} AND BBP RULES:
                1. ANALYZE the application structure (e.g., Login page, Dashboard, E-commerce).
                2. GENERATE a customized execution plan.
                3. DO NOT run tools sequentially without reason.
                4. IF BBP rules say "No DoS", use stealthy options.
                5. IF you struggle, STOP, reason, and change approach.
                
                YOUR FIRST ACTION MUST BE TO OUTPUT THE PLAN.
                """
            })
            
        else:
            print(f"⚠️ Initial visual analysis failed: {visual_result.get('error')}")
            self.agent_memory.append({
                "type": "observation",
                "content": f"Initial visual recon failed: {visual_result.get('error')}. Proceeding with standard recon."
            })
        
        for step_count in range(20): # Limit to 20 steps
            print("\n" + "="*70)
            print(f"🧠 AGENT STEP {step_count + 1}/20")
            
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
            
            # 1. THINK: AI decides next action
            print("🧠 Aegis AI is thinking...")
            self.reasoning_display.show_thought(
                "Agent is analyzing current state and determining next action",
                thought_type="analysis"
            )
            
            action = await self.ai_core.get_next_action_async(bbp_rules, self.agent_memory)
            
            print(f"🤖 AI PROPOSAL : {action}")
            
            # PHASE 4 TASK 8: Check for tool installation confirmation requests
            if isinstance(action, dict) and action.get("confirmation_required"):
                confirmation_type = action.get("action", "unknown")
                
                if confirmation_type == "install_tool":
                    # Tool installation request
                    print("\n" + "="*70)
                    print(action.get("message", ""))
                    print("="*70)
                    
                    try:
                        loop = asyncio.get_event_loop()
                        user_response = await loop.run_in_executor(None, lambda: input("\n❓ Do you approve this tool installation? (y/n): ").lower().strip())
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
            
            # 2. HANDLE SYSTEM ACTIONS
            tool = action.get("tool")
            args = action.get("args", {})
            
            if tool == "finish_mission":
                print(f"🛡️ MISSION COMPLETED : {args.get('reason')}")
                break
                
            if tool == "ask_user_for_approval":
                print(f"💡 AI REQUEST : {args.get('message')}")
                # Falls directly into human approval
            
            if tool == "system" or not tool:
                print(f"⚠️ AI Alert : {action.get('message', 'Invalid action')}")
                self.agent_memory.append({"type": "observation", "content": "I generated an invalid action. I must retry."})
                continue 

            # 3. HUMAN APPROVAL (Human-in-the-Loop) with TASK 4: Semi-Autonomous Mode
            # Check if tool is intrusive
            from utils.dynamic_tool_loader import get_tool_loader
            tool_loader = get_tool_loader()
            is_intrusive = tool_loader.is_tool_intrusive(tool)
            
            # TASK 4: Auto-approve non-intrusive tools
            if not is_intrusive:
                print(f"✅ Action auto-approved (Non-intrusive reconnaissance)")
                response = 'o'  # Auto-approve
            else:
                # Intrusive tool: ask for approval
                print(f"⚠️ WARNING: INTRUSIVE Action detected!")
                try:
                    loop = asyncio.get_event_loop()
                    response = await loop.run_in_executor(None, lambda: input("❓ Do you approve this action? (y/n/q) : ").lower().strip())
                except EOFError:
                    break
            
            if response in ['q', 'quit', 'exit']:
                print("🛑 Mission stopped by user.")
                break
                
            if response in ['o', 'oui', 'y', 'yes', '']:
                # 4. ACT: Execute action
                print(f"🚀 Execution : {tool}...")
                
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
                
                # BLACKBOARD MEMORY: Extract facts from tool output
                if result.get("status") == "success":
                    try:
                        mission_context = f"Target: {target}, Rules: {bbp_rules}"
                        await self.ai_core.extract_facts_from_output(tool, result, mission_context)
                    except Exception as e:
                        logger.warning(f"Failed to extract facts: {e}")
                
                # 5. OBSERVE: Add result to memory
                print(f"📝 Result : {result.get('status', 'error')}")
                
                if result.get("status") == "success":
                    data = result.get("data", "No data returned.")
                    
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
                    # Tell AI there was an error
                    error_msg = result.get('error', 'Unknown error')
                    
                    # Record failed attempt for learning
                    if learning_engine:
                        target_for_record = args.get('domain') or args.get('target') or args.get('url', 'unknown')
                        learning_engine.record_failed_attempt(tool, target_for_record, error_msg)
                    
                    self.reasoning_display.show_thought(
                        f"Action {tool} failed: {error_msg}",
                        thought_type="error",
                        metadata={"action": tool, "error": error_msg}
                    )
                    
                    self.agent_memory.append({"type": "observation", "content": f"Action {tool} FAILED. Error: {error_msg}. I must try something else."})
                    
            else:
                print("❌ Action cancelled by user.")
                
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
🛡️  AEGIS AI - AUTONOMOUS PENTEST AGENT (v8.0 - Multi-LLM)
=============================================================
🤖 Multi-LLM Brains via OpenRouter API:
   • Hermes 3 Llama 70B:     Strategic planning and triage
   • Dolphin 3.0 Mistral 24B: Vulnerability analysis and exploitation
   • Qwen 2.5 72B:           Code analysis and payload generation
🛠️  Mode:   Semi-Autonomous (Auto-approved Recon, Exploitation on approval)
🔥 Cap.:   Authenticated Session, Strategic Database, Self-Learning

Example commands:
• "scan example.com"
• "bug bounty konghq.com"

Type 'help' for commands or 'quit' to exit.
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
