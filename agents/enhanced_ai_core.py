# agents/enhanced_ai_core.py
# --- VERSION 7.0 - OpenRouter Multi-LLM Enhanced ---

import asyncio
import json
import re
import os
from typing import Dict, List, Any
import logging
from agents.learning_engine import AegisLearningEngine
from agents.multi_llm_orchestrator import MultiLLMOrchestrator
from utils.reasoning_display import get_reasoning_display
from utils.database_manager import get_database

logger = logging.getLogger(__name__)

# CRITICAL: Model constants for OpenRouter API - Load from environment or use defaults
ORCHESTRATOR_MODEL = os.getenv("ORCHESTRATOR_MODEL", "nousresearch/hermes-3-llama-3.1-70b")
# CODER_MODEL can override CODE_MODEL for specialized coding tasks (e.g., Dolphin-Deepseek)
CODE_MODEL = os.getenv("CODER_MODEL", os.getenv("CODE_MODEL", "qwen/qwen-2.5-72b-instruct"))
REASONING_MODEL = os.getenv("REASONING_MODEL", "cognitivecomputations/dolphin3.0-r1-mistral-24b")

class EnhancedAegisAI:
    """
    Enhanced AI Core v7.0 - Powered by Three Specialized LLMs via OpenRouter
    
    This class orchestrates three LLMs from OpenRouter API:
    1. Hermes 3 Llama 70B - Strategic planning, triage, and decision-making
    2. Dolphin 3.0 R1 Mistral 24B - Reasoning and vulnerability analysis  
    3. Qwen 2.5 72B - Code analysis and payload generation
    """
    
    def __init__(self, learning_engine: AegisLearningEngine = None):
        self.orchestrator = MultiLLMOrchestrator()
        self.learning_engine = learning_engine or AegisLearningEngine()
        self.learned_patterns = ""
        self.is_initialized = False
        self.reasoning_display = get_reasoning_display(verbose=True)
        self.conversation_history = []  # Added for memory management
        self.dynamic_tool_prompt = ""  # TASK 3: Dynamic tool prompt
        self.max_history_size = 10  # Maximum conversation history to keep
        self.context_summary = None  # Summary of older context
        self.db = get_database()  # TASK 2: Mission database integration
        
        # PHASE 2: Business logic mapper for application-specific testing
        from utils.business_logic_mapper import get_business_logic_mapper
        self.logic_mapper = get_business_logic_mapper()
    
    async def initialize(self):
        """Initialize the enhanced AI core with all LLMs"""
        try:
            logger.info("🚀 Initializing Enhanced Aegis AI with Multi-LLM support...")
            
            # Initialize the orchestrator
            await self.orchestrator.initialize()
            
            # TASK 3: Load dynamic tool prompt
            from utils.dynamic_tool_loader import get_tool_loader
            tool_loader = get_tool_loader()
            self.dynamic_tool_prompt = tool_loader.build_dynamic_tool_prompt()
            logger.info("✅ Dynamic tool prompt loaded.")
            
            # Load learned patterns if learning engine is available
            if self.learning_engine:
                logger.info("🧠 Loading learned patterns from previous missions...")
                try:
                    loop = asyncio.get_event_loop()
                    self.learned_patterns = await loop.run_in_executor(
                        None, self.learning_engine.load_learned_patterns
                    )
                    logger.info("✅ Learned patterns loaded.")
                except AttributeError:
                    logger.warning("⚠️ load_learned_patterns method not available, skipping.")
                    self.learned_patterns = ""
            
            self.is_initialized = True
            logger.info("✅ Enhanced AI Core ready with multi-LLM support.")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize Enhanced AI Core: {e}", exc_info=True)
            raise
    
    def _prune_memory(self, history: List[Dict]) -> List[Dict]:
        """
        Enhanced memory management to prevent "Digital Alzheimer's"
        Keeps recent detailed interactions and maintains contextual summary
        
        Args:
            history: Full conversation history
            
        Returns:
            Pruned history with summary of old interactions
        """
        if len(history) <= self.max_history_size:
            return history
        
        # Keep the last max_history_size interactions
        recent = history[-self.max_history_size:]
        
        # Summarize older interactions if we haven't done so recently
        older = history[:-self.max_history_size]
        
        # Extract key information from older interactions
        key_findings = []
        key_decisions = []
        for item in older:
            content = item.get('content', '')
            if 'vulnerability' in content.lower() or 'finding' in content.lower():
                key_findings.append(content[:100])  # First 100 chars
            if 'decision' in content.lower() or 'action' in content.lower():
                key_decisions.append(content[:100])
        
        # Build comprehensive summary
        summary_parts = [
            f"[Context from {len(older)} previous interactions:",
            f"Key findings: {len(key_findings)}",
            f"Key decisions: {len(key_decisions)}"
        ]
        
        if key_findings:
            summary_parts.append(f"Notable findings: {', '.join(key_findings[:3])}")
        
        summary_content = " ".join(summary_parts) + "]"
        
        # Create a summary entry
        summary_entry = {
            "role": "system",
            "content": summary_content
        }
        
        return [summary_entry] + recent
    
    # --- LEVEL 1: STRATEGIC TRIAGE (using Llama 70B) ---
    async def triage_mission(self, conversation_history: List[Dict]) -> Dict:
        """
        Analyzes conversation and determines if mission is ready
        Uses Llama 70B for strategic planning and decision-making
        """
        if not self.is_initialized:
            return {"response_type": "error", "text": "AI not initialized."}
        
        # Show reasoning about mission triage
        self.reasoning_display.show_thought(
            "Analyzing conversation to determine mission readiness",
            thought_type="strategic",
            metadata={
                "conversation_length": len(conversation_history),
                "function": "triage_mission"
            }
        )
        
        system_prompt = """You are Aegis AI, a cybersecurity mission planner. Your goal is to gather ALL necessary information before launching a mission.

Required information:
1. **TARGET** (e.g., "example.com", "192.168.1.1", or a file like "image.png")
2. **RULES** (e.g., scope, out-of-scope, rate limits, CTF rules)

YOUR TASK:
- Analyze the conversation history
- If information is missing, ask a CLEAR and CONCISE question
- When user provides information, acknowledge it and ask for what's next
- **DO NOT start any scans yourself**

**ONCE YOU HAVE ALL INFORMATION (TARGET + RULES)**, respond ONLY with this JSON:
```json
{
  "response_type": "start_mission",
  "target": "[the main target]",
  "rules": "[summary of all rules and instructions]"
}
```

If information is missing, respond with:
```json
{
  "response_type": "question",
  "text": "[your question to the user]"
}
```"""

        # Convert conversation history to message format
        conversation_text = "\n".join([
            f"{msg.get('role', 'user')}: {msg.get('content', '')}"
            for msg in conversation_history
        ])
        
        user_message = f"""Conversation history:
{conversation_text}

Analyze this conversation and determine if we have all information (target and rules) to start the mission. Respond with the appropriate JSON."""

        try:
            response = await self.orchestrator.execute_task(
                task_type='triage',
                system_prompt=system_prompt,
                user_message=user_message,
                temperature=0.7,
                max_tokens=1024
            )
            
            content = response['content']
            
            # Extract JSON from response
            json_match = re.search(r'```json\s*(\{.*?\})\s*```', content, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group(1))
                
                # Show reasoning about the triage decision
                self.reasoning_display.show_thought(
                    f"Triage decision: {result.get('response_type', 'unknown')}",
                    thought_type="decision",
                    metadata=result
                )
                
                return result
            
            # Try to parse as direct JSON
            try:
                result = json.loads(content)
                
                # Show reasoning about the triage decision
                self.reasoning_display.show_thought(
                    f"Triage decision: {result.get('response_type', 'unknown')}",
                    thought_type="decision",
                    metadata=result
                )
                
                return result
            except json.JSONDecodeError:
                # Fallback: treat as conversational response
                result = {
                    "response_type": "question",
                    "text": content
                }
                
                self.reasoning_display.show_thought(
                    "Could not parse as JSON, treating as conversational response",
                    thought_type="warning",
                    metadata={"raw_response": content[:200]}
                )
                
                return result
                
        except Exception as e:
            logger.error(f"Error in triage_mission: {e}", exc_info=True)
            return {
                "response_type": "error",
                "text": f"Error analyzing mission: {str(e)}"
            }
    
    # --- LEVEL 2: AUTONOMOUS AGENT (using Mixtral 8x7B) ---
    def get_next_action(self, bbp_rules: str, agent_memory: List[Dict]) -> Dict:
        """
        Decides the next action based on BBP rules and agent memory
        Uses Mixtral 8x7B for vulnerability analysis and exploitation planning
        
        Note: This is synchronous to maintain compatibility with existing code
        """
        # Run async function in sync context
        return asyncio.run(self._get_next_action_async(bbp_rules, agent_memory))
    
    async def _get_next_action_async(self, bbp_rules: str, agent_memory: List[Dict]) -> Dict:
        """Async implementation of get_next_action"""
        if not self.is_initialized:
            return {"tool": "system", "message": "AI not initialized"}
        
        # TASK 1: Prune memory to prevent unlimited growth
        agent_memory = self._prune_memory(agent_memory)
        
        # TASK 2: Get database statistics for context awareness
        db_stats = self.db.get_statistics()
        scanned_targets = self.db.get_scanned_targets()
        
        # Build database context string
        db_context = f"""
DATABASE STATUS (Avoid Duplicate Work):
- Total scanned targets: {db_stats.get('total_scanned_targets', 0)}
- Total findings: {db_stats.get('total_findings', 0)}
- Verified findings: {db_stats.get('verified_findings', 0)}
"""
        if scanned_targets:
            recent_scans = scanned_targets[:5]  # Last 5 scans
            db_context += "\nRecent scans (avoid duplicating):\n"
            for scan in recent_scans:
                db_context += f"  - {scan['target']} ({scan['scan_type']}) at {scan['scanned_at']}\n"
        
        # Show reasoning about next action decision
        self.reasoning_display.show_thought(
            "Determining next action based on mission rules and agent memory",
            thought_type="tactical",
            metadata={
                "memory_items": len(agent_memory),
                "last_observation": agent_memory[-1] if agent_memory else None,
                "db_stats": db_stats
            }
        )
        
        system_prompt = f"""You are an advanced autonomous penetration testing agent with sophisticated reasoning capabilities.
Your task is to decide the next action based on mission rules, observations, and learned patterns.

MISSION RULES:
{bbp_rules}

{db_context}

LEARNED PATTERNS FROM PREVIOUS MISSIONS:
{self.learned_patterns}

{self.dynamic_tool_prompt}

{self.logic_mapper.get_testable_functions()}

PHASE 4 - MULTIMODAL CAPABILITIES:
You now have access to visual reconnaissance tools for analyzing web interfaces:
- visual_recon.capture_screenshot(url, full_page=True/False): Capture authenticated screenshots
- visual_recon.get_dom_snapshot(url, selectors=[]): Extract DOM elements and analyze page structure
- logic_tester.test_logic_flow(flow_name, steps, expected_behavior): Test business logic for vulnerabilities

Use these tools when:
- You need to understand the visual layout or UI of a target
- You want to analyze client-side elements that might not be visible in HTTP responses
- You're testing multi-step business workflows for logic flaws
- You need to verify visual elements or CAPTCHA-type protections

ENHANCED MULTI-STAGE REASONING FRAMEWORK:

STAGE 1 - DEEP ANALYSIS:
1. Current State Assessment:
   - What has been accomplished so far?
   - What vulnerabilities or findings have been discovered?
   - What areas remain unexplored?
   - What patterns or anomalies are present in the results?
   - Are there any dead ends or rabbit holes to avoid?
   - Check the DATABASE STATUS above to avoid duplicate scans!

2. Information Gap Analysis:
   - What critical information is missing?
   - What assumptions are we making?
   - What dependencies exist between discoveries?
   - What could we be overlooking?

STAGE 2 - STRATEGIC PLANNING:
1. Multi-Path Exploration:
   - Generate 3-5 possible next actions
   - Evaluate each action's potential value
   - Consider both breadth (new attack surfaces) and depth (following leads)
   - Assess resource cost vs expected gain

2. Prioritization Framework:
   - Severity: Which actions target high-impact vulnerabilities?
   - Likelihood: Which actions have the highest success probability?
   - Coverage: Which areas need more comprehensive testing?
   - Efficiency: Which actions provide maximum insight with minimal effort?

STAGE 3 - RISK ASSESSMENT:
1. Scope Compliance:
   - Does this action stay within the authorized scope?
   - Are there any out-of-scope dependencies?
   - What are the potential unintended consequences?

2. Technical Risk:
   - Could this action cause service disruption?
   - What is the intrusive level of this action?
   - Are there safer alternatives?

STAGE 4 - DECISION MAKING:
1. Select the optimal action that:
   - Maximizes detection chances
   - Follows a logical progression
   - Respects mission rules and scope
   - Provides actionable intelligence
   - Balances thoroughness with efficiency

2. Adaptive Learning:
   - Learn from previous failed attempts
   - Adjust strategy based on target behavior
   - Recognize when to pivot vs persist

STAGE 5 - REFLECTION:
1. Self-Assessment:
   - Is this the best possible action right now?
   - What could go wrong?
   - What fallback options exist?
   - How will this contribute to the overall mission?

CRITICAL INSTRUCTIONS:
- Show ALL your reasoning through each stage
- Explain WHY you chose this specific action over alternatives
- Consider edge cases and potential obstacles
- Follow the rules STRICTLY (no out-of-scope testing)
- If mission is complete, use finish_mission
- If uncertain or need guidance, use ask_user_for_approval
- Be thorough, methodical, and intelligent in your approach
- Learn from past observations and avoid repeating failed attempts

⚠️ STRICT GROUNDING RULE (ANTI-HALLUCINATION) ⚠️
You can ONLY attack targets that explicitly exist in the 'DATABASE STATUS' list provided above.
When proposing an action, you MUST cite the specific 'target_id' or exact string from the database context.
If you want to attack a new target, you must first run 'subdomain_enumeration' to find it and add it to the DB.
DO NOT invent URLs, domains, or targets that are not present in the database or mission context.
ANY action targeting a URL/domain MUST reference an existing entry from the scanned targets list.

Respond with JSON ONLY including comprehensive multi-stage reasoning:
```json
{{
  "tool": "tool_name",
  "args": {{"param": "value"}},
  "reasoning": {{
    "analysis": "Deep analysis of current state, findings, and patterns",
    "options_considered": ["option1", "option2", "option3"],
    "selected_option": "tool_name",
    "justification": "Why this option is optimal: expected outcomes, strategic fit, risk assessment",
    "expected_outcome": "What we expect to discover or achieve",
    "fallback_plan": "What to do if this action fails or doesn't yield results",
    "mission_progress": "How this action advances the overall mission objectives"
  }}
}}
```"""

        # Format agent memory
        memory_text = "\n".join([
            f"[{mem.get('type', 'unknown')}] {mem.get('content', '')}"
            for mem in agent_memory[-10:]  # Last 10 observations
        ])
        
        user_message = f"""Agent memory:
{memory_text}

Based on this context, what should be the next action? Respond with JSON only."""

        try:
            response = await self.orchestrator.execute_task(
                task_type='next_action',
                system_prompt=system_prompt,
                user_message=user_message,
                temperature=0.8,
                max_tokens=1024
            )
            
            content = response['content']
            
            # Extract JSON from response
            json_match = re.search(r'```json\s*(\{.*?\})\s*```', content, re.DOTALL)
            if json_match:
                action = json.loads(json_match.group(1))
                
                # Display the proposed action with reasoning
                self.reasoning_display.show_action_proposal(
                    action=action,
                    reasoning=action.get('reasoning', 'No explicit reasoning provided')
                )
                
                return action
            
            # Try direct JSON parse
            try:
                action = json.loads(content)
                
                # Display the proposed action with reasoning
                self.reasoning_display.show_action_proposal(
                    action=action,
                    reasoning=action.get('reasoning', 'No explicit reasoning provided')
                )
                
                return action
            except json.JSONDecodeError:
                logger.warning(f"Could not parse action as JSON: {content}")
                
                self.reasoning_display.show_thought(
                    f"Failed to parse LLM response as action JSON",
                    thought_type="error",
                    metadata={"raw_response": content[:200]}
                )
                
                return {
                    "tool": "system",
                    "message": "Failed to parse action. Please reformulate."
                }
                
        except Exception as e:
            logger.error(f"Error getting next action: {e}", exc_info=True)
            return {
                "tool": "system",
                "message": f"Error: {str(e)}"
            }
    
    # --- LEVEL 3: CODE ANALYSIS (using Qwen-coder) ---
    async def analyze_code(self, code: str, context: str = "") -> Dict[str, Any]:
        """
        Analyzes code for vulnerabilities
        Uses Qwen-coder for deep code analysis
        """
        if not self.is_initialized:
            return {"error": "AI not initialized"}
        
        system_prompt = """You are an expert code analyst specialized in security vulnerabilities.
Analyze the provided code and identify:
1. Security vulnerabilities
2. Potential exploits
3. Weaknesses in implementation
4. Recommended fixes

Provide detailed analysis with severity ratings."""

        user_message = f"""Context: {context}

Code to analyze:
```
{code}
```

Provide a comprehensive security analysis."""

        try:
            response = await self.orchestrator.execute_task(
                task_type='code_analysis',
                system_prompt=system_prompt,
                user_message=user_message,
                temperature=0.6,
                max_tokens=2048
            )
            
            return {
                "analysis": response['content'],
                "model_used": response['role']
            }
            
        except Exception as e:
            logger.error(f"Error analyzing code: {e}", exc_info=True)
            return {"error": str(e)}
    
    # --- LEVEL 4: PAYLOAD GENERATION (using Qwen-coder) ---
    async def generate_payload(
        self,
        vulnerability_type: str,
        target_info: Dict[str, Any],
        constraints: List[str] = None
    ) -> Dict[str, Any]:
        """
        Generates exploit payloads for a specific vulnerability
        Uses Qwen-coder for technical payload engineering
        """
        if not self.is_initialized:
            return {"error": "AI not initialized"}
        
        constraints_text = "\n".join(constraints) if constraints else "No specific constraints"
        
        system_prompt = f"""You are an expert payload engineer for penetration testing.
Generate safe, educational payloads for vulnerability testing.
Always include:
1. The payload code/string
2. How to use it
3. Expected result
4. Safety considerations"""

        user_message = f"""Generate a payload for:
Vulnerability Type: {vulnerability_type}
Target Information: {json.dumps(target_info, indent=2)}
Constraints: {constraints_text}

Provide multiple payload variants if applicable."""

        try:
            response = await self.orchestrator.execute_task(
                task_type='payload_generation',
                system_prompt=system_prompt,
                user_message=user_message,
                temperature=0.7,
                max_tokens=2048
            )
            
            return {
                "payloads": response['content'],
                "model_used": response['role']
            }
            
        except Exception as e:
            logger.error(f"Error generating payload: {e}", exc_info=True)
            return {"error": str(e)}
    
    # --- SPECIALIZED MODEL CALLS (using explicit model constants) ---
    
    async def call_code_specialist(
        self,
        prompt: str,
        context: str = "",
        temperature: float = 0.6,
        max_tokens: int = 2048,
        model_override: str = None
    ) -> Dict[str, Any]:
        """
        Call the code specialist model explicitly
        Uses CODE_MODEL constant to ensure correct model
        
        Args:
            prompt: The code analysis or generation prompt
            context: Additional context
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            model_override: Override model (should be CODE_MODEL)
            
        Returns:
            Response dictionary
        """
        if not self.is_initialized:
            return {"error": "AI not initialized"}
        
        # Use explicit model constant
        model_to_use = model_override if model_override else CODE_MODEL
        
        # Ensure the model override matches our approved model
        if model_override and model_override != CODE_MODEL:
            logger.warning(f"⚠️ Model override '{model_override}' does not match CODE_MODEL '{CODE_MODEL}'")
        
        system_prompt = f"""You are an expert code analyst and payload engineer for penetration testing.
{context}"""
        
        try:
            # Call the coder LLM directly with explicit model
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
            
            response = await self.orchestrator.call_llm(
                'coder',
                messages,
                temperature=temperature,
                max_tokens=max_tokens
            )
            
            return {
                "content": response['content'],
                "model_used": response['model'],
                "role": response['role']
            }
            
        except Exception as e:
            logger.error(f"Error calling code specialist: {e}", exc_info=True)
            return {"error": str(e)}
    
    async def call_reasoning_specialist(
        self,
        prompt: str,
        context: str = "",
        temperature: float = 0.7,
        max_tokens: int = 2048,
        model_override: str = None
    ) -> Dict[str, Any]:
        """
        Call the reasoning specialist model explicitly
        Uses REASONING_MODEL constant to ensure correct model
        
        Args:
            prompt: The reasoning or analysis prompt
            context: Additional context
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            model_override: Override model (should be REASONING_MODEL)
            
        Returns:
            Response dictionary
        """
        if not self.is_initialized:
            return {"error": "AI not initialized"}
        
        # Use explicit model constant
        model_to_use = model_override if model_override else REASONING_MODEL
        
        # Ensure the model override matches our approved model
        if model_override and model_override != REASONING_MODEL:
            logger.warning(f"⚠️ Model override '{model_override}' does not match REASONING_MODEL '{REASONING_MODEL}'")
        
        system_prompt = f"""You are an expert reasoning and vulnerability analysis specialist.
{context}"""
        
        try:
            # Call the vulnerability/reasoning LLM directly with explicit model
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
            
            response = await self.orchestrator.call_llm(
                'vulnerability',
                messages,
                temperature=temperature,
                max_tokens=max_tokens
            )
            
            return {
                "content": response['content'],
                "model_used": response['model'],
                "role": response['role']
            }
            
        except Exception as e:
            logger.error(f"Error calling reasoning specialist: {e}", exc_info=True)
            return {"error": str(e)}
    
    # --- COLLABORATIVE ANALYSIS ---
    async def collaborative_vulnerability_assessment(
        self,
        target: str,
        findings: List[Dict]
    ) -> Dict[str, Any]:
        """
        Performs collaborative analysis using all three LLMs
        Each provides its specialized perspective
        """
        if not self.is_initialized:
            return {"error": "AI not initialized"}
        
        findings_summary = json.dumps(findings, indent=2)
        context = f"Target: {target}\nFindings: {findings_summary}"
        
        strategic_q = f"Based on these findings, what should be our strategic priorities and overall risk assessment?"
        vulnerability_q = f"Analyze these vulnerabilities: which are most critical and what exploitation paths exist?"
        coding_q = f"For the technical findings, what payloads or exploits should we develop to validate them?"
        
        try:
            results = await self.orchestrator.collaborative_analysis(
                context=context,
                strategic_question=strategic_q,
                vulnerability_question=vulnerability_q,
                coding_question=coding_q
            )
            
            return {
                "strategic_assessment": results['strategic']['content'],
                "vulnerability_analysis": results['vulnerability']['content'],
                "technical_recommendations": results['coder']['content']
            }
            
        except Exception as e:
            logger.error(f"Error in collaborative assessment: {e}", exc_info=True)
            return {"error": str(e)}
    
    # --- AI-ENHANCED TRIAGE ---
    async def contextual_triage(
        self,
        finding: Dict,
        mission_context: str
    ) -> Dict[str, Any]:
        """
        AI-enhanced triage using the Reasoning LLM to re-assess vulnerability priority
        
        This method takes a vulnerability finding and mission context, then uses the
        Reasoning specialist to provide an AI-enhanced assessment of true priority,
        exploitability, and business impact.
        
        Args:
            finding: Vulnerability finding dictionary with type, description, severity, etc.
            mission_context: Mission context including target, goals, and constraints
            
        Returns:
            Enhanced finding with AI-triaged priority and assessment
        """
        if not self.is_initialized:
            return {"error": "AI not initialized"}
        
        logger.info(f"🧠 AI Triage: Analyzing {finding.get('type', 'unknown')} vulnerability")
        
        # Build context for the reasoning LLM
        finding_summary = json.dumps(finding, indent=2)
        
        triage_prompt = f"""You are an expert security analyst performing vulnerability triage.

MISSION CONTEXT:
{mission_context}

VULNERABILITY FINDING:
{finding_summary}

Your task is to re-assess this vulnerability's TRUE PRIORITY considering:
1. The specific mission context and target
2. Real-world exploitability (not just theoretical severity)
3. Business impact in this specific scenario
4. Likelihood of successful exploitation
5. Effort required vs potential gain

Provide your assessment as JSON with this EXACT structure:
{{
  "priority": "P0-Critical|P1-High|P2-Medium|P3-Low|P4-Info",
  "risk_score": 0.0-10.0,
  "exploitability": "trivial|easy|moderate|difficult|very_difficult",
  "business_impact": "critical|high|medium|low|minimal",
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation of your assessment",
  "recommended_actions": ["action1", "action2"],
  "should_verify": true|false,
  "verification_priority": 1-10
}}

Respond with ONLY the JSON, no additional text."""
        
        try:
            # Call the reasoning specialist for intelligent triage
            response = await self.call_reasoning_specialist(
                prompt=triage_prompt,
                context="Vulnerability triage and prioritization",
                temperature=0.6,  # Lower temperature for more focused analysis
                max_tokens=1024
            )
            
            content = response.get('content', '')
            
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                triage_result = json.loads(json_match.group(0))
                
                # Enhance the original finding with AI triage
                enhanced_finding = {
                    **finding,
                    'ai_triage': triage_result,
                    'ai_triaged': True,
                    'triage_model': response.get('model_used', 'unknown')
                }
                
                logger.info(f"✅ AI Triage complete: {triage_result.get('priority', 'unknown')} "
                          f"(confidence: {triage_result.get('confidence', 0.0)})")
                
                # Show triage reasoning in display
                self.reasoning_display.show_thought(
                    f"AI triage assessed {finding.get('type')} as {triage_result.get('priority')}",
                    thought_type="decision",
                    metadata={
                        "original_severity": finding.get('severity', 'unknown'),
                        "ai_priority": triage_result.get('priority'),
                        "risk_score": triage_result.get('risk_score'),
                        "exploitability": triage_result.get('exploitability'),
                        "reasoning": triage_result.get('reasoning', '')[:100]
                    }
                )
                
                return enhanced_finding
            
            # If JSON parsing fails, return original finding with error note
            logger.warning("Failed to parse AI triage JSON response")
            return {
                **finding,
                'ai_triage': {
                    'error': 'Failed to parse triage response',
                    'raw_response': content[:200]
                },
                'ai_triaged': False
            }
            
        except Exception as e:
            logger.error(f"Error in contextual triage: {e}", exc_info=True)
            return {
                **finding,
                'ai_triage': {
                    'error': str(e)
                },
                'ai_triaged': False
            }
    
    # --- DEEP THINK VERIFICATION (TASK 1) ---
    async def verify_finding_with_reasoning(
        self,
        finding: Dict,
        target_url: str
    ) -> Optional[Dict]:
        """
        Devil's Advocate verification loop - Reasoning Model critiques findings
        to drastically reduce hallucinations and false positives.
        
        Args:
            finding: Vulnerability finding dictionary
            target_url: Target URL where vulnerability was found
            
        Returns:
            Finding if valid, None if hallucination detected
        """
        if not self.is_initialized:
            logger.warning("AI not initialized for verification")
            return finding
        
        logger.info(f"🔍 Deep Think: Verifying {finding.get('type', 'unknown')} finding...")
        
        # Construct comprehensive prompt for the Reasoning LLM
        finding_summary = json.dumps(finding, indent=2)
        
        verification_prompt = f"""You are a Senior Security Engineer reviewing a junior researcher's vulnerability report.
Your role is to act as a "Devil's Advocate" and critically assess whether this is a legitimate finding or a false positive.

TARGET URL: {target_url}

REPORTED FINDING:
{finding_summary}

CRITICAL ANALYSIS REQUIRED:
As a senior expert, you must scrutinize this finding for common false positives:
1. **404 Errors Masquerading as Vulnerabilities**: Is this just a 404/403 page being misinterpreted?
2. **Generic WAF Blocks**: Is this a WAF/security product blocking the request rather than an actual vulnerability?
3. **Expected Security Responses**: Is this a normal security control working as intended?
4. **Misinterpreted Error Messages**: Are error messages being confused with exploitable conditions?
5. **Context Confusion**: Does the evidence actually prove the vulnerability claim?
6. **Insufficient Evidence**: Is there concrete proof, or just speculation?

RESPOND WITH JSON ONLY:
{{
  "is_hallucination": true|false,
  "confidence_score": 0-100,
  "reasoning": "Detailed explanation of why this is or isn't a hallucination/false positive. Include specific technical reasoning."
}}

Be skeptical and thorough. Only mark is_hallucination=false if you have high confidence this is a real vulnerability."""

        try:
            # Call the vulnerability/reasoning specialist
            response = await self.call_reasoning_specialist(
                prompt=verification_prompt,
                context="Devil's Advocate verification of security findings",
                temperature=0.6,  # Lower temperature for more focused analysis
                max_tokens=1024
            )
            
            content = response.get('content', '')
            
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                verification = json.loads(json_match.group(0))
                
                is_hallucination = verification.get('is_hallucination', False)
                confidence = verification.get('confidence_score', 0)
                reasoning = verification.get('reasoning', 'No reasoning provided')
                
                logger.info(f"📊 Verification: hallucination={is_hallucination}, confidence={confidence}")
                logger.info(f"💭 Reasoning: {reasoning[:200]}...")
                
                # Show verification reasoning
                self.reasoning_display.show_thought(
                    f"Deep Think verification: {'REJECTED' if is_hallucination else 'ACCEPTED'} (confidence: {confidence}%)",
                    thought_type="verification",
                    metadata={
                        "finding_type": finding.get('type'),
                        "is_hallucination": is_hallucination,
                        "confidence_score": confidence,
                        "reasoning": reasoning[:200]
                    }
                )
                
                # If hallucination detected, log warning and return None
                if is_hallucination:
                    logger.warning(f"⚠️ HALLUCINATION DETECTED: {finding.get('type')} at {target_url}")
                    logger.warning(f"   Reason: {reasoning}")
                    return None
                
                # Valid finding - return it
                logger.info(f"✅ Finding verified as legitimate")
                return finding
            
            # If JSON parsing fails, be conservative and accept the finding with warning
            logger.warning("Could not parse verification JSON, accepting finding with warning")
            return finding
            
        except Exception as e:
            logger.error(f"Error during Deep Think verification: {e}", exc_info=True)
            # On error, be conservative and return the finding
            return finding
    
    # --- MULTIMODAL VISUAL ANALYSIS ---
    async def analyze_visuals(
        self,
        image_path: str,
        text_prompt: str
    ) -> str:
        """
        Analyze visual content (screenshots, UI images) using the Visual LLM
        
        This method provides the "Eyes" capability - it processes visual information
        and returns a neutral text description that separates perception from action.
        The visual analysis is internal and provides context for decision-making.
        
        Args:
            image_path: Path to the image file to analyze
            text_prompt: What to analyze or look for in the image
            
        Returns:
            Text description of the visual analysis
        """
        if not self.is_initialized:
            return "Error: AI not initialized"
        
        logger.info(f"👁️ Analyzing visual content: {image_path}")
        
        # Show reasoning about visual analysis
        self.reasoning_display.show_thought(
            "Initiating visual analysis of screenshot/image",
            thought_type="analysis",
            metadata={
                "image_path": image_path,
                "prompt": text_prompt[:100]
            }
        )
        
        try:
            # Call the orchestrator's multimodal task executor
            response = await self.orchestrator.execute_multimodal_task(
                text_prompt=text_prompt,
                image_path=image_path
            )
            
            if 'error' in response:
                error_msg = f"Visual analysis failed: {response['error']}"
                logger.error(error_msg)
                
                self.reasoning_display.show_thought(
                    error_msg,
                    thought_type="error",
                    metadata={"image_path": image_path}
                )
                
                return error_msg
            
            content = response.get('content', '')
            
            logger.info(f"✅ Visual analysis complete")
            
            # Show the visual analysis result
            self.reasoning_display.show_thought(
                "Visual analysis completed successfully",
                thought_type="observation",
                metadata={
                    "image_path": image_path,
                    "analysis_length": len(content),
                    "model": response.get('model', 'unknown')
                }
            )
            
            return content
            
        except Exception as e:
            error_msg = f"Error analyzing visuals: {str(e)}"
            logger.error(error_msg, exc_info=True)
            
            self.reasoning_display.show_thought(
                error_msg,
                thought_type="error",
                metadata={"image_path": image_path}
            )
            
            return error_msg
