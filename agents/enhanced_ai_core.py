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

logger = logging.getLogger(__name__)

# CRITICAL: Model constants for OpenRouter API - DO NOT MODIFY
ORCHESTRATOR_MODEL = "nousresearch/hermes-3-llama-3.1-70b"
CODE_MODEL = "qwen/qwen-2.5-72b-instruct"
REASONING_MODEL = "cognitivecomputations/dolphin3.0-r1-mistral-24b"

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
    
    async def initialize(self):
        """Initialize the enhanced AI core with all LLMs"""
        try:
            logger.info("🚀 Initializing Enhanced Aegis AI with Multi-LLM support...")
            
            # Initialize the orchestrator
            await self.orchestrator.initialize()
            
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
        TASK 1: Memory management to prevent "Digital Alzheimer's"
        Keeps the last 5 detailed interactions and summarizes older ones
        
        Args:
            history: Full conversation history
            
        Returns:
            Pruned history with summary of old interactions
        """
        if len(history) <= 5:
            return history
        
        # Keep the last 5 interactions
        recent = history[-5:]
        
        # Summarize older interactions
        older = history[:-5]
        summary_content = f"[Previous context: {len(older)} earlier interactions covering mission initialization and early reconnaissance]"
        
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
        
        # Show reasoning about next action decision
        self.reasoning_display.show_thought(
            "Determining next action based on mission rules and agent memory",
            thought_type="tactical",
            metadata={
                "memory_items": len(agent_memory),
                "last_observation": agent_memory[-1] if agent_memory else None
            }
        )
        
        system_prompt = f"""You are an advanced autonomous penetration testing agent with sophisticated reasoning capabilities.
Your task is to decide the next action based on mission rules, observations, and learned patterns.

MISSION RULES:
{bbp_rules}

LEARNED PATTERNS FROM PREVIOUS MISSIONS:
{self.learned_patterns}

AVAILABLE TOOLS:
- subdomain_enumeration: Find subdomains (args: domain)
- port_scanning: Scan open ports (args: target)
- nmap_scan: Detailed nmap scan (args: target, ports)
- url_discovery: Discover URLs and endpoints (args: domain)
- tech_detection: Detect technologies (args: target)
- vulnerability_scan: Scan for vulnerabilities (args: target)
- discover_interactables: Find forms and inputs (args: target)
- test_form_payload: Test form with payload (args: target, form_identifier, input_payloads)
- fetch_url: Fetch a URL (args: target)
- finish_mission: Complete mission (args: reason)
- ask_user_for_approval: Ask for guidance (args: message)

ENHANCED REASONING FRAMEWORK:
1. ANALYSIS: Carefully analyze the agent memory to understand:
   - What has been done already
   - What vulnerabilities or findings have been discovered
   - What areas remain unexplored
   - Any patterns or anomalies in the results

2. STRATEGIC THINKING: Consider multiple approaches:
   - What is the most efficient next step?
   - What will provide the most valuable information?
   - Are there any dependencies or prerequisites?
   - What are the risks vs rewards?

3. COMPREHENSIVE COVERAGE: Ensure thorough testing by:
   - Testing different attack surfaces
   - Following up on interesting findings
   - Validating potential vulnerabilities
   - Exploring both breadth and depth

4. DECISION MAKING: Choose the action that:
   - Maximizes detection chances
   - Follows a logical progression
   - Respects mission rules and scope
   - Provides actionable intelligence

IMPORTANT INSTRUCTIONS:
- Show ALL your reasoning and thought process
- Explain WHY you chose this specific action
- Consider multiple options before deciding
- Follow the rules STRICTLY (no out-of-scope testing)
- If mission is complete, use finish_mission
- If uncertain or need guidance, use ask_user_for_approval
- Be thorough and methodical in your approach

Respond with JSON ONLY including detailed reasoning:
```json
{{
  "tool": "tool_name",
  "args": {{"param": "value"}},
  "reasoning": "Detailed explanation of your thought process: What you observed, why this action is optimal, what you expect to discover, and how it fits into the overall strategy"
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
