# agents/multi_llm_orchestrator.py
"""
Multi-LLM Orchestrator for Aegis AI - v6.0
Manages three specialized LLMs via Together AI API:
- Llama 70B: Strategic planning, triage, and high-level decision making
- Mixtral 8x7B: Vulnerability analysis and exploitation planning
- Qwen-coder: Code analysis, payload generation, and technical implementation
"""

import asyncio
import json
import os
import aiohttp
from typing import Dict, List, Any, Optional
import logging
from utils.reasoning_display import get_reasoning_display

logger = logging.getLogger(__name__)

class LLMConfig:
    """Configuration for each specialized LLM"""
    def __init__(self, model_name: str, role: str, specialization: List[str]):
        self.model_name = model_name
        self.role = role
        self.specialization = specialization
        self.api_url = "https://api.together.xyz/v1/chat/completions"

class MultiLLMOrchestrator:
    """
    Orchestrates three specialized LLMs for different pentesting tasks
    """
    
    def __init__(self):
        self.api_key = None
        self.is_initialized = False
        self.reasoning_display = get_reasoning_display(verbose=True)
        
        # Define the three specialized LLMs
        self.llms = {
            'strategic': LLMConfig(
                model_name="meta-llama/Llama-3-70b-chat-hf",
                role="Strategic Planner & Triage Agent",
                specialization=[
                    "mission_planning",
                    "triage",
                    "scope_analysis",
                    "decision_making",
                    "risk_assessment",
                    "prioritization"
                ]
            ),
            'vulnerability': LLMConfig(
                model_name="mistralai/Mixtral-8x7B-Instruct-v0.1",
                role="Vulnerability Analyst & Exploitation Expert",
                specialization=[
                    "vulnerability_analysis",
                    "exploit_planning",
                    "security_assessment",
                    "attack_vectors",
                    "weakness_identification",
                    "penetration_testing"
                ]
            ),
            'coder': LLMConfig(
                model_name="Qwen/Qwen2.5-Coder-32B-Instruct",
                role="Code Analyst & Payload Engineer",
                specialization=[
                    "code_analysis",
                    "payload_generation",
                    "script_creation",
                    "exploit_coding",
                    "technical_implementation",
                    "tool_orchestration"
                ]
            )
        }
    
    async def initialize(self):
        """Initialize the orchestrator and validate API key"""
        try:
            logger.info("🤖 Initializing Multi-LLM Orchestrator...")
            
            self.api_key = os.environ.get("TOGETHER_API_KEY")
            if not self.api_key:
                logger.error("❌ TOGETHER_API_KEY environment variable not set.")
                raise ValueError("TOGETHER_API_KEY must be set to use the AI.")
            
            logger.info("✅ API Key loaded successfully.")
            logger.info(f"📋 Configured LLMs:")
            for llm_type, config in self.llms.items():
                logger.info(f"   • {config.role}: {config.model_name}")
            
            self.is_initialized = True
            logger.info("✅ Multi-LLM Orchestrator ready.")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize orchestrator: {e}", exc_info=True)
            raise
    
    def select_llm(self, task_type: str) -> str:
        """
        Intelligently selects the most appropriate LLM for a given task
        
        Args:
            task_type: Type of task to perform
            
        Returns:
            Key of the selected LLM ('strategic', 'vulnerability', or 'coder')
        """
        task_mapping = {
            # Strategic tasks
            'mission_planning': 'strategic',
            'triage': 'strategic',
            'scope_analysis': 'strategic',
            'decision_making': 'strategic',
            'risk_assessment': 'strategic',
            'prioritization': 'strategic',
            'conversation': 'strategic',
            
            # Vulnerability tasks
            'vulnerability_analysis': 'vulnerability',
            'exploit_planning': 'vulnerability',
            'security_assessment': 'vulnerability',
            'attack_vectors': 'vulnerability',
            'weakness_identification': 'vulnerability',
            'penetration_testing': 'vulnerability',
            'next_action': 'vulnerability',
            
            # Coding tasks
            'code_analysis': 'coder',
            'payload_generation': 'coder',
            'script_creation': 'coder',
            'exploit_coding': 'coder',
            'technical_implementation': 'coder',
            'tool_orchestration': 'coder',
        }
        
        selected = task_mapping.get(task_type, 'strategic')
        logger.info(f"🎯 Task '{task_type}' → LLM: {self.llms[selected].role}")
        
        # Show reasoning about LLM selection
        self.reasoning_display.show_thought(
            f"Selected {self.llms[selected].role} for task type '{task_type}'",
            thought_type="decision",
            metadata={
                "task_type": task_type,
                "selected_llm": selected,
                "model": self.llms[selected].model_name,
                "specialization": self.llms[selected].specialization
            }
        )
        
        return selected
    
    async def call_llm(
        self, 
        llm_type: str, 
        messages: List[Dict[str, str]], 
        temperature: float = 0.7,
        max_tokens: int = 2048
    ) -> Dict[str, Any]:
        """
        Call a specific LLM via Together AI API
        
        Args:
            llm_type: Type of LLM to use ('strategic', 'vulnerability', or 'coder')
            messages: List of message dicts with 'role' and 'content'
            temperature: Sampling temperature (0.0 to 1.0)
            max_tokens: Maximum tokens to generate
            
        Returns:
            Response dictionary with 'content' and metadata
        """
        if not self.is_initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")
        
        if llm_type not in self.llms:
            raise ValueError(f"Unknown LLM type: {llm_type}")
        
        config = self.llms[llm_type]
        
        try:
            logger.info(f"🔄 Calling {config.role} ({config.model_name})...")
            
            # Show reasoning about the LLM call
            user_message = next((m['content'] for m in messages if m['role'] == 'user'), "")
            system_message = next((m['content'] for m in messages if m['role'] == 'system'), "")
            
            self.reasoning_display.show_thought(
                f"Preparing to call {config.role} for task execution",
                thought_type="llm_call",
                metadata={
                    "model": config.model_name,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "message_preview": user_message[:100] + "..." if len(user_message) > 100 else user_message
                }
            )
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": config.model_name,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "top_p": 0.9,
                "top_k": 50,
                "repetition_penalty": 1.1,
                "stop": ["<|im_end|>", "</s>"]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    config.api_url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        logger.error(f"API Error: {response.status} - {error_text}")
                        raise RuntimeError(f"API returned status {response.status}: {error_text}")
                    
                    result = await response.json()
                    
                    if 'choices' not in result or not result['choices']:
                        raise RuntimeError("API response missing 'choices'")
                    
                    content = result['choices'][0]['message']['content']
                    
                    logger.info(f"✅ Response received from {config.role}")
                    
                    # Display the LLM interaction with full reasoning
                    self.reasoning_display.show_llm_interaction(
                        llm_name=config.role,
                        prompt=user_message,
                        response=content,
                        metadata={
                            "model": config.model_name,
                            "usage": result.get('usage', {}),
                            "temperature": temperature,
                            "max_tokens": max_tokens
                        }
                    )
                    
                    return {
                        'content': content,
                        'model': config.model_name,
                        'role': config.role,
                        'llm_type': llm_type,
                        'usage': result.get('usage', {})
                    }
                    
        except asyncio.TimeoutError:
            logger.error(f"Timeout calling {config.role}")
            raise RuntimeError(f"Request to {config.role} timed out")
        except Exception as e:
            logger.error(f"Error calling {config.role}: {e}", exc_info=True)
            raise
    
    async def execute_task(
        self,
        task_type: str,
        system_prompt: str,
        user_message: str,
        temperature: float = 0.7,
        max_tokens: int = 2048
    ) -> Dict[str, Any]:
        """
        Execute a task by automatically selecting and calling the appropriate LLM
        
        Args:
            task_type: Type of task (determines which LLM to use)
            system_prompt: System/instruction prompt
            user_message: User message/query
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            
        Returns:
            Response dictionary with content and metadata
        """
        llm_type = self.select_llm(task_type)
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ]
        
        return await self.call_llm(llm_type, messages, temperature, max_tokens)
    
    async def collaborative_analysis(
        self,
        context: str,
        strategic_question: str,
        vulnerability_question: str,
        coding_question: str
    ) -> Dict[str, Any]:
        """
        Perform collaborative analysis using all three LLMs
        Each LLM contributes its specialized perspective
        
        Args:
            context: Shared context for all LLMs
            strategic_question: Question for strategic LLM
            vulnerability_question: Question for vulnerability LLM
            coding_question: Question for coder LLM
            
        Returns:
            Dictionary with responses from all three LLMs
        """
        logger.info("🤝 Starting collaborative analysis with all LLMs...")
        
        # Call all three LLMs in parallel
        strategic_task = self.call_llm(
            'strategic',
            [
                {"role": "system", "content": f"You are a strategic pentesting planner. Context: {context}"},
                {"role": "user", "content": strategic_question}
            ],
            temperature=0.7
        )
        
        vulnerability_task = self.call_llm(
            'vulnerability',
            [
                {"role": "system", "content": f"You are a vulnerability analyst. Context: {context}"},
                {"role": "user", "content": vulnerability_question}
            ],
            temperature=0.8
        )
        
        coder_task = self.call_llm(
            'coder',
            [
                {"role": "system", "content": f"You are a code analyst and payload engineer. Context: {context}"},
                {"role": "user", "content": coding_question}
            ],
            temperature=0.6
        )
        
        # Wait for all responses
        results = await asyncio.gather(strategic_task, vulnerability_task, coder_task)
        
        return {
            'strategic': results[0],
            'vulnerability': results[1],
            'coder': results[2]
        }
