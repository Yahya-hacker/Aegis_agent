# agents/multi_llm_orchestrator.py
"""
Multi-LLM Orchestrator for Aegis AI - v7.5
Manages four specialized LLMs via OpenRouter API with multi-account sharding:
- Hermes 3 Llama 70B: Strategic planning, triage, and high-level decision making
- Dolphin 3.0 R1 Mistral 24B: Reasoning and vulnerability analysis
- Qwen 2.5 72B: Code analysis, payload generation, and technical implementation
- Qwen 2.5 VL 32B: Visual analysis and UI reconnaissance
"""

import asyncio
import base64
import json
import os
import time
import aiohttp
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging
from utils.reasoning_display import get_reasoning_display

logger = logging.getLogger(__name__)

# Constants for long mission tracking and error detection
ERROR_MSG_TRUNCATE_LENGTH = 100  # Characters to include in error classification
HIGH_TOKEN_USAGE_THRESHOLD = 0.75  # Warn when using >75% of max_tokens
RECURRING_ERROR_THRESHOLD = 3  # Number of occurrences before flagging as recurring

class LLMConfig:
    """Configuration for each specialized LLM"""
    def __init__(self, model_name: str, role: str, specialization: List[str]):
        self.model_name = model_name
        self.role = role
        self.specialization = specialization
        self.api_url = "https://openrouter.ai/api/v1/chat/completions"

class MultiLLMOrchestrator:
    """
    Orchestrates four specialized LLMs for different pentesting tasks.
    All models are configurable via environment variables - no hardcoded model names!
    """
    
    # Class constants for role management
    ROLE_STRATEGIC = 'strategic'
    ROLE_VULNERABILITY = 'vulnerability'
    ROLE_CODER = 'coder'
    ROLE_VISUAL = 'visual'
    ALL_ROLES = [ROLE_STRATEGIC, ROLE_VULNERABILITY, ROLE_CODER, ROLE_VISUAL]
    
    def __init__(self):
        self.api_key = None  # Legacy field for backward compatibility
        self.api_keys = {}  # API key registry mapping roles to keys
        self.is_initialized = False
        self.reasoning_display = get_reasoning_display(verbose=True)
        self.max_retries = 3
        self.retry_delay = 2  # seconds
        self.request_timeout = 60  # seconds
        
        # Load default generation parameters from environment
        self.default_temperature = float(os.getenv("DEFAULT_TEMPERATURE", "0.7"))
        self.default_max_tokens = int(os.getenv("DEFAULT_MAX_TOKENS", "4096"))
        
        # Sophisticated tracking for long missions and complex chains
        self._initialize_usage_tracker()
        self.context_history = []  # Track context size over time
        self.error_patterns = {}  # Track recurring errors for pattern detection
        
        # Load model names from environment variables with fallback defaults
        # These defaults match the recommended models, but can be changed easily via .env
        strategic_model = os.getenv(
            "STRATEGIC_MODEL",
            os.getenv("ORCHESTRATOR_MODEL", "nousresearch/hermes-3-llama-3.1-70b")
        )
        
        reasoning_model = os.getenv(
            "REASONING_MODEL",
            "cognitivecomputations/dolphin3.0-r1-mistral-24b"
        )
        
        code_model = os.getenv(
            "CODE_MODEL",
            os.getenv("CODER_MODEL", "qwen/qwen-2.5-72b-instruct")
        )
        
        visual_model = os.getenv(
            "VISUAL_MODEL",
            "qwen/qwen2.5-vl-32b-instruct:free"
        )
        
        # Define the four specialized LLMs with environment-configured models
        # NO HARDCODED MODEL NAMES - All loaded from environment!
        self.llms = {
            'strategic': LLMConfig(
                model_name=strategic_model,
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
                model_name=reasoning_model,
                role="Reasoning & Vulnerability Analyst",
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
                model_name=code_model,
                role="Code Analyst & Payload Engineer",
                specialization=[
                    "code_analysis",
                    "payload_generation",
                    "script_creation",
                    "exploit_coding",
                    "technical_implementation",
                    "tool_orchestration"
                ]
            ),
            'visual': LLMConfig(
                model_name=visual_model,
                role="Visual Analyst & UI Reconnaissance",
                specialization=[
                    "image_analysis",
                    "ui_reconnaissance",
                    "visual_vulnerability_detection",
                    "screenshot_analysis",
                    "layout_understanding",
                    "multimodal_analysis"
                ]
            )
        }
        
        logger.info("🔧 LLM Configuration loaded from environment:")
        logger.info(f"   Strategic Model: {strategic_model}")
        logger.info(f"   Reasoning Model: {reasoning_model}")
        logger.info(f"   Code Model: {code_model}")
        logger.info(f"   Visual Model: {visual_model}")
        logger.info(f"   Default Temperature: {self.default_temperature}")
        logger.info(f"   Default Max Tokens: {self.default_max_tokens}")
    
    def _initialize_usage_tracker(self):
        """
        Initialize usage tracking for all roles.
        Extracted as a private method to avoid code duplication between __init__ and reset.
        """
        self.usage_tracker = {role: {'calls': 0, 'tokens': 0, 'cost': 0.0} for role in self.ALL_ROLES}
    
    async def initialize(self):
        """Initialize the orchestrator and validate API keys with sharding support"""
        try:
            logger.info("🤖 Initializing Multi-LLM Orchestrator with API Key Sharding...")
            
            # Load master key (required fallback)
            master_key = os.environ.get("OPENROUTER_API_KEY") or None
            
            # Build API key registry with fallback logic
            # Each role can have its own key, or fallback to master key
            self.api_keys = {
                'strategic': os.environ.get("STRATEGIC_API_KEY") or master_key,
                'vulnerability': os.environ.get("REASONING_API_KEY") or master_key,
                'coder': os.environ.get("CODE_API_KEY") or master_key,
                'visual': os.environ.get("VISUAL_API_KEY") or master_key
            }
            
            # Validation: Check for missing keys
            missing_keys = []
            for role, key in self.api_keys.items():
                if not key or key.strip() == "":
                    missing_keys.append(role)
            
            if missing_keys:
                error_msg = (
                    f"❌ CRITICAL: Missing API keys for roles: {', '.join(missing_keys)}. "
                    f"Either set OPENROUTER_API_KEY (master key) or provide specific keys "
                    f"(STRATEGIC_API_KEY, REASONING_API_KEY, CODE_API_KEY, VISUAL_API_KEY)."
                )
                logger.error(error_msg)
                raise ValueError(error_msg)
            
            # Strip whitespace from all keys
            for role in self.api_keys:
                self.api_keys[role] = self.api_keys[role].strip()
            
            # Maintain backward compatibility: set legacy self.api_key to master key if available
            # If no master key but all roles have specific keys, self.api_key remains None
            self.api_key = master_key if master_key else None
            
            # Log configuration status with sophisticated reporting
            logger.info("🔑 API Key Configuration Status:")
            logger.info(f"   Master Key (OPENROUTER_API_KEY): {'✅ Configured' if master_key else '❌ Not Set'}")
            logger.info("")
            logger.info("   Role-Specific Key Assignment:")
            
            for role, key in self.api_keys.items():
                role_key_env_map = {
                    'strategic': 'STRATEGIC_API_KEY',
                    'vulnerability': 'REASONING_API_KEY',
                    'coder': 'CODE_API_KEY',
                    'visual': 'VISUAL_API_KEY'
                }
                
                role_env_var = role_key_env_map[role]
                specific_key = os.environ.get(role_env_var)
                
                if specific_key and specific_key.strip():
                    # Using role-specific key
                    logger.info(f"   ✅ {role.capitalize()}: Using specific key ({role_env_var})")
                else:
                    # Falling back to master key
                    logger.info(f"   ⚠️  {role.capitalize()}: Fallback to master key (OPENROUTER_API_KEY)")
            
            logger.info("")
            logger.info(f"📋 Configured LLMs (via OpenRouter):")
            for llm_type, config in self.llms.items():
                logger.info(f"   • {config.role}: {config.model_name}")
            
            self.is_initialized = True
            logger.info("✅ Multi-LLM Orchestrator ready with API Key Sharding enabled.")
            
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
        temperature: float = None,
        max_tokens: int = None
    ) -> Dict[str, Any]:
        """
        Call a specific LLM via OpenRouter API with retry logic and error handling
        Uses role-specific API keys from the key registry for granular cost control
        
        Args:
            llm_type: Type of LLM to use ('strategic', 'vulnerability', 'coder', or 'visual')
            messages: List of message dicts with 'role' and 'content'
            temperature: Sampling temperature (0.0 to 1.0). If None, uses DEFAULT_TEMPERATURE from env
            max_tokens: Maximum tokens to generate. If None, uses DEFAULT_MAX_TOKENS from env
            
        Returns:
            Response dictionary with 'content' and metadata
        """
        if not self.is_initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")
        
        if llm_type not in self.llms:
            raise ValueError(f"Unknown LLM type: {llm_type}")
        
        # Retrieve role-specific API key from registry
        if llm_type not in self.api_keys:
            raise RuntimeError(f"CRITICAL: No API key configured for role '{llm_type}'. This should not happen after initialization.")
        
        role_api_key = self.api_keys[llm_type]
        
        # Safety check: Ensure key is not empty at runtime
        if not role_api_key or role_api_key.strip() == "":
            raise RuntimeError(f"CRITICAL: API key for role '{llm_type}' is empty or invalid at runtime.")
        
        # Log which key role is being used at DEBUG level (as required by Task 1)
        # Security: Never log actual key values, only the role being used
        logger.debug(f"🔑 Using API key for role '{llm_type}'")
        
        # Use default parameters from environment if not specified
        if temperature is None:
            temperature = self.default_temperature
        if max_tokens is None:
            max_tokens = self.default_max_tokens
        
        config = self.llms[llm_type]
        
        # Retry logic with exponential backoff
        for attempt in range(self.max_retries):
            try:
                logger.info(f"🔄 Calling {config.role} ({config.model_name}) - Attempt {attempt + 1}/{self.max_retries}...")
                
                # Show reasoning about the LLM call
                user_message = next((m['content'] for m in messages if m['role'] == 'user'), "")
                
                self.reasoning_display.show_thought(
                    f"Preparing to call {config.role} for task execution",
                    thought_type="llm_call",
                    metadata={
                        "model": config.model_name,
                        "temperature": temperature,
                        "max_tokens": max_tokens,
                        "attempt": attempt + 1,
                        "message_preview": user_message[:100] + "..." if len(user_message) > 100 else user_message
                    }
                )
                
                headers = {
                    "Authorization": f"Bearer {role_api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/Yahya-hacker/Aegis_agent",
                    "X-Title": "Aegis AI Pentesting Agent"
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
                        timeout=aiohttp.ClientTimeout(total=self.request_timeout)
                    ) as response:
                        response_text = await response.text()
                        
                        if response.status != 200:
                            logger.error(f"API Error: {response.status} - {response_text}")
                            
                            # Check if it's a retryable error
                            if response.status in [429, 500, 502, 503, 504]:
                                if attempt < self.max_retries - 1:
                                    wait_time = self.retry_delay * (2 ** attempt)  # Exponential backoff
                                    logger.warning(f"Retryable error, waiting {wait_time}s before retry...")
                                    await asyncio.sleep(wait_time)
                                    continue
                            
                            raise RuntimeError(f"API returned status {response.status}: {response_text}")
                        
                        try:
                            result = await response.json() if not response_text else json.loads(response_text)
                        except json.JSONDecodeError as e:
                            logger.error(f"Failed to parse API response as JSON: {e}")
                            logger.error(f"Response text: {response_text[:500]}")
                            raise RuntimeError(f"Invalid JSON response from API: {str(e)}")
                        
                        if 'choices' not in result or not result['choices']:
                            logger.error(f"API response missing 'choices': {result}")
                            raise RuntimeError("API response missing 'choices'")
                        
                        content = result['choices'][0]['message']['content']
                        
                        if not content or len(content.strip()) == 0:
                            logger.warning("API returned empty content")
                            if attempt < self.max_retries - 1:
                                logger.warning("Retrying due to empty response...")
                                await asyncio.sleep(self.retry_delay)
                                continue
                            raise RuntimeError("API returned empty content after all retries")
                        
                        logger.info(f"✅ Response received from {config.role}")
                        
                        # Track usage for long mission monitoring
                        usage = result.get('usage', {})
                        total_tokens = usage.get('total_tokens', 0)
                        self.usage_tracker[llm_type]['calls'] += 1
                        self.usage_tracker[llm_type]['tokens'] += total_tokens
                        
                        # Warn if approaching context limits (sophisticated monitoring)
                        if total_tokens > 0:
                            # Use asyncio.get_running_loop() for modern asyncio compatibility
                            try:
                                loop_time = asyncio.get_running_loop().time()
                            except RuntimeError:
                                # Fallback for edge cases where no running loop exists
                                loop_time = time.time()
                            
                            self.context_history.append({
                                'llm_type': llm_type,
                                'tokens': total_tokens,
                                'timestamp': loop_time
                            })
                            
                            # Warn if single call uses >75% of max tokens
                            if total_tokens > (max_tokens * HIGH_TOKEN_USAGE_THRESHOLD):
                                logger.warning(
                                    f"⚠️  HIGH TOKEN USAGE: {llm_type} used {total_tokens}/{max_tokens} tokens. "
                                    f"Consider chunking or summarizing for long missions."
                                )
                        
                        # Display the LLM interaction with full reasoning
                        self.reasoning_display.show_llm_interaction(
                            llm_name=config.role,
                            prompt=user_message,
                            response=content,
                            metadata={
                                "model": config.model_name,
                                "usage": usage,
                                "temperature": temperature,
                                "max_tokens": max_tokens,
                                "attempt": attempt + 1,
                                "cumulative_calls": self.usage_tracker[llm_type]['calls'],
                                "cumulative_tokens": self.usage_tracker[llm_type]['tokens']
                            }
                        )
                        
                        return {
                            'content': content,
                            'model': config.model_name,
                            'role': config.role,
                            'llm_type': llm_type,
                            'usage': usage
                        }
                        
            except asyncio.TimeoutError:
                logger.error(f"Timeout calling {config.role} (attempt {attempt + 1}/{self.max_retries})")
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_delay * (2 ** attempt)
                    logger.warning(f"Retrying after timeout in {wait_time}s...")
                    await asyncio.sleep(wait_time)
                    continue
                raise RuntimeError(f"Request to {config.role} timed out after {self.max_retries} attempts")
            except Exception as e:
                # Create a more robust error classification using error type and message
                # Truncate to avoid grouping different errors together
                error_type = type(e).__name__
                error_msg = str(e)
                # Use constant for truncation length for better maintainability
                error_key = f"{error_type}:{error_msg[:ERROR_MSG_TRUNCATE_LENGTH]}"
                self.error_patterns[error_key] = self.error_patterns.get(error_key, 0) + 1
                
                # Sophisticated error pattern detection for long missions
                if self.error_patterns[error_key] >= RECURRING_ERROR_THRESHOLD:
                    logger.error(
                        f"🔴 RECURRING ERROR PATTERN DETECTED: '{error_type}' occurred {self.error_patterns[error_key]} times. "
                        f"This may indicate a systemic issue in long missions or complex exploit chains."
                    )
                
                logger.error(f"Error calling {config.role} (attempt {attempt + 1}/{self.max_retries}): {e}", exc_info=True)
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_delay * (2 ** attempt)
                    logger.warning(f"Retrying after error in {wait_time}s...")
                    await asyncio.sleep(wait_time)
                    continue
                raise
        
        # If we get here, all retries failed
        raise RuntimeError(f"Failed to call {config.role} after {self.max_retries} attempts")
    
    async def execute_task(
        self,
        task_type: str,
        system_prompt: str,
        user_message: str,
        temperature: float = None,
        max_tokens: int = None
    ) -> Dict[str, Any]:
        """
        Execute a task by automatically selecting and calling the appropriate LLM
        
        Args:
            task_type: Type of task (determines which LLM to use)
            system_prompt: System/instruction prompt
            user_message: User message/query
            temperature: Sampling temperature. If None, uses DEFAULT_TEMPERATURE from env
            max_tokens: Maximum tokens to generate. If None, uses DEFAULT_MAX_TOKENS from env
            
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
            ]
        )
        
        vulnerability_task = self.call_llm(
            'vulnerability',
            [
                {"role": "system", "content": f"You are a vulnerability analyst. Context: {context}"},
                {"role": "user", "content": vulnerability_question}
            ]
        )
        
        coder_task = self.call_llm(
            'coder',
            [
                {"role": "system", "content": f"You are a code analyst and payload engineer. Context: {context}"},
                {"role": "user", "content": coding_question}
            ]
        )
        
        # Wait for all responses
        results = await asyncio.gather(strategic_task, vulnerability_task, coder_task)
        
        return {
            'strategic': results[0],
            'vulnerability': results[1],
            'coder': results[2]
        }
    
    async def execute_multimodal_task(
        self,
        text_prompt: str,
        image_path: str
    ) -> Dict[str, Any]:
        """
        Execute a multimodal task using the visual LLM with an image
        
        This method processes an image along with a text prompt to extract
        visual information, analyze UI elements, or detect visual vulnerabilities.
        
        Args:
            text_prompt: Text description of what to analyze in the image
            image_path: Path to the image file to analyze
            
        Returns:
            Response dictionary with visual analysis
        """
        if not self.is_initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")
        
        logger.info(f"👁️ Executing multimodal task with visual LLM...")
        logger.info(f"   Prompt: {text_prompt[:100]}...")
        logger.info(f"   Image: {image_path}")
        
        try:
            # Read and encode the image
            with open(image_path, 'rb') as image_file:
                image_data = image_file.read()
                image_base64 = base64.b64encode(image_data).decode('utf-8')
            
            # Determine image type from extension
            image_ext = Path(image_path).suffix.lower()
            mime_type_map = {
                '.png': 'image/png',
                '.jpg': 'image/jpeg',
                '.jpeg': 'image/jpeg',
                '.gif': 'image/gif',
                '.webp': 'image/webp'
            }
            mime_type = mime_type_map.get(image_ext, 'image/png')
            
            config = self.llms['visual']
            
            # Show reasoning about the multimodal call
            self.reasoning_display.show_thought(
                f"Preparing multimodal analysis with {config.role}",
                thought_type="llm_call",
                metadata={
                    "model": config.model_name,
                    "image_path": image_path,
                    "image_size": len(image_data),
                    "prompt_preview": text_prompt[:100]
                }
            )
            
            # Build the multimodal message
            # Retrieve role-specific API key for visual model
            if 'visual' not in self.api_keys:
                raise RuntimeError("CRITICAL: No API key configured for visual role. This should not happen after initialization.")
            
            visual_api_key = self.api_keys['visual']
            
            # Safety check
            if not visual_api_key or visual_api_key.strip() == "":
                raise RuntimeError("CRITICAL: API key for visual role is empty or invalid at runtime.")
            
            headers = {
                "Authorization": f"Bearer {visual_api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/Yahya-hacker/Aegis_agent",
                "X-Title": "Aegis AI Pentesting Agent"
            }
            
            # Multimodal message format for vision models
            messages = [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": text_prompt
                        },
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:{mime_type};base64,{image_base64}"
                            }
                        }
                    ]
                }
            ]
            
            payload = {
                "model": config.model_name,
                "messages": messages,
                "temperature": self.default_temperature,
                "max_tokens": self.default_max_tokens
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    config.api_url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.request_timeout)
                ) as response:
                    response_text = await response.text()
                    
                    if response.status != 200:
                        logger.error(f"Visual API Error: {response.status} - {response_text}")
                        raise RuntimeError(f"API returned status {response.status}: {response_text}")
                    
                    result = json.loads(response_text)
                    
                    if 'choices' not in result or not result['choices']:
                        raise RuntimeError("API response missing 'choices'")
                    
                    content = result['choices'][0]['message']['content']
                    
                    logger.info(f"✅ Visual analysis complete")
                    
                    # Display the multimodal interaction
                    self.reasoning_display.show_llm_interaction(
                        llm_name=config.role,
                        prompt=f"{text_prompt}\n[Image: {image_path}]",
                        response=content,
                        metadata={
                            "model": config.model_name,
                            "usage": result.get('usage', {}),
                            "image_size": len(image_data)
                        }
                    )
                    
                    return {
                        'content': content,
                        'model': config.model_name,
                        'role': config.role,
                        'llm_type': 'visual',
                        'image_path': image_path,
                        'usage': result.get('usage', {})
                    }
                    
        except FileNotFoundError:
            error_msg = f"Image file not found: {image_path}"
            logger.error(error_msg)
            return {'error': error_msg}
        except Exception as e:
            logger.error(f"Error in multimodal task: {e}", exc_info=True)
            return {'error': str(e)}
    
    def get_usage_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive usage statistics for monitoring long missions and complex chains.
        
        This is critical for identifying issues like:
        - Context window exhaustion over time
        - Unbalanced load across different model types
        - Cumulative cost tracking per role
        - Detecting when to checkpoint or summarize state
        
        Returns:
            Dictionary with detailed usage statistics per role
        """
        total_calls = sum(stats['calls'] for stats in self.usage_tracker.values())
        total_tokens = sum(stats['tokens'] for stats in self.usage_tracker.values())
        
        stats = {
            'total_calls': total_calls,
            'total_tokens': total_tokens,
            'by_role': self.usage_tracker.copy(),
            'context_history_size': len(self.context_history),
            'unique_error_patterns': len(self.error_patterns),
            'recurring_errors': {k: v for k, v in self.error_patterns.items() if v >= 2}
        }
        
        logger.info("📊 Long Mission Statistics:")
        logger.info(f"   Total LLM Calls: {total_calls}")
        logger.info(f"   Total Tokens Used: {total_tokens:,}")
        logger.info(f"   Breakdown by Role:")
        for role, role_stats in self.usage_tracker.items():
            if role_stats['calls'] > 0:
                avg_tokens = role_stats['tokens'] / role_stats['calls']
                logger.info(f"      {role}: {role_stats['calls']} calls, {role_stats['tokens']:,} tokens (avg: {avg_tokens:.0f})")
        
        if stats['recurring_errors']:
            logger.warning(f"   ⚠️  Recurring Errors: {len(stats['recurring_errors'])} patterns detected")
        
        return stats
    
    def reset_usage_tracking(self):
        """
        Reset usage tracking for a new mission phase.
        Useful for checkpointing in long-running missions.
        """
        logger.info("🔄 Resetting usage tracking for new mission phase...")
        self._initialize_usage_tracker()
        self.context_history = []
        # Keep error_patterns to track systemic issues across resets
