# agents/unified_llm_orchestrator.py
"""
Unified LLM Orchestrator for Aegis AI - v9.0
Single LLM Architecture: Uses DeepSeek R1 for ALL tasks except visual analysis.
Visual tasks still use a dedicated visual LLM (Qwen 2.5 VL).

This replaces the multi-LLM architecture with a simpler, unified approach:
- One main LLM (DeepSeek R1) handles: strategic planning, vulnerability analysis, 
  code analysis, payload generation, reasoning, and all other text-based tasks
- Visual LLM (Qwen 2.5 VL) handles only: image/screenshot analysis

Benefits:
- Simpler architecture
- Consistent reasoning across all task types
- Reduced API complexity
- Persistent connection maintained for efficiency
"""

import asyncio
import base64
import hashlib
import json
import os
import time
import aiohttp
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import logging
from utils.reasoning_display import get_reasoning_display

logger = logging.getLogger(__name__)

# Constants for long mission tracking and error detection
ERROR_MSG_TRUNCATE_LENGTH = 100
HIGH_TOKEN_USAGE_THRESHOLD = 0.75
RECURRING_ERROR_THRESHOLD = 3


class LLMConfig:
    """Configuration for an LLM"""
    def __init__(self, model_name: str, role: str, specialization: List[str]):
        self.model_name = model_name
        self.role = role
        self.specialization = specialization
        self.api_url = "https://openrouter.ai/api/v1/chat/completions"


class UnifiedLLMOrchestrator:
    """
    Unified LLM Orchestrator using a single main LLM for all text-based tasks.
    
    This orchestrator uses:
    - One main LLM (default: DeepSeek R1) for ALL reasoning, planning, analysis, and code tasks
    - One visual LLM (default: Qwen 2.5 VL) for image/screenshot analysis only
    
    All models are configurable via environment variables.
    """
    
    # Role constants
    ROLE_MAIN = 'main'  # Single main LLM for all tasks
    ROLE_VISUAL = 'visual'  # Visual LLM for image analysis
    ALL_ROLES = [ROLE_MAIN, ROLE_VISUAL]
    
    def __init__(self):
        self.api_key = None
        self.api_keys = {}
        self.is_initialized = False
        self.reasoning_display = get_reasoning_display(verbose=True)
        self.max_retries = 3
        self.retry_delay = 2
        self.request_timeout = 120  # Increased for DeepSeek R1's reasoning
        
        # Persistent session for API connection
        self._session: Optional[aiohttp.ClientSession] = None
        self._session_lock = asyncio.Lock()
        
        # Load default generation parameters
        self.default_temperature = float(os.getenv("DEFAULT_TEMPERATURE", "0.7"))
        self.default_max_tokens = int(os.getenv("DEFAULT_MAX_TOKENS", "8192"))  # Increased for complex reasoning
        
        # Usage tracking
        self._initialize_usage_tracker()
        self.context_history = []
        self.error_patterns = {}
        
        # Loop detection
        self.action_history: List[str] = []
        self.max_action_history = 20
        self.loop_detection_window = 3
        self.loop_occurrence_threshold = 2
        
        # Load model configuration from environment
        # MAIN_MODEL is the single unified LLM for all tasks
        main_model = os.getenv(
            "MAIN_MODEL",
            os.getenv(
                "DEEPSEEK_MODEL",
                "deepseek/deepseek-r1"  # DeepSeek R1 as default
            )
        )
        
        # Visual model for image analysis only
        visual_model = os.getenv(
            "VISUAL_MODEL",
            "qwen/qwen2.5-vl-32b-instruct:free"
        )
        
        # Configure the two LLMs
        self.llms = {
            'main': LLMConfig(
                model_name=main_model,
                role="Unified AI Agent",
                specialization=[
                    "strategic_planning",
                    "mission_triage",
                    "vulnerability_analysis",
                    "exploit_planning",
                    "code_analysis",
                    "payload_generation",
                    "decision_making",
                    "reasoning",
                    "security_assessment",
                    "tool_orchestration"
                ]
            ),
            'visual': LLMConfig(
                model_name=visual_model,
                role="Visual Analyst",
                specialization=[
                    "image_analysis",
                    "screenshot_analysis",
                    "ui_reconnaissance",
                    "visual_vulnerability_detection"
                ]
            )
        }
        
        logger.info("🔧 Unified LLM Configuration loaded:")
        logger.info(f"   Main Model (all tasks): {main_model}")
        logger.info(f"   Visual Model (images only): {visual_model}")
        logger.info(f"   Default Temperature: {self.default_temperature}")
        logger.info(f"   Default Max Tokens: {self.default_max_tokens}")
    
    def _initialize_usage_tracker(self):
        """Initialize usage tracking for all roles."""
        self.usage_tracker = {role: {'calls': 0, 'tokens': 0, 'cost': 0.0} for role in self.ALL_ROLES}
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """
        Get or create a persistent aiohttp session.
        This maintains the API connection active to avoid reconnecting for each request.
        """
        async with self._session_lock:
            if self._session is None or self._session.closed:
                # Create a new session with connection pooling
                connector = aiohttp.TCPConnector(
                    limit=10,  # Max 10 concurrent connections
                    keepalive_timeout=300,  # Keep connections alive for 5 minutes
                    enable_cleanup_closed=True
                )
                timeout = aiohttp.ClientTimeout(
                    total=self.request_timeout,
                    connect=30,
                    sock_read=self.request_timeout
                )
                self._session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout
                )
                logger.info("🔌 Created new persistent API session")
            return self._session
    
    async def close_session(self):
        """Close the persistent session when done."""
        async with self._session_lock:
            if self._session and not self._session.closed:
                await self._session.close()
                self._session = None
                logger.info("🔌 Closed persistent API session")
    
    def _compute_action_signature(self, action: Dict[str, Any]) -> str:
        """Compute a unique signature for an action to enable loop detection."""
        tool = action.get('tool', '')
        args = action.get('args', {}).copy()
        volatile_keys = ['timestamp', 'nonce', 'request_id', 'id', 'random', 'uuid']
        for key in volatile_keys:
            if key in args:
                del args[key]
        normalized = f"{tool}:{json.dumps(args, sort_keys=True)}"
        return hashlib.md5(normalized.encode()).hexdigest()[:16]
    
    def _detect_loop(self, new_action: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Detect if the agent is stuck in a repetitive action loop."""
        new_signature = self._compute_action_signature(new_action)
        recent_actions = self.action_history[-self.loop_detection_window:]
        occurrences = recent_actions.count(new_signature)
        
        if occurrences >= self.loop_occurrence_threshold:
            tool = new_action.get('tool', 'unknown')
            target = new_action.get('args', {}).get('target', 
                     new_action.get('args', {}).get('domain',
                     new_action.get('args', {}).get('url', 'unknown')))
            
            loop_description = f"Action '{tool}' on '{target}' proposed {occurrences + 1} times in last {self.loop_detection_window} turns"
            logger.warning(f"🔄 LOOP DETECTED: {loop_description}")
            return True, loop_description
        
        return False, None
    
    def record_action(self, action: Dict[str, Any]) -> None:
        """Record an action in the history for loop detection."""
        signature = self._compute_action_signature(action)
        self.action_history.append(signature)
        if len(self.action_history) > self.max_action_history:
            self.action_history = self.action_history[-self.max_action_history:]
    
    async def check_and_handle_loop(
        self,
        proposed_action: Dict[str, Any],
        system_prompt: str,
        user_message: str
    ) -> Dict[str, Any]:
        """Check for action loops and handle them by forcing a strategy pivot."""
        is_loop, loop_description = self._detect_loop(proposed_action)
        
        if not is_loop:
            self.record_action(proposed_action)
            return proposed_action
        
        logger.warning(f"🔄 Logic Loop Detected: {loop_description}")
        logger.warning("🔄 Forcing a strategy pivot...")
        
        self.reasoning_display.show_thought(
            f"Loop detected - forcing strategy change",
            thought_type="warning",
            metadata={
                "loop_description": loop_description,
                "proposed_tool": proposed_action.get('tool'),
                "action_history_size": len(self.action_history)
            }
        )
        
        pivot_system_prompt = f"""{system_prompt}

⚠️ CRITICAL LOOP DETECTED ⚠️
You have been stuck in a loop: {loop_description}

You MUST:
1. Choose a COMPLETELY DIFFERENT tool than '{proposed_action.get('tool')}'
2. Or target a DIFFERENT URL/domain/endpoint
3. Consider moving to a different phase of testing
4. If you've exhausted options, use 'finish_mission' with a summary

DO NOT propose the same action again. Think creatively about alternative approaches."""
        
        try:
            response = await self.execute_task(
                task_type='next_action',
                system_prompt=pivot_system_prompt,
                user_message=user_message,
                temperature=self.default_temperature + 0.1
            )
            
            from agents.enhanced_ai_core import parse_json_robust
            
            new_action = await parse_json_robust(
                response.get('content', ''),
                orchestrator=self,
                context="Pivot action after loop detection"
            )
            
            if new_action and new_action.get('tool') != proposed_action.get('tool'):
                logger.info(f"✅ Successfully pivoted to new action: {new_action.get('tool')}")
                self.record_action(new_action)
                return new_action
            else:
                logger.warning("⚠️ Pivot failed, returning original action with loop warning")
                proposed_action['_loop_warning'] = loop_description
                self.record_action(proposed_action)
                return proposed_action
                
        except Exception as e:
            logger.error(f"Error during loop pivot: {e}")
            proposed_action['_loop_warning'] = f"Loop detected but pivot failed: {e}"
            self.record_action(proposed_action)
            return proposed_action

    async def initialize(self):
        """Initialize the orchestrator and validate API keys."""
        try:
            logger.info("🤖 Initializing Unified LLM Orchestrator (Single LLM Architecture)...")
            
            # Load API keys
            master_key = os.environ.get("OPENROUTER_API_KEY") or None
            
            # Build API key registry
            # Main model uses MAIN_API_KEY or falls back to master key
            # Visual model uses VISUAL_API_KEY or falls back to master key
            self.api_keys = {
                'main': os.environ.get("MAIN_API_KEY") or os.environ.get("DEEPSEEK_API_KEY") or master_key,
                'visual': os.environ.get("VISUAL_API_KEY") or master_key
            }
            
            # Validation
            missing_keys = []
            for role, key in self.api_keys.items():
                if not key or key.strip() == "":
                    missing_keys.append(role)
            
            if missing_keys:
                error_msg = (
                    f"❌ CRITICAL: Missing API keys for roles: {', '.join(missing_keys)}. "
                    f"Set OPENROUTER_API_KEY (master key) or provide specific keys "
                    f"(MAIN_API_KEY/DEEPSEEK_API_KEY, VISUAL_API_KEY)."
                )
                logger.error(error_msg)
                raise ValueError(error_msg)
            
            # Strip whitespace
            for role in self.api_keys:
                self.api_keys[role] = self.api_keys[role].strip()
            
            self.api_key = master_key if master_key else None
            
            # Log configuration
            logger.info("🔑 API Key Configuration:")
            logger.info(f"   Master Key: {'✅ Configured' if master_key else '❌ Not Set'}")
            for role, key in self.api_keys.items():
                logger.info(f"   {role.capitalize()} LLM: ✅ Key configured")
            
            logger.info("")
            logger.info("📋 Unified LLM Configuration:")
            logger.info(f"   • Main LLM (all tasks): {self.llms['main'].model_name}")
            logger.info(f"   • Visual LLM (images only): {self.llms['visual'].model_name}")
            
            # Initialize persistent session
            await self._get_session()
            
            self.is_initialized = True
            logger.info("✅ Unified LLM Orchestrator ready (Single LLM mode).")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize orchestrator: {e}", exc_info=True)
            raise
    
    def select_llm(self, task_type: str, domain_context: str = None) -> str:
        """
        Select the appropriate LLM for a given task.
        
        In unified mode, this always returns 'main' unless the task is visual.
        
        Args:
            task_type: Type of task to perform
            domain_context: Optional domain context (ignored in unified mode)
            
        Returns:
            'main' for all text tasks, 'visual' for image analysis
        """
        # Visual tasks go to the visual LLM
        visual_tasks = ['image_analysis', 'screenshot_analysis', 'visual_recon', 'ui_analysis']
        
        if task_type in visual_tasks:
            selected = 'visual'
        else:
            # Everything else goes to the main LLM
            selected = 'main'
        
        logger.info(f"🎯 Task '{task_type}' → LLM: {self.llms[selected].role} ({self.llms[selected].model_name})")
        
        self.reasoning_display.show_thought(
            f"Selected {self.llms[selected].role} for task type '{task_type}'",
            thought_type="decision",
            metadata={
                "task_type": task_type,
                "selected_llm": selected,
                "model": self.llms[selected].model_name
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
        Call the specified LLM via OpenRouter API with retry logic.
        Uses a persistent session for efficiency.
        
        Args:
            llm_type: 'main' or 'visual'
            messages: List of message dicts
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            
        Returns:
            Response dictionary
        """
        if not self.is_initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")
        
        if llm_type not in self.llms:
            # Default to main for unknown types
            llm_type = 'main'
        
        role_api_key = self.api_keys.get(llm_type)
        if not role_api_key:
            raise RuntimeError(f"No API key for role '{llm_type}'")
        
        if temperature is None:
            temperature = self.default_temperature
        if max_tokens is None:
            max_tokens = self.default_max_tokens
        
        config = self.llms[llm_type]
        
        for attempt in range(self.max_retries):
            try:
                logger.info(f"🔄 Calling {config.role} ({config.model_name}) - Attempt {attempt + 1}/{self.max_retries}...")
                
                user_message = next((m['content'] for m in messages if m['role'] == 'user'), "")
                
                self.reasoning_display.show_thought(
                    f"Calling {config.role} for task execution",
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
                
                # Use persistent session
                session = await self._get_session()
                
                async with session.post(
                    config.api_url,
                    headers=headers,
                    json=payload
                ) as response:
                    response_text = await response.text()
                    
                    if response.status != 200:
                        logger.error(f"API Error: {response.status} - {response_text}")
                        
                        if response.status in [429, 500, 502, 503, 504]:
                            if attempt < self.max_retries - 1:
                                wait_time = self.retry_delay * (2 ** attempt)
                                logger.warning(f"Retryable error, waiting {wait_time}s...")
                                await asyncio.sleep(wait_time)
                                continue
                        
                        raise RuntimeError(f"API returned status {response.status}: {response_text}")
                    
                    try:
                        result = json.loads(response_text) if response_text else {}
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse API response: {e}")
                        raise RuntimeError(f"Invalid JSON response: {str(e)}")
                    
                    if 'choices' not in result or not result['choices']:
                        logger.error(f"API response missing 'choices': {result}")
                        raise RuntimeError("API response missing 'choices'")
                    
                    content = result['choices'][0]['message']['content']
                    
                    if not content or len(content.strip()) == 0:
                        if attempt < self.max_retries - 1:
                            await asyncio.sleep(self.retry_delay)
                            continue
                        raise RuntimeError("API returned empty content")
                    
                    logger.info(f"✅ Response received from {config.role}")
                    
                    # Track usage
                    usage = result.get('usage', {})
                    total_tokens = usage.get('total_tokens', 0)
                    self.usage_tracker[llm_type]['calls'] += 1
                    self.usage_tracker[llm_type]['tokens'] += total_tokens
                    
                    if total_tokens > 0:
                        try:
                            loop_time = asyncio.get_running_loop().time()
                        except RuntimeError:
                            loop_time = time.time()
                        
                        self.context_history.append({
                            'llm_type': llm_type,
                            'tokens': total_tokens,
                            'timestamp': loop_time
                        })
                        
                        if total_tokens > (max_tokens * HIGH_TOKEN_USAGE_THRESHOLD):
                            logger.warning(
                                f"⚠️ HIGH TOKEN USAGE: {total_tokens}/{max_tokens} tokens"
                            )
                    
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
                logger.error(f"Timeout calling {config.role} (attempt {attempt + 1})")
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_delay * (2 ** attempt)
                    await asyncio.sleep(wait_time)
                    continue
                raise RuntimeError(f"Request timed out after {self.max_retries} attempts")
            except Exception as e:
                error_type = type(e).__name__
                error_msg = str(e)
                error_key = f"{error_type}:{error_msg[:ERROR_MSG_TRUNCATE_LENGTH]}"
                self.error_patterns[error_key] = self.error_patterns.get(error_key, 0) + 1
                
                if self.error_patterns[error_key] >= RECURRING_ERROR_THRESHOLD:
                    logger.error(f"🔴 RECURRING ERROR: '{error_type}' occurred {self.error_patterns[error_key]} times")
                
                logger.error(f"Error calling {config.role}: {e}", exc_info=True)
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_delay * (2 ** attempt)
                    await asyncio.sleep(wait_time)
                    continue
                raise
        
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
        Execute a task using the unified LLM.
        
        In single-LLM mode, all tasks except visual go to the main LLM.
        
        Args:
            task_type: Type of task (used for logging, not routing in unified mode)
            system_prompt: System prompt
            user_message: User message
            temperature: Sampling temperature
            max_tokens: Maximum tokens
            
        Returns:
            Response dictionary
        """
        # Select LLM (will be 'main' for most tasks)
        llm_type = self.select_llm(task_type)
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ]
        
        return await self.call_llm(llm_type, messages, temperature, max_tokens)
    
    async def execute_multimodal_task(
        self,
        text_prompt: str,
        image_path: str
    ) -> Dict[str, Any]:
        """
        Execute a multimodal task using the visual LLM with an image.
        
        Args:
            text_prompt: Text description of what to analyze
            image_path: Path to the image file
            
        Returns:
            Response dictionary
        """
        if not self.is_initialized:
            raise RuntimeError("Orchestrator not initialized")
        
        logger.info(f"👁️ Executing visual analysis task...")
        logger.info(f"   Prompt: {text_prompt[:100]}...")
        logger.info(f"   Image: {image_path}")
        
        try:
            with open(image_path, 'rb') as image_file:
                image_data = image_file.read()
                image_base64 = base64.b64encode(image_data).decode('utf-8')
            
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
            visual_api_key = self.api_keys['visual']
            
            self.reasoning_display.show_thought(
                f"Preparing visual analysis with {config.role}",
                thought_type="llm_call",
                metadata={
                    "model": config.model_name,
                    "image_path": image_path,
                    "image_size": len(image_data)
                }
            )
            
            headers = {
                "Authorization": f"Bearer {visual_api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/Yahya-hacker/Aegis_agent",
                "X-Title": "Aegis AI Pentesting Agent"
            }
            
            messages = [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": text_prompt},
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:{mime_type};base64,{image_base64}"}
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
            
            session = await self._get_session()
            
            async with session.post(
                config.api_url,
                headers=headers,
                json=payload
            ) as response:
                response_text = await response.text()
                
                if response.status != 200:
                    logger.error(f"Visual API Error: {response.status} - {response_text}")
                    raise RuntimeError(f"API returned status {response.status}")
                
                result = json.loads(response_text)
                
                if 'choices' not in result or not result['choices']:
                    raise RuntimeError("API response missing 'choices'")
                
                content = result['choices'][0]['message']['content']
                
                logger.info("✅ Visual analysis complete")
                
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
        """Get usage statistics for monitoring."""
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
        
        logger.info("📊 Usage Statistics:")
        logger.info(f"   Total LLM Calls: {total_calls}")
        logger.info(f"   Total Tokens: {total_tokens:,}")
        for role, role_stats in self.usage_tracker.items():
            if role_stats['calls'] > 0:
                avg = role_stats['tokens'] / role_stats['calls']
                logger.info(f"   {role}: {role_stats['calls']} calls, {role_stats['tokens']:,} tokens (avg: {avg:.0f})")
        
        return stats
    
    def reset_usage_tracking(self):
        """Reset usage tracking for a new mission phase."""
        logger.info("🔄 Resetting usage tracking...")
        self._initialize_usage_tracker()
        self.context_history = []
