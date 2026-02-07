# aegis/llm.py
"""
Clean LLM Interface for Aegis AI.

Provides a unified async interface for multi-model LLM interactions.
Supports OpenRouter, local models, and fallback chains.
"""

import os
import json
import logging
import aiohttp
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


class LLMEngine:
    """
    Unified LLM interface supporting multiple models.
    
    Model Types:
    - strategic: High-level planning and analysis
    - reasoning: Deep thinking (DeepSeek-R1 style)
    - coder: Code generation and technical tasks
    - fast: Quick responses for simple tasks
    """
    
    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY")
        self.base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "https://github.com/aegis-agent",
            "X-Title": "Aegis Agent",
            "Content-Type": "application/json"
        }
        
        # Model configuration
        self.models = {
            "strategic": os.getenv("STRATEGIC_MODEL", "nousresearch/hermes-3-llama-3.1-405b:free"),
            "reasoning": os.getenv("REASONING_MODEL", "deepseek/deepseek-r1:free"),
            "coder": os.getenv("CODE_MODEL", "qwen/qwen-2.5-coder-32b-instruct:free"),
            "fast": os.getenv("FAST_MODEL", "google/gemini-2.0-flash-exp:free") 
        }
    
    async def chat(
        self, 
        messages: List[Dict[str, str]], 
        model_type: str = "strategic",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        json_mode: bool = False
    ) -> str:
        """Send a chat completion request."""
        model = self.models.get(model_type, self.models["strategic"])
        
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }
        
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
            
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    headers=self.headers,
                    json=payload
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        logger.error(f"LLM API Error {response.status}: {error_text}")
                        return ""
                        
                    data = await response.json()
                    return data['choices'][0]['message']['content']
            except Exception as e:
                logger.error(f"LLM Request Failed: {e}")
                return ""
    
    async def get_json(
        self,
        messages: List[Dict[str, str]],
        model_type: str = "strategic"
    ) -> Dict[str, Any]:
        """Get a JSON response with robust parsing."""
        content = await self.chat(messages, model_type, json_mode=True)
        return self._parse_json(content)
    
    def _parse_json(self, content: str) -> Dict[str, Any]:
        """Parse JSON from potentially markdown-wrapped response."""
        try:
            # Strip markdown code blocks
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            
            return json.loads(content.strip())
        except Exception as e:
            logger.error(f"JSON Parsing Failed: {e}")
            return {}


# Singleton
_llm_engine = None

def get_llm() -> LLMEngine:
    global _llm_engine
    if not _llm_engine:
        _llm_engine = LLMEngine()
    return _llm_engine
