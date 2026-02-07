"""
Nexus - LiteLLM Client
======================

Unified LLM client with multi-provider support and fallbacks.
Strictly typed for Python 3.10+.
"""

import os
import json
import logging
from typing import Literal, Optional, Any
from dotenv import load_dotenv

import litellm
from litellm import acompletion

load_dotenv()

logger = logging.getLogger(__name__)

# Type alias for model roles
ModelType = Literal["strategic", "reasoning", "code", "visual"]


# Model mapping from environment
def get_model_mapping() -> dict[ModelType, str]:
    """Get model mapping from environment variables."""
    return {
        "strategic": os.getenv("STRATEGIC_MODEL", "openrouter/deepseek/deepseek-r1"),
        "reasoning": os.getenv("REASONING_MODEL", "openrouter/deepseek/deepseek-r1"),
        "code": os.getenv("CODE_MODEL", "openrouter/qwen/qwen-2.5-72b-instruct"),
        "visual": os.getenv("VISUAL_MODEL", "openrouter/qwen/qwen2.5-vl-72b-instruct"),
    }


# Fallback chains per model type
FALLBACK_CHAINS: dict[ModelType, list[str]] = {
    "strategic": [
        "openrouter/anthropic/claude-3-opus",
        "openrouter/deepseek/deepseek-r1",
    ],
    "reasoning": [
        "openrouter/deepseek/deepseek-r1",
        "openrouter/anthropic/claude-3-sonnet",
    ],
    "code": [
        "openrouter/qwen/qwen-2.5-72b-instruct",
        "openrouter/deepseek/deepseek-coder-33b-instruct",
    ],
    "visual": [
        "openrouter/qwen/qwen2.5-vl-72b-instruct",
    ],
}


# Configure LiteLLM
litellm.set_verbose = os.getenv("LITELLM_LOG", "INFO") == "DEBUG"

# Set API keys
if os.getenv("OPENROUTER_API_KEY"):
    os.environ["OPENROUTER_API_KEY"] = os.getenv("OPENROUTER_API_KEY")
if os.getenv("ANTHROPIC_API_KEY"):
    os.environ["ANTHROPIC_API_KEY"] = os.getenv("ANTHROPIC_API_KEY")
if os.getenv("DEEPSEEK_API_KEY"):
    os.environ["DEEPSEEK_API_KEY"] = os.getenv("DEEPSEEK_API_KEY")


async def get_completion(
    model_type: ModelType,
    messages: list[dict[str, Any]],
    temperature: float = 0.7,
    max_tokens: int = 4096,
    response_format: Optional[dict] = None,
    **kwargs: Any
) -> dict[str, Any]:
    """
    Get completion from LLM with automatic fallbacks.
    
    Args:
        model_type: Type of model to use (strategic, reasoning, code, visual)
        messages: Chat messages
        temperature: Sampling temperature
        max_tokens: Maximum tokens in response
        response_format: Optional JSON response format
        **kwargs: Additional LiteLLM parameters
    
    Returns:
        Parsed response with content and metadata
    """
    model_mapping = get_model_mapping()
    primary_model = model_mapping[model_type]
    fallbacks = FALLBACK_CHAINS.get(model_type, [])
    
    logger.info(f"🧠 LiteLLM: {model_type} -> {primary_model}")
    
    try:
        response = await acompletion(
            model=primary_model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=response_format,
            fallbacks=fallbacks if os.getenv("LITELLM_FALLBACKS", "true").lower() == "true" else None,
            **kwargs
        )
        
        content = response.choices[0].message.content
        
        return {
            "content": content,
            "model": response.model,
            "usage": {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            },
            "finish_reason": response.choices[0].finish_reason,
        }
        
    except Exception as e:
        logger.error(f"❌ LiteLLM error: {e}")
        raise


async def get_json_completion(
    model_type: ModelType,
    messages: list[dict[str, Any]],
    **kwargs: Any
) -> Optional[dict[str, Any]]:
    """
    Get JSON-formatted completion.
    
    Args:
        model_type: Type of model to use
        messages: Chat messages
        **kwargs: Additional parameters
    
    Returns:
        Parsed JSON response or None if parsing fails
    """
    response = await get_completion(
        model_type=model_type,
        messages=messages,
        response_format={"type": "json_object"},
        **kwargs
    )
    
    try:
        return json.loads(response["content"])
    except json.JSONDecodeError as e:
        logger.warning(f"⚠️ JSON parse failed: {e}")
        # Try to extract JSON from response
        content = response["content"]
        start = content.find("{")
        end = content.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(content[start:end])
            except json.JSONDecodeError:
                pass
        return None


async def stream_completion(
    model_type: ModelType,
    messages: list[dict[str, Any]],
    **kwargs: Any
):
    """
    Stream completion tokens.
    
    Yields token chunks for real-time display.
    """
    model_mapping = get_model_mapping()
    primary_model = model_mapping[model_type]
    
    async for chunk in await acompletion(
        model=primary_model,
        messages=messages,
        stream=True,
        **kwargs
    ):
        if chunk.choices[0].delta.content:
            yield chunk.choices[0].delta.content


# Singleton client
class LiteLLMClient:
    """Singleton LiteLLM client for consistent usage."""
    
    _instance: Optional["LiteLLMClient"] = None
    
    def __new__(cls) -> "LiteLLMClient":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    async def complete(self, model_type: ModelType, messages: list[dict], **kwargs) -> dict:
        return await get_completion(model_type, messages, **kwargs)
    
    async def complete_json(self, model_type: ModelType, messages: list[dict], **kwargs) -> Optional[dict]:
        return await get_json_completion(model_type, messages, **kwargs)


def get_litellm_client() -> LiteLLMClient:
    """Get the LiteLLM client singleton."""
    return LiteLLMClient()
