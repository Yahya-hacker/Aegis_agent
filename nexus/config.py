"""
Nexus v2.0 - Centralized Configuration
======================================

All configuration in one place.
Supports: Environment variables + Web UI overrides.
"""

import os
from typing import Optional, Dict, Any, Literal
from dataclasses import dataclass, field
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Base paths
BASE_DIR = Path(__file__).parent.parent.resolve()
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)


# ============================================================================
# MODEL CONFIGURATION (Web UI + .env configurable)
# ============================================================================

@dataclass
class ModelConfig:
    """LLM model configuration."""
    model_id: str
    provider: str = "openrouter"  # openrouter, openai, anthropic, google, ollama, custom
    temperature: float = 0.7
    max_tokens: int = 4096
    api_base: Optional[str] = None  # For custom/local endpoints
    api_key_env: Optional[str] = None  # Env var name for specific API key
    
    @property
    def full_model_id(self) -> str:
        """Get full model ID for LiteLLM."""
        if self.provider == "custom":
            return f"openai/{self.model_id}"  # Custom usually follows OpenAI format
        if self.provider == "ollama":
            return f"ollama/{self.model_id}"
        if "/" in self.model_id and self.provider == "openrouter":
            return self.model_id
        return f"{self.provider}/{self.model_id}"


@dataclass
class ModelRegistry:
    """Registry of all model configurations."""
    
    strategic: ModelConfig = field(default_factory=lambda: ModelConfig(
        model_id=os.getenv("STRATEGIC_MODEL", "deepseek/deepseek-r1"),
        temperature=0.7
    ))
    
    reasoning: ModelConfig = field(default_factory=lambda: ModelConfig(
        model_id=os.getenv("REASONING_MODEL", "deepseek/deepseek-r1"),
        temperature=0.6
    ))
    
    code: ModelConfig = field(default_factory=lambda: ModelConfig(
        model_id=os.getenv("CODE_MODEL", "qwen/qwen-2.5-72b-instruct"),
        temperature=0.4
    ))
    
    visual: ModelConfig = field(default_factory=lambda: ModelConfig(
        model_id=os.getenv("VISUAL_MODEL", "qwen/qwen2.5-vl-72b-instruct"),
        temperature=0.5
    ))
    
    def get(self, role: str) -> ModelConfig:
        """Get model config by role."""
        return getattr(self, role, self.strategic)
    
    def update(self, role: str, model_id: str, **kwargs) -> None:
        """Update model config (for Web UI)."""
        config = self.get(role)
        config.model_id = model_id
        for k, v in kwargs.items():
            if hasattr(config, k):
                setattr(config, k, v)
    
    def to_dict(self) -> Dict[str, Dict[str, Any]]:
        """Export for API/WebUI."""
        return {
            "strategic": {
                "model_id": self.strategic.model_id,
                "temperature": self.strategic.temperature,
            },
            "reasoning": {
                "model_id": self.reasoning.model_id,
                "temperature": self.reasoning.temperature,
            },
            "code": {
                "model_id": self.code.model_id,
                "temperature": self.code.temperature,
            },
            "visual": {
                "model_id": self.visual.model_id,
                "temperature": self.visual.temperature,
            },
        }


# ============================================================================
# API KEYS
# ============================================================================

@dataclass
class APIKeys:
    """API key configuration."""
    openrouter: str = field(default_factory=lambda: os.getenv("OPENROUTER_API_KEY", ""))
    openai: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    anthropic: str = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", ""))
    google: str = field(default_factory=lambda: os.getenv("GOOGLE_API_KEY", ""))
    deepseek: str = field(default_factory=lambda: os.getenv("DEEPSEEK_API_KEY", ""))
    meta: str = field(default_factory=lambda: os.getenv("META_API_KEY", ""))  # If direct access
    ollama_base: str = field(default_factory=lambda: os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"))
    custom_base: str = field(default_factory=lambda: os.getenv("CUSTOM_LLM_BASE_URL", ""))
    custom_key: str = field(default_factory=lambda: os.getenv("CUSTOM_LLM_API_KEY", "sk-custom"))
    e2b: str = field(default_factory=lambda: os.getenv("E2B_API_KEY", ""))
    interact_sh: str = field(default_factory=lambda: os.getenv("INTERACT_SH_TOKEN", ""))
    
    def validate(self) -> Dict[str, bool]:
        """Check which APIs are configured."""
        return {
            "openrouter": bool(self.openrouter),
            "anthropic": bool(self.anthropic),
            "deepseek": bool(self.deepseek),
            "e2b": bool(self.e2b),
            "interact_sh": bool(self.interact_sh),
        }


# ============================================================================
# EPISTEMIC SETTINGS
# ============================================================================

@dataclass
class EpistemicConfig:
    """Epistemic priority system settings."""
    search_threshold: float = float(os.getenv("EPISTEMIC_SEARCH_THRESHOLD", "0.4"))
    balanced_threshold: float = float(os.getenv("EPISTEMIC_BALANCED_THRESHOLD", "0.6"))
    exploit_threshold: float = float(os.getenv("EPISTEMIC_EXPLOIT_THRESHOLD", "0.8"))
    
    # Categories to track
    categories: list = field(default_factory=lambda: [
        "technology_stack",
        "architecture", 
        "input_vectors",
        "authentication",
        "api_structure",
        "database",
        "security_controls",
        "business_logic",
    ])


# ============================================================================
# EXECUTION SETTINGS
# ============================================================================

@dataclass
class ExecutionConfig:
    """Tool execution settings."""
    e2b_timeout: int = int(os.getenv("E2B_SANDBOX_TIMEOUT", "300"))
    e2b_template: str = os.getenv("E2B_TEMPLATE", "base")
    
    browser_headless: bool = os.getenv("BROWSER_HEADLESS", "true").lower() == "true"
    browser_timeout: int = int(os.getenv("BROWSER_TIMEOUT", "30000"))
    
    oast_server: str = os.getenv("OAST_SERVER", "interact.sh")
    oast_poll_interval: int = int(os.getenv("OAST_POLL_INTERVAL", "5"))
    
    proxy_enabled: bool = os.getenv("PROXY_ENABLED", "false").lower() == "true"
    proxy_port: int = int(os.getenv("PROXY_PORT", "8080"))
    
    rate_limit_delay: float = float(os.getenv("RATE_LIMIT_DELAY", "1.0"))
    max_concurrent_tools: int = int(os.getenv("MAX_CONCURRENT_TOOLS", "5"))

    # Docker Settings
    docker_image: str = os.getenv("DOCKER_IMAGE", "kalilinux/kali-rolling")
    docker_container_name: str = os.getenv("DOCKER_CONTAINER_NAME", "nexus-kali")
    docker_volume_path: str = os.getenv("DOCKER_VOLUME_PATH", str(DATA_DIR / "tool_data"))


# ============================================================================
# DATA LAYER SETTINGS
# ============================================================================

@dataclass
class DataConfig:
    """Data storage settings."""
    # Database
    database_url: str = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR}/nexus.db")
    
    # Vector store
    vector_store: str = os.getenv("VECTOR_STORE", "chromadb")  # chromadb, qdrant, pinecone
    vector_collection: str = os.getenv("VECTOR_COLLECTION", "nexus_memory")
    chromadb_path: str = str(DATA_DIR / "chromadb")
    qdrant_url: str = os.getenv("QDRANT_URL", "http://localhost:6333")
    
    # Redis
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    redis_enabled: bool = os.getenv("REDIS_ENABLED", "false").lower() == "true"
    
    # Knowledge graph
    graph_backend: str = os.getenv("GRAPH_BACKEND", "networkx")  # networkx, neo4j
    neo4j_url: str = os.getenv("NEO4J_URL", "bolt://localhost:7687")


# ============================================================================
# TOOL SETTINGS
# ============================================================================

@dataclass
class ToolConfig:
    """Security tool settings."""
    # Risk thresholds
    high_risk_threshold: float = 7.0
    medium_risk_threshold: float = 4.0
    
    # Enabled tool categories
    enabled_categories: list = field(default_factory=lambda: [
        "recon", "exploit", "auth", "fuzzers"
    ])
    
    # Tool paths (optional overrides)
    tool_paths: Dict[str, str] = field(default_factory=dict)
    
    # Wordlists
    wordlist_dir: str = os.getenv("WORDLIST_DIR", "/usr/share/wordlists")
    subdomain_wordlist: str = os.getenv("SUBDOMAIN_WORDLIST", "subdomains-top1million-5000.txt")
    directory_wordlist: str = os.getenv("DIRECTORY_WORDLIST", "directory-list-2.3-medium.txt")


# ============================================================================
# MISSION SETTINGS
# ============================================================================

@dataclass
class MissionConfig:
    """Mission execution settings."""
    max_iterations: int = int(os.getenv("MAX_ITERATIONS", "100"))
    max_backtrack: int = int(os.getenv("MAX_BACKTRACK", "10"))
    auto_report: bool = os.getenv("AUTO_REPORT", "true").lower() == "true"
    
    # Scope
    respect_scope: bool = True
    out_of_scope_patterns: list = field(default_factory=list)
    
    # Mode
    default_mode: str = os.getenv("DEFAULT_MODE", "penetration_testing")


# ============================================================================
# MAIN CONFIG CLASS
# ============================================================================

@dataclass
class NexusConfig:
    """Master configuration for Nexus v2.0."""
    
    models: ModelRegistry = field(default_factory=ModelRegistry)
    api_keys: APIKeys = field(default_factory=APIKeys)
    epistemic: EpistemicConfig = field(default_factory=EpistemicConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    data: DataConfig = field(default_factory=DataConfig)
    tools: ToolConfig = field(default_factory=ToolConfig)
    mission: MissionConfig = field(default_factory=MissionConfig)
    
    # Server
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8000"))
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"
    
    def to_dict(self) -> Dict[str, Any]:
        """Export full config for API."""
        return {
            "models": self.models.to_dict(),
            "api_keys": self.api_keys.validate(),
            "epistemic": {
                "search_threshold": self.epistemic.search_threshold,
                "balanced_threshold": self.epistemic.balanced_threshold,
                "exploit_threshold": self.epistemic.exploit_threshold,
            },
            "execution": {
                "e2b_timeout": self.execution.e2b_timeout,
                "browser_headless": self.execution.browser_headless,
                "rate_limit_delay": self.execution.rate_limit_delay,
            },
            "data": {
                "vector_store": self.data.vector_store,
                "redis_enabled": self.data.redis_enabled,
            },
            "mission": {
                "max_iterations": self.mission.max_iterations,
                "auto_report": self.mission.auto_report,
            },
        }


# Global config instance
_config: Optional[NexusConfig] = None


def get_config() -> NexusConfig:
    """Get the global Nexus configuration."""
    global _config
    if _config is None:
        _config = NexusConfig()
    return _config


def update_model_config(role: str, model_id: str, **kwargs) -> None:
    """Update model configuration (for Web UI)."""
    config = get_config()
    config.models.update(role, model_id, **kwargs)
