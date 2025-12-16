#!/usr/bin/env python3
"""
AEGIS OMEGA PROTOCOL - Hive Mind Module
========================================

Implements Collaborative Swarm Intelligence:
- Distributed, real-time knowledge sharing across agent instances
- WAF bypass propagation: If Agent A finds a bypass, Agent B knows instantly
- Shared vulnerability discoveries and successful attack patterns
- Exponentially faster learning during engagements

Supports multiple backends:
- File-based (default): Uses shared JSON files for single-machine multi-agent
- Redis: For distributed multi-machine deployments
- WebSocket: For real-time browser-based agents
"""

import asyncio
import logging
import json
import os
import time
import hashlib
import uuid
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from enum import Enum
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class KnowledgeType(Enum):
    """Types of knowledge that can be shared"""
    WAF_BYPASS = "waf_bypass"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    ENDPOINT = "endpoint"
    TECHNOLOGY = "technology"
    ATTACK_PATTERN = "attack_pattern"
    FAILED_ATTEMPT = "failed_attempt"
    SUCCESS_PATTERN = "success_pattern"
    RATE_LIMIT = "rate_limit"
    HONEYPOT = "honeypot"


@dataclass
class SharedKnowledge:
    """A piece of knowledge to share across the hive"""
    id: str
    knowledge_type: str
    target_domain: str  # Domain this knowledge applies to (e.g., "*.example.com")
    data: Dict[str, Any]
    confidence: float  # 0.0-1.0
    source_agent: str  # Agent ID that discovered this
    timestamp: float
    ttl: int = 3600  # Time-to-live in seconds
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "id": self.id,
            "knowledge_type": self.knowledge_type,
            "target_domain": self.target_domain,
            "data": self.data,
            "confidence": self.confidence,
            "source_agent": self.source_agent,
            "timestamp": self.timestamp,
            "ttl": self.ttl,
            "tags": self.tags
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SharedKnowledge":
        """Create from dictionary"""
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            knowledge_type=data.get("knowledge_type", "unknown"),
            target_domain=data.get("target_domain", "*"),
            data=data.get("data", {}),
            confidence=data.get("confidence", 0.5),
            source_agent=data.get("source_agent", "unknown"),
            timestamp=data.get("timestamp", time.time()),
            ttl=data.get("ttl", 3600),
            tags=data.get("tags", [])
        )
    
    def is_expired(self) -> bool:
        """Check if this knowledge has expired"""
        return time.time() > (self.timestamp + self.ttl)


class HiveMindBackend(ABC):
    """Abstract base class for Hive Mind storage backends"""
    
    @abstractmethod
    async def publish(self, knowledge: SharedKnowledge) -> bool:
        """Publish knowledge to the hive"""
        pass
    
    @abstractmethod
    async def subscribe(
        self,
        callback: Callable[[SharedKnowledge], None],
        filters: Optional[Dict[str, Any]] = None
    ) -> None:
        """Subscribe to knowledge updates"""
        pass
    
    @abstractmethod
    async def query(
        self,
        knowledge_type: Optional[str] = None,
        target_domain: Optional[str] = None,
        tags: Optional[List[str]] = None,
        min_confidence: float = 0.0
    ) -> List[SharedKnowledge]:
        """Query knowledge from the hive"""
        pass
    
    @abstractmethod
    async def get_agents(self) -> List[str]:
        """Get list of active agents in the hive"""
        pass


class FileBasedBackend(HiveMindBackend):
    """
    File-based backend for single-machine multi-agent setups.
    Uses shared JSON files with file locking.
    """
    
    def __init__(self, storage_dir: str = "data/hive_mind"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.knowledge_file = self.storage_dir / "shared_knowledge.json"
        self.agents_file = self.storage_dir / "active_agents.json"
        
        self._subscribers: List[Callable] = []
        self._last_check = 0.0
        self._check_interval = 1.0  # Check for updates every second
        self._running = False
        
        # Initialize files
        if not self.knowledge_file.exists():
            self._write_json(self.knowledge_file, {"knowledge": []})
        if not self.agents_file.exists():
            self._write_json(self.agents_file, {"agents": {}})
    
    def _read_json(self, file_path: Path) -> Dict:
        """Thread-safe JSON read"""
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    
    def _write_json(self, file_path: Path, data: Dict) -> None:
        """Thread-safe JSON write"""
        temp_file = file_path.with_suffix('.tmp')
        with open(temp_file, 'w') as f:
            json.dump(data, f, indent=2)
        temp_file.replace(file_path)
    
    async def publish(self, knowledge: SharedKnowledge) -> bool:
        """Publish knowledge to shared file"""
        try:
            data = self._read_json(self.knowledge_file)
            knowledge_list = data.get("knowledge", [])
            
            # Check for duplicate
            existing_ids = {k.get("id") for k in knowledge_list}
            if knowledge.id in existing_ids:
                # Update existing
                knowledge_list = [
                    knowledge.to_dict() if k.get("id") == knowledge.id else k
                    for k in knowledge_list
                ]
            else:
                knowledge_list.append(knowledge.to_dict())
            
            # Clean expired entries
            current_time = time.time()
            knowledge_list = [
                k for k in knowledge_list
                if current_time <= (k.get("timestamp", 0) + k.get("ttl", 3600))
            ]
            
            data["knowledge"] = knowledge_list
            self._write_json(self.knowledge_file, data)
            
            # Notify subscribers
            for callback in self._subscribers:
                try:
                    callback(knowledge)
                except Exception as e:
                    logger.error(f"Subscriber callback error: {e}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to publish knowledge: {e}")
            return False
    
    async def subscribe(
        self,
        callback: Callable[[SharedKnowledge], None],
        filters: Optional[Dict[str, Any]] = None
    ) -> None:
        """Subscribe to knowledge updates"""
        self._subscribers.append(callback)
        
        # Start polling if not already running
        if not self._running:
            self._running = True
            asyncio.create_task(self._poll_for_updates())
    
    async def _poll_for_updates(self):
        """Poll for new knowledge updates"""
        last_seen_ids: Set[str] = set()
        
        # Initialize with existing IDs
        data = self._read_json(self.knowledge_file)
        for k in data.get("knowledge", []):
            last_seen_ids.add(k.get("id", ""))
        
        while self._running:
            try:
                await asyncio.sleep(self._check_interval)
                
                data = self._read_json(self.knowledge_file)
                current_knowledge = data.get("knowledge", [])
                
                for k_dict in current_knowledge:
                    k_id = k_dict.get("id", "")
                    if k_id and k_id not in last_seen_ids:
                        last_seen_ids.add(k_id)
                        knowledge = SharedKnowledge.from_dict(k_dict)
                        
                        for callback in self._subscribers:
                            try:
                                callback(knowledge)
                            except Exception as e:
                                logger.error(f"Subscriber callback error: {e}")
                                
            except Exception as e:
                logger.error(f"Polling error: {e}")
    
    async def query(
        self,
        knowledge_type: Optional[str] = None,
        target_domain: Optional[str] = None,
        tags: Optional[List[str]] = None,
        min_confidence: float = 0.0
    ) -> List[SharedKnowledge]:
        """Query knowledge from shared file"""
        data = self._read_json(self.knowledge_file)
        results = []
        current_time = time.time()
        
        for k_dict in data.get("knowledge", []):
            # Check expiration
            if current_time > (k_dict.get("timestamp", 0) + k_dict.get("ttl", 3600)):
                continue
            
            # Check filters
            if knowledge_type and k_dict.get("knowledge_type") != knowledge_type:
                continue
            
            if target_domain:
                k_domain = k_dict.get("target_domain", "*")
                if k_domain != "*" and not self._domain_matches(target_domain, k_domain):
                    continue
            
            if k_dict.get("confidence", 0) < min_confidence:
                continue
            
            if tags:
                k_tags = set(k_dict.get("tags", []))
                if not any(t in k_tags for t in tags):
                    continue
            
            results.append(SharedKnowledge.from_dict(k_dict))
        
        return results
    
    def _domain_matches(self, target: str, pattern: str) -> bool:
        """Check if target domain matches pattern (supports wildcards)"""
        if pattern == "*":
            return True
        if pattern.startswith("*."):
            suffix = pattern[1:]  # Remove *
            return target.endswith(suffix) or target == pattern[2:]
        return target == pattern
    
    async def get_agents(self) -> List[str]:
        """Get list of active agents"""
        data = self._read_json(self.agents_file)
        agents = data.get("agents", {})
        
        # Filter to active agents (heartbeat within last 60 seconds)
        current_time = time.time()
        active = [
            agent_id for agent_id, last_seen in agents.items()
            if current_time - last_seen < 60
        ]
        return active
    
    async def heartbeat(self, agent_id: str) -> None:
        """Update agent heartbeat"""
        data = self._read_json(self.agents_file)
        agents = data.get("agents", {})
        agents[agent_id] = time.time()
        data["agents"] = agents
        self._write_json(self.agents_file, data)


class RedisBackend(HiveMindBackend):
    """
    Redis-based backend for distributed multi-machine deployments.
    Uses Redis pub/sub for real-time updates.
    """
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        password: Optional[str] = None,
        db: int = 0,
        prefix: str = "aegis_hive:"
    ):
        self.host = host
        self.port = port
        self.password = password
        self.db = db
        self.prefix = prefix
        self._redis = None
        self._pubsub = None
        self._subscribers: List[Callable] = []
    
    async def _get_redis(self):
        """Lazy initialization of Redis connection"""
        if self._redis is None:
            try:
                import aioredis
                self._redis = await aioredis.from_url(
                    f"redis://{self.host}:{self.port}/{self.db}",
                    password=self.password,
                    encoding="utf-8",
                    decode_responses=True
                )
            except ImportError:
                logger.error("aioredis not installed. Install with: pip install aioredis")
                raise
        return self._redis
    
    async def publish(self, knowledge: SharedKnowledge) -> bool:
        """Publish knowledge to Redis"""
        try:
            redis = await self._get_redis()
            
            # Store in hash
            key = f"{self.prefix}knowledge:{knowledge.id}"
            await redis.hset(key, mapping={"data": json.dumps(knowledge.to_dict())})
            await redis.expire(key, knowledge.ttl)
            
            # Add to type index
            type_key = f"{self.prefix}type:{knowledge.knowledge_type}"
            await redis.sadd(type_key, knowledge.id)
            
            # Add to domain index
            domain_key = f"{self.prefix}domain:{knowledge.target_domain}"
            await redis.sadd(domain_key, knowledge.id)
            
            # Publish notification
            channel = f"{self.prefix}updates"
            await redis.publish(channel, json.dumps(knowledge.to_dict()))
            
            return True
            
        except Exception as e:
            logger.error(f"Redis publish failed: {e}")
            return False
    
    async def subscribe(
        self,
        callback: Callable[[SharedKnowledge], None],
        filters: Optional[Dict[str, Any]] = None
    ) -> None:
        """Subscribe to Redis pub/sub for real-time updates"""
        self._subscribers.append(callback)
        
        # Start listener if not already running
        if self._pubsub is None:
            redis = await self._get_redis()
            self._pubsub = redis.pubsub()
            await self._pubsub.subscribe(f"{self.prefix}updates")
            asyncio.create_task(self._listen_for_updates())
    
    async def _listen_for_updates(self):
        """Listen for Redis pub/sub messages"""
        while True:
            try:
                message = await self._pubsub.get_message(
                    ignore_subscribe_messages=True,
                    timeout=1.0
                )
                
                if message and message.get("type") == "message":
                    data = json.loads(message.get("data", "{}"))
                    knowledge = SharedKnowledge.from_dict(data)
                    
                    for callback in self._subscribers:
                        try:
                            callback(knowledge)
                        except Exception as e:
                            logger.error(f"Subscriber callback error: {e}")
                            
            except Exception as e:
                logger.error(f"Redis listener error: {e}")
                await asyncio.sleep(1)
    
    async def query(
        self,
        knowledge_type: Optional[str] = None,
        target_domain: Optional[str] = None,
        tags: Optional[List[str]] = None,
        min_confidence: float = 0.0
    ) -> List[SharedKnowledge]:
        """Query knowledge from Redis"""
        try:
            redis = await self._get_redis()
            results = []
            
            # Get knowledge IDs based on filters
            if knowledge_type:
                type_key = f"{self.prefix}type:{knowledge_type}"
                ids = await redis.smembers(type_key)
            elif target_domain:
                domain_key = f"{self.prefix}domain:{target_domain}"
                ids = await redis.smembers(domain_key)
            else:
                # Get all knowledge IDs
                pattern = f"{self.prefix}knowledge:*"
                keys = []
                async for key in redis.scan_iter(match=pattern):
                    kid = key.replace(f"{self.prefix}knowledge:", "")
                    keys.append(kid)
                ids = keys
            
            # Fetch each knowledge entry
            for kid in ids:
                key = f"{self.prefix}knowledge:{kid}"
                data = await redis.hget(key, "data")
                if data:
                    k_dict = json.loads(data)
                    
                    if k_dict.get("confidence", 0) >= min_confidence:
                        results.append(SharedKnowledge.from_dict(k_dict))
            
            return results
            
        except Exception as e:
            logger.error(f"Redis query failed: {e}")
            return []
    
    async def get_agents(self) -> List[str]:
        """Get list of active agents from Redis"""
        try:
            redis = await self._get_redis()
            agents_key = f"{self.prefix}agents"
            
            current_time = time.time()
            agents = await redis.hgetall(agents_key)
            
            active = [
                agent_id for agent_id, last_seen in agents.items()
                if current_time - float(last_seen) < 60
            ]
            return active
            
        except Exception as e:
            logger.error(f"Failed to get agents: {e}")
            return []
    
    async def heartbeat(self, agent_id: str) -> None:
        """Update agent heartbeat in Redis"""
        try:
            redis = await self._get_redis()
            agents_key = f"{self.prefix}agents"
            await redis.hset(agents_key, agent_id, str(time.time()))
        except Exception as e:
            logger.error(f"Heartbeat failed: {e}")


class HiveMind:
    """
    Hive Mind - Collaborative Swarm Intelligence System.
    
    Enables multiple Aegis agent instances to share knowledge in real-time:
    - WAF bypass techniques
    - Discovered vulnerabilities
    - Successful attack patterns
    - Rate limit information
    - Honeypot detection
    
    Example:
        Agent A finds Cloudflare bypass on subdomain1.example.com
        -> Publishes to Hive Mind
        -> Agent B attacking subdomain2.example.com instantly knows and applies bypass
    """
    
    def __init__(
        self,
        agent_id: Optional[str] = None,
        backend: Optional[HiveMindBackend] = None,
        auto_apply: bool = True
    ):
        """
        Initialize the Hive Mind.
        
        Args:
            agent_id: Unique identifier for this agent instance
            backend: Storage backend (defaults to FileBasedBackend)
            auto_apply: Automatically apply received knowledge
        """
        self.agent_id = agent_id or f"agent_{uuid.uuid4().hex[:8]}"
        self.backend = backend or FileBasedBackend()
        self.auto_apply = auto_apply
        
        # Local knowledge cache
        self._local_cache: Dict[str, SharedKnowledge] = {}
        
        # Knowledge handlers
        self._handlers: Dict[str, List[Callable]] = {}
        
        # Statistics
        self.stats = {
            "published": 0,
            "received": 0,
            "applied": 0,
            "queries": 0,
            "errors": 0
        }
        
        # Auto-apply rules
        self._auto_apply_rules: Dict[str, Callable] = {}
        
        # Robustness: Graceful degradation support
        self._degraded_mode = False
        self._last_error_time: Optional[float] = None
        self._consecutive_errors = 0
        self._max_consecutive_errors = 5
        
        logger.info(f"🐝 Hive Mind initialized - Agent ID: {self.agent_id}")
    
    async def start(self) -> None:
        """Start the Hive Mind (subscribe to updates, start heartbeat)"""
        try:
            # Subscribe to knowledge updates
            await self.backend.subscribe(self._on_knowledge_received)
            
            # Start heartbeat
            asyncio.create_task(self._heartbeat_loop())
            
            self._degraded_mode = False
        except Exception as e:
            logger.warning(f"⚠️ Hive Mind starting in degraded mode: {e}")
            self._degraded_mode = True
        
        logger.info("🐝 Hive Mind connected to swarm")
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeats"""
        while True:
            try:
                if hasattr(self.backend, 'heartbeat'):
                    await self.backend.heartbeat(self.agent_id)
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
            await asyncio.sleep(30)  # Every 30 seconds
    
    def _on_knowledge_received(self, knowledge: SharedKnowledge) -> None:
        """Handle received knowledge"""
        # Skip our own knowledge
        if knowledge.source_agent == self.agent_id:
            return
        
        logger.info(f"🐝 Received knowledge: {knowledge.knowledge_type} from {knowledge.source_agent}")
        self.stats["received"] += 1
        
        # Cache locally
        self._local_cache[knowledge.id] = knowledge
        
        # Call handlers
        if knowledge.knowledge_type in self._handlers:
            for handler in self._handlers[knowledge.knowledge_type]:
                try:
                    handler(knowledge)
                except Exception as e:
                    logger.error(f"Knowledge handler error: {e}")
        
        # Auto-apply if enabled
        if self.auto_apply and knowledge.knowledge_type in self._auto_apply_rules:
            try:
                apply_func = self._auto_apply_rules[knowledge.knowledge_type]
                apply_func(knowledge)
                self.stats["applied"] += 1
                logger.info(f"✅ Auto-applied {knowledge.knowledge_type}")
            except Exception as e:
                logger.error(f"Auto-apply error: {e}")
    
    async def share_waf_bypass(
        self,
        target_domain: str,
        waf_type: str,
        bypass_technique: str,
        payload: str,
        headers: Optional[Dict[str, str]] = None,
        confidence: float = 0.9
    ) -> bool:
        """
        Share a discovered WAF bypass with the hive.
        
        Args:
            target_domain: Domain where bypass was discovered
            waf_type: Type of WAF (e.g., "cloudflare", "akamai")
            bypass_technique: Description of the technique
            payload: The actual bypass payload
            headers: Any special headers used
            confidence: Confidence level (0.0-1.0)
            
        Returns:
            True if successfully shared
        """
        knowledge = SharedKnowledge(
            id=f"waf_{hashlib.md5(f'{target_domain}{waf_type}{payload}'.encode()).hexdigest()[:12]}",
            knowledge_type=KnowledgeType.WAF_BYPASS.value,
            target_domain=target_domain,
            data={
                "waf_type": waf_type,
                "bypass_technique": bypass_technique,
                "payload": payload,
                "headers": headers or {},
                "verified": True
            },
            confidence=confidence,
            source_agent=self.agent_id,
            timestamp=time.time(),
            ttl=7200,  # 2 hours
            tags=["waf", waf_type, "bypass"]
        )
        
        success = await self.backend.publish(knowledge)
        if success:
            self.stats["published"] += 1
            logger.info(f"🐝 Shared WAF bypass: {waf_type} on {target_domain}")
        
        return success
    
    async def share_vulnerability(
        self,
        target_domain: str,
        vuln_type: str,
        endpoint: str,
        severity: str,
        payload: Optional[str] = None,
        evidence: Optional[str] = None,
        confidence: float = 0.8
    ) -> bool:
        """
        Share a discovered vulnerability with the hive.
        
        Args:
            target_domain: Domain where vulnerability was found
            vuln_type: Type of vulnerability (e.g., "sqli", "xss")
            endpoint: Vulnerable endpoint
            severity: Severity level (critical, high, medium, low)
            payload: Exploit payload
            evidence: Proof of vulnerability
            confidence: Confidence level
            
        Returns:
            True if successfully shared
        """
        knowledge = SharedKnowledge(
            id=f"vuln_{hashlib.md5(f'{target_domain}{endpoint}{vuln_type}'.encode()).hexdigest()[:12]}",
            knowledge_type=KnowledgeType.VULNERABILITY.value,
            target_domain=target_domain,
            data={
                "type": vuln_type,
                "endpoint": endpoint,
                "severity": severity,
                "payload": payload,
                "evidence": evidence,
                "verified": confidence >= 0.8
            },
            confidence=confidence,
            source_agent=self.agent_id,
            timestamp=time.time(),
            ttl=3600,  # 1 hour
            tags=["vulnerability", vuln_type, severity]
        )
        
        success = await self.backend.publish(knowledge)
        if success:
            self.stats["published"] += 1
            logger.info(f"🐝 Shared vulnerability: {vuln_type} on {endpoint}")
        
        return success
    
    async def share_success_pattern(
        self,
        target_domain: str,
        pattern_name: str,
        pattern_data: Dict[str, Any],
        success_rate: float = 1.0
    ) -> bool:
        """
        Share a successful attack pattern with the hive.
        
        Args:
            target_domain: Domain where pattern worked
            pattern_name: Name of the pattern
            pattern_data: Pattern details
            success_rate: How often this pattern works
            
        Returns:
            True if successfully shared
        """
        knowledge = SharedKnowledge(
            id=f"pattern_{hashlib.md5(f'{target_domain}{pattern_name}'.encode()).hexdigest()[:12]}",
            knowledge_type=KnowledgeType.SUCCESS_PATTERN.value,
            target_domain=target_domain,
            data={
                "name": pattern_name,
                **pattern_data,
                "success_rate": success_rate
            },
            confidence=success_rate,
            source_agent=self.agent_id,
            timestamp=time.time(),
            ttl=3600,
            tags=["pattern", "success"]
        )
        
        success = await self.backend.publish(knowledge)
        if success:
            self.stats["published"] += 1
        
        return success
    
    async def share_failed_attempt(
        self,
        target_domain: str,
        attempt_type: str,
        details: Dict[str, Any]
    ) -> bool:
        """
        Share a failed attempt to prevent other agents from wasting time.
        
        Args:
            target_domain: Target domain
            attempt_type: What was attempted
            details: Details of the failure
            
        Returns:
            True if successfully shared
        """
        knowledge = SharedKnowledge(
            id=f"fail_{hashlib.md5(f'{target_domain}{attempt_type}{time.time()}'.encode()).hexdigest()[:12]}",
            knowledge_type=KnowledgeType.FAILED_ATTEMPT.value,
            target_domain=target_domain,
            data={
                "attempt_type": attempt_type,
                **details,
                "do_not_retry": True
            },
            confidence=0.9,
            source_agent=self.agent_id,
            timestamp=time.time(),
            ttl=1800,  # 30 minutes
            tags=["failure", attempt_type]
        )
        
        return await self.backend.publish(knowledge)
    
    async def get_waf_bypasses(
        self,
        target_domain: str
    ) -> List[SharedKnowledge]:
        """
        Get known WAF bypasses for a target domain.
        
        Args:
            target_domain: Domain to get bypasses for
            
        Returns:
            List of WAF bypass knowledge
        """
        self.stats["queries"] += 1
        
        bypasses = await self.backend.query(
            knowledge_type=KnowledgeType.WAF_BYPASS.value,
            target_domain=target_domain,
            min_confidence=0.7
        )
        
        # Also check wildcard domain
        parsed = target_domain.split(".")
        if len(parsed) > 2:
            wildcard = "*." + ".".join(parsed[-2:])
            wildcard_bypasses = await self.backend.query(
                knowledge_type=KnowledgeType.WAF_BYPASS.value,
                target_domain=wildcard,
                min_confidence=0.7
            )
            bypasses.extend(wildcard_bypasses)
        
        return bypasses
    
    async def get_vulnerabilities(
        self,
        target_domain: str,
        min_confidence: float = 0.7
    ) -> List[SharedKnowledge]:
        """
        Get known vulnerabilities for a target domain.
        
        Args:
            target_domain: Domain to get vulnerabilities for
            min_confidence: Minimum confidence level
            
        Returns:
            List of vulnerability knowledge
        """
        self.stats["queries"] += 1
        
        return await self.backend.query(
            knowledge_type=KnowledgeType.VULNERABILITY.value,
            target_domain=target_domain,
            min_confidence=min_confidence
        )
    
    async def get_failed_attempts(
        self,
        target_domain: str
    ) -> List[SharedKnowledge]:
        """
        Get failed attempts to avoid repeating them.
        
        Args:
            target_domain: Target domain
            
        Returns:
            List of failed attempt knowledge
        """
        return await self.backend.query(
            knowledge_type=KnowledgeType.FAILED_ATTEMPT.value,
            target_domain=target_domain
        )
    
    def register_handler(
        self,
        knowledge_type: str,
        handler: Callable[[SharedKnowledge], None]
    ) -> None:
        """
        Register a handler for specific knowledge type.
        
        Args:
            knowledge_type: Type of knowledge to handle
            handler: Callback function
        """
        if knowledge_type not in self._handlers:
            self._handlers[knowledge_type] = []
        self._handlers[knowledge_type].append(handler)
    
    def set_auto_apply_rule(
        self,
        knowledge_type: str,
        apply_func: Callable[[SharedKnowledge], None]
    ) -> None:
        """
        Set an auto-apply rule for knowledge type.
        
        Args:
            knowledge_type: Type of knowledge
            apply_func: Function to apply the knowledge
        """
        self._auto_apply_rules[knowledge_type] = apply_func
    
    async def get_swarm_status(self) -> Dict[str, Any]:
        """Get status of the swarm"""
        agents = await self.backend.get_agents()
        
        return {
            "agent_id": self.agent_id,
            "active_agents": len(agents),
            "agents": agents,
            "stats": self.stats,
            "local_cache_size": len(self._local_cache)
        }
    
    def format_for_llm(self, target_domain: str) -> str:
        """
        Format hive knowledge for LLM consumption.
        
        Args:
            target_domain: Domain to get knowledge for
            
        Returns:
            Formatted string for LLM context
        """
        lines = ["[HIVE MIND - SHARED INTELLIGENCE]"]
        
        # Get cached knowledge for this domain
        relevant = [
            k for k in self._local_cache.values()
            if not k.is_expired() and (
                k.target_domain == "*" or
                k.target_domain == target_domain or
                (k.target_domain.startswith("*.") and target_domain.endswith(k.target_domain[1:]))
            )
        ]
        
        if not relevant:
            lines.append("No shared intelligence available for this target.")
            return "\n".join(lines)
        
        # Group by type
        by_type: Dict[str, List[SharedKnowledge]] = {}
        for k in relevant:
            if k.knowledge_type not in by_type:
                by_type[k.knowledge_type] = []
            by_type[k.knowledge_type].append(k)
        
        for ktype, items in by_type.items():
            lines.append(f"\n{ktype.upper()} ({len(items)} items):")
            for item in items[:5]:  # Limit to 5 per type
                data_preview = str(item.data)[:100]
                lines.append(f"  - [conf: {item.confidence:.0%}] {data_preview}...")
        
        lines.append(f"\nTotal: {len(relevant)} knowledge items from {len(set(k.source_agent for k in relevant))} agents")
        
        return "\n".join(lines)


# Singleton instance
_hive_mind: Optional[HiveMind] = None


def get_hive_mind(
    agent_id: Optional[str] = None,
    backend: Optional[HiveMindBackend] = None
) -> HiveMind:
    """Get or create the global Hive Mind instance"""
    global _hive_mind
    if _hive_mind is None:
        _hive_mind = HiveMind(agent_id=agent_id, backend=backend)
    return _hive_mind


async def get_hive_mind_async(
    agent_id: Optional[str] = None,
    backend: Optional[HiveMindBackend] = None
) -> HiveMind:
    """Get or create and start the global Hive Mind instance"""
    hive = get_hive_mind(agent_id, backend)
    await hive.start()
    return hive
