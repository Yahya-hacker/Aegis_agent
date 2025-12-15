#!/usr/bin/env python3
"""
AEGIS OMEGA PROTOCOL - Epistemic Priority System
=================================================

Implements confidence-based mode shifting:
- Architecture Confidence Scoring: Track knowledge certainty about target
- Mode Shift: Switch to "Epistemic Search" when confidence < 60%
- Exploitation Lock: Disable intrusive tools until confidence threshold met

This ensures systematic information gathering before exploitation attempts.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class EpistemicMode(Enum):
    """Operating modes based on epistemic state"""
    SEARCH = "epistemic_search"    # Focus on information gain
    BALANCED = "balanced"           # Mixed recon and testing
    EXPLOITATION = "exploitation"   # Full exploitation enabled


class KnowledgeCategory(Enum):
    """Categories of knowledge about the target"""
    TECHNOLOGY_STACK = "technology_stack"
    ARCHITECTURE = "architecture"
    INPUT_VECTORS = "input_vectors"
    AUTHENTICATION = "authentication"
    API_STRUCTURE = "api_structure"
    DATABASE = "database"
    SECURITY_CONTROLS = "security_controls"
    BUSINESS_LOGIC = "business_logic"


@dataclass
class KnowledgeItem:
    """A piece of knowledge with confidence level"""
    category: KnowledgeCategory
    key: str
    value: Any
    confidence: float  # 0.0 to 1.0
    source: str        # Where this knowledge came from
    timestamp: datetime = field(default_factory=datetime.now)
    verified: bool = False


@dataclass
class EpistemicState:
    """Current epistemic state of the agent"""
    mode: EpistemicMode = EpistemicMode.SEARCH
    overall_confidence: float = 0.0
    category_confidence: Dict[str, float] = field(default_factory=dict)
    knowledge_base: Dict[str, KnowledgeItem] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=datetime.now)


class EpistemicPriorityManager:
    """
    Manages epistemic priority rules for systematic testing.
    
    Core Rules:
    1. If architecture confidence < 60%, DISABLE exploitation tools
    2. In "Epistemic Search" mode, maximize Information Gain
    3. Track knowledge gaps and prioritize filling them
    
    Actions in Epistemic Search mode:
    - Analyze JS files for API endpoints
    - Read API docs and OpenAPI specs
    - Fingerprint technology stacks
    - Map authentication flows
    """
    
    # Confidence threshold for enabling exploitation
    EXPLOITATION_THRESHOLD = 0.6
    
    # Balanced mode threshold
    BALANCED_THRESHOLD = 0.4
    
    # Tools that require high confidence to use
    EXPLOITATION_TOOLS = {
        "sql_injection_test",
        "xss_test",
        "command_injection",
        "file_upload_exploit",
        "deserialization_attack",
        "ssrf_test",
        "lfi_test",
        "rfi_test",
        "xxe_test",
        "template_injection",
        "authentication_bypass",
        "brute_force_login",
        "session_hijacking",
        "csrf_test",
        "idor_test"
    }
    
    # Tools that increase knowledge (always allowed)
    EPISTEMIC_TOOLS = {
        "http_request",
        "find_forms",
        "technology_fingerprint",
        "javascript_analysis",
        "api_discovery",
        "robots_txt",
        "sitemap_parse",
        "openapi_parse",
        "directory_scan",
        "screenshot_capture",
        "dns_lookup",
        "whois_lookup",
        "ssl_analysis",
        "header_analysis",
        "cookie_analysis",
        "error_analysis"
    }
    
    # Knowledge weights for overall confidence calculation
    CATEGORY_WEIGHTS = {
        KnowledgeCategory.TECHNOLOGY_STACK: 0.20,
        KnowledgeCategory.ARCHITECTURE: 0.15,
        KnowledgeCategory.INPUT_VECTORS: 0.20,
        KnowledgeCategory.AUTHENTICATION: 0.10,
        KnowledgeCategory.API_STRUCTURE: 0.10,
        KnowledgeCategory.DATABASE: 0.10,
        KnowledgeCategory.SECURITY_CONTROLS: 0.10,
        KnowledgeCategory.BUSINESS_LOGIC: 0.05,
    }
    
    def __init__(self):
        """Initialize the Epistemic Priority Manager"""
        self.state = EpistemicState()
        self._initialize_category_confidence()
        
        logger.info("🧭 Epistemic Priority Manager initialized")
    
    def _initialize_category_confidence(self) -> None:
        """Initialize confidence tracking for all categories"""
        for category in KnowledgeCategory:
            self.state.category_confidence[category.value] = 0.0
    
    def add_knowledge(self, category: KnowledgeCategory, key: str, value: Any,
                      confidence: float, source: str, verified: bool = False) -> KnowledgeItem:
        """
        Add a piece of knowledge to the knowledge base.
        
        Args:
            category: Knowledge category
            key: Identifier for this knowledge
            value: The actual knowledge
            confidence: Confidence level (0.0-1.0)
            source: Source of this knowledge
            verified: Whether this has been verified
            
        Returns:
            The created KnowledgeItem
        """
        item = KnowledgeItem(
            category=category,
            key=key,
            value=value,
            confidence=confidence,
            source=source,
            verified=verified
        )
        
        item_id = f"{category.value}:{key}"
        self.state.knowledge_base[item_id] = item
        
        # Update category confidence
        self._update_category_confidence(category)
        
        # Update overall confidence
        self._update_overall_confidence()
        
        # Check for mode shift
        self._check_mode_shift()
        
        logger.info(f"📚 Knowledge: [{category.value}] {key} (conf: {confidence:.0%})")
        
        return item
    
    def _update_category_confidence(self, category: KnowledgeCategory) -> None:
        """Update confidence for a specific category"""
        items = [
            item for item in self.state.knowledge_base.values()
            if item.category == category
        ]
        
        if not items:
            self.state.category_confidence[category.value] = 0.0
        else:
            # Average confidence of all items in category
            avg_confidence = sum(item.confidence for item in items) / len(items)
            
            # Boost for verified items
            verified_count = sum(1 for item in items if item.verified)
            verification_boost = min(0.1, verified_count * 0.02)
            
            # Boost for multiple sources
            sources = set(item.source for item in items)
            source_boost = min(0.1, len(sources) * 0.02)
            
            final_confidence = min(1.0, avg_confidence + verification_boost + source_boost)
            self.state.category_confidence[category.value] = final_confidence
    
    def _update_overall_confidence(self) -> None:
        """Calculate overall architecture confidence"""
        weighted_sum = 0.0
        
        for category, weight in self.CATEGORY_WEIGHTS.items():
            cat_confidence = self.state.category_confidence.get(category.value, 0.0)
            weighted_sum += cat_confidence * weight
        
        self.state.overall_confidence = weighted_sum
        self.state.last_updated = datetime.now()
    
    def _check_mode_shift(self) -> None:
        """Check if mode should shift based on confidence"""
        old_mode = self.state.mode
        
        if self.state.overall_confidence >= self.EXPLOITATION_THRESHOLD:
            self.state.mode = EpistemicMode.EXPLOITATION
        elif self.state.overall_confidence >= self.BALANCED_THRESHOLD:
            self.state.mode = EpistemicMode.BALANCED
        else:
            self.state.mode = EpistemicMode.SEARCH
        
        if self.state.mode != old_mode:
            logger.info(f"🔄 MODE SHIFT: {old_mode.value} → {self.state.mode.value} "
                       f"(confidence: {self.state.overall_confidence:.0%})")
    
    def is_tool_allowed(self, tool_name: str) -> Tuple[bool, str]:
        """
        Check if a tool is allowed given current epistemic state.
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            Tuple of (allowed: bool, reason: str)
        """
        # Epistemic tools are always allowed
        if tool_name in self.EPISTEMIC_TOOLS:
            return True, "Epistemic tool - always allowed"
        
        # Exploitation tools require sufficient confidence
        if tool_name in self.EXPLOITATION_TOOLS:
            if self.state.mode == EpistemicMode.EXPLOITATION:
                return True, f"Exploitation mode enabled (conf: {self.state.overall_confidence:.0%})"
            elif self.state.mode == EpistemicMode.BALANCED:
                return True, f"Balanced mode - proceed with caution (conf: {self.state.overall_confidence:.0%})"
            else:
                return False, (
                    f"EPISTEMIC LOCK: Architecture confidence {self.state.overall_confidence:.0%} "
                    f"< {self.EXPLOITATION_THRESHOLD:.0%} threshold. "
                    f"Complete reconnaissance first."
                )
        
        # Unknown tools - allow in balanced/exploitation mode
        if self.state.mode in [EpistemicMode.BALANCED, EpistemicMode.EXPLOITATION]:
            return True, "Unknown tool allowed in current mode"
        else:
            return False, "Unknown tool blocked in Epistemic Search mode"
    
    def get_knowledge_gaps(self) -> List[Tuple[KnowledgeCategory, float]]:
        """
        Identify knowledge gaps (low confidence categories).
        
        Returns:
            List of (category, confidence) sorted by lowest confidence first
        """
        gaps = [
            (KnowledgeCategory(cat), conf)
            for cat, conf in self.state.category_confidence.items()
        ]
        
        # Sort by confidence (lowest first)
        gaps.sort(key=lambda x: x[1])
        
        return gaps
    
    def get_recommended_actions(self) -> List[Dict[str, Any]]:
        """
        Get recommended actions to increase confidence.
        
        Returns:
            List of recommended actions prioritized by information gain
        """
        recommendations = []
        gaps = self.get_knowledge_gaps()
        
        # Category-specific recommendations
        category_actions = {
            KnowledgeCategory.TECHNOLOGY_STACK: [
                {"tool": "technology_fingerprint", "reason": "Identify technology stack"},
                {"tool": "header_analysis", "reason": "Extract server/framework info from headers"},
                {"tool": "error_analysis", "reason": "Trigger errors to reveal stack info"}
            ],
            KnowledgeCategory.ARCHITECTURE: [
                {"tool": "sitemap_parse", "reason": "Map site structure from sitemap"},
                {"tool": "robots_txt", "reason": "Find hidden paths from robots.txt"},
                {"tool": "directory_scan", "reason": "Discover directory structure"}
            ],
            KnowledgeCategory.INPUT_VECTORS: [
                {"tool": "find_forms", "reason": "Discover form inputs"},
                {"tool": "api_discovery", "reason": "Find API endpoints"},
                {"tool": "javascript_analysis", "reason": "Extract endpoints from JS"}
            ],
            KnowledgeCategory.AUTHENTICATION: [
                {"tool": "cookie_analysis", "reason": "Analyze session cookies"},
                {"tool": "find_forms", "reason": "Locate login forms"},
            ],
            KnowledgeCategory.API_STRUCTURE: [
                {"tool": "openapi_parse", "reason": "Parse OpenAPI/Swagger specs"},
                {"tool": "javascript_analysis", "reason": "Extract API calls from JS"},
                {"tool": "api_discovery", "reason": "Discover API endpoints"}
            ],
            KnowledgeCategory.DATABASE: [
                {"tool": "error_analysis", "reason": "Identify database from error messages"},
                {"tool": "technology_fingerprint", "reason": "Detect database technology"}
            ],
            KnowledgeCategory.SECURITY_CONTROLS: [
                {"tool": "header_analysis", "reason": "Check security headers"},
                {"tool": "ssl_analysis", "reason": "Analyze TLS/SSL configuration"},
                {"tool": "cookie_analysis", "reason": "Check cookie security flags"}
            ],
            KnowledgeCategory.BUSINESS_LOGIC: [
                {"tool": "find_forms", "reason": "Understand business workflows"},
                {"tool": "api_discovery", "reason": "Map business logic endpoints"}
            ]
        }
        
        for category, confidence in gaps:
            if confidence < 0.8:  # Only recommend if not already confident
                actions = category_actions.get(category, [])
                for action in actions:
                    info_gain = (0.8 - confidence) * self.CATEGORY_WEIGHTS.get(category, 0.1)
                    recommendations.append({
                        "action": action,
                        "category": category.value,
                        "current_confidence": confidence,
                        "estimated_info_gain": info_gain,
                        "priority": info_gain
                    })
        
        # Sort by priority (highest information gain first)
        recommendations.sort(key=lambda x: x["priority"], reverse=True)
        
        return recommendations[:10]  # Top 10 recommendations
    
    def get_state_summary(self) -> Dict[str, Any]:
        """Get summary of current epistemic state"""
        return {
            "mode": self.state.mode.value,
            "overall_confidence": self.state.overall_confidence,
            "category_confidence": self.state.category_confidence.copy(),
            "knowledge_items": len(self.state.knowledge_base),
            "exploitation_enabled": self.state.mode == EpistemicMode.EXPLOITATION,
            "knowledge_gaps": [
                {"category": cat.value, "confidence": conf}
                for cat, conf in self.get_knowledge_gaps()[:3]
            ]
        }
    
    def format_for_llm(self) -> str:
        """Format epistemic state for LLM consumption"""
        gaps = self.get_knowledge_gaps()[:3]
        
        lines = [
            f"[EPISTEMIC STATE] Mode: {self.state.mode.value.upper()}",
            f"[CONFIDENCE] Overall: {self.state.overall_confidence:.0%} "
            f"(threshold: {self.EXPLOITATION_THRESHOLD:.0%})",
            f"[EXPLOITATION] {'ENABLED' if self.state.mode == EpistemicMode.EXPLOITATION else 'LOCKED'}",
        ]
        
        if gaps:
            gap_str = ", ".join(f"{cat.value}: {conf:.0%}" for cat, conf in gaps)
            lines.append(f"[KNOWLEDGE GAPS] {gap_str}")
        
        if self.state.mode == EpistemicMode.SEARCH:
            lines.append("[PRIORITY] HIGH - Maximize Information Gain, disable exploitation")
        
        return "\n".join(lines)
    
    def reset(self) -> None:
        """Reset epistemic state"""
        self.state = EpistemicState()
        self._initialize_category_confidence()
        logger.info("🔄 Epistemic state reset")


# Global instance
_epistemic_manager: Optional[EpistemicPriorityManager] = None


def get_epistemic_manager() -> EpistemicPriorityManager:
    """Get the global epistemic priority manager"""
    global _epistemic_manager
    if _epistemic_manager is None:
        _epistemic_manager = EpistemicPriorityManager()
    return _epistemic_manager
