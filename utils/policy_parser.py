#!/usr/bin/env python3
"""
Policy Parser and Target Prioritization
========================================

Implements natural language policy parsing and target scoring:
- Parse "out of scope" directives
- Score targets based on signals (tech stack, HTTP status, WAF presence)
- Prioritize high-value targets
- Ensure compliance with rules and policies
"""

import asyncio
import logging
import re
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class PolicyAction(Enum):
    """Actions that can be taken based on policy"""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class PolicyRule:
    """Represents a parsed policy rule"""
    id: str
    rule_type: str  # "scope", "rate_limit", "excluded_endpoint", etc.
    action: PolicyAction
    pattern: str  # The pattern to match
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TargetSignal:
    """A signal that contributes to target scoring"""
    name: str
    value: Any
    score_impact: float  # Positive = increases priority, negative = decreases
    confidence: float  # How reliable this signal is (0.0-1.0)
    description: str


@dataclass
class ScoredTarget:
    """A target with its calculated priority score"""
    url: str
    score: float
    signals: List[TargetSignal] = field(default_factory=list)
    in_scope: bool = True
    requires_approval: bool = False
    exclusion_reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class PolicyParser:
    """
    Parses natural language policies and scope directives.
    
    Examples:
    - "Do not test login.example.com"
    - "Focus on *.staging.corp.com"
    - "Avoid endpoints containing /admin/"
    - "Rate limit: max 10 requests per minute"
    """
    
    def __init__(self):
        """Initialize the policy parser"""
        self.rules: List[PolicyRule] = []
        self._rule_counter = 0
        
        # Common patterns for policy parsing
        self.scope_patterns = [
            (r"(?:do not test|avoid|exclude|out of scope).*?([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})", "exclude_domain"),
            (r"(?:focus on|only test|in scope).*?([a-zA-Z0-9\-\.\*]+\.[a-zA-Z]{2,})", "include_domain"),
            (r"(?:avoid|exclude|skip).*?endpoints?.*?containing.*?([\/\w\-]+)", "exclude_endpoint"),
            (r"(?:avoid|exclude|skip).*?(\d+\.\d+\.\d+\.\d+(?:\/\d+)?)", "exclude_ip"),
        ]
        
        self.rate_limit_patterns = [
            (r"(?:rate limit|max).*?(\d+).*?(?:requests?|reqs?).*?(?:per|/).*?(minute|second|hour)", "rate_limit"),
            (r"(?:delay|wait).*?(\d+).*?(seconds?|ms|milliseconds?)", "delay"),
        ]
        
        self.risk_patterns = [
            (r"(?:high risk|dangerous|intrusive).*?([\w\/\-]+)", "high_risk_action"),
            (r"(?:require approval|ask before).*?([\w\s]+)", "require_approval"),
        ]
    
    def parse_policy(self, policy_text: str) -> List[PolicyRule]:
        """
        Parse natural language policy text into structured rules.
        
        Args:
            policy_text: Natural language policy description
            
        Returns:
            List of parsed policy rules
        """
        logger.info("📜 Parsing policy text...")
        
        rules = []
        
        # Split into sentences
        sentences = re.split(r'[.!;\n]', policy_text)
        
        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence:
                continue
            
            # Try scope patterns
            for pattern, rule_type in self.scope_patterns:
                match = re.search(pattern, sentence, re.IGNORECASE)
                if match:
                    target = match.group(1)
                    action = PolicyAction.DENY if "exclude" in rule_type or "avoid" in sentence.lower() else PolicyAction.ALLOW
                    
                    self._rule_counter += 1
                    rule = PolicyRule(
                        id=f"rule_{self._rule_counter}",
                        rule_type=rule_type,
                        action=action,
                        pattern=target,
                        description=sentence,
                        metadata={"original_text": sentence}
                    )
                    rules.append(rule)
                    logger.info(f"  ✓ Parsed {rule_type}: {target} ({action.value})")
            
            # Try rate limit patterns
            for pattern, rule_type in self.rate_limit_patterns:
                match = re.search(pattern, sentence, re.IGNORECASE)
                if match:
                    self._rule_counter += 1
                    # Safe access to match groups
                    value = match.group(1)
                    unit = match.group(2) if match.lastindex and match.lastindex >= 2 else "requests"
                    
                    rule = PolicyRule(
                        id=f"rule_{self._rule_counter}",
                        rule_type=rule_type,
                        action=PolicyAction.ALLOW,
                        pattern=sentence,
                        description=sentence,
                        metadata={
                            "value": value,
                            "unit": unit
                        }
                    )
                    rules.append(rule)
                    logger.info(f"  ✓ Parsed {rule_type}: {value} {unit}")
            
            # Try risk patterns
            for pattern, rule_type in self.risk_patterns:
                match = re.search(pattern, sentence, re.IGNORECASE)
                if match:
                    self._rule_counter += 1
                    action = PolicyAction.REQUIRE_APPROVAL if "approval" in rule_type else PolicyAction.DENY
                    rule = PolicyRule(
                        id=f"rule_{self._rule_counter}",
                        rule_type=rule_type,
                        action=action,
                        pattern=match.group(1),
                        description=sentence,
                        metadata={"original_text": sentence}
                    )
                    rules.append(rule)
                    logger.info(f"  ✓ Parsed {rule_type}: {match.group(1)} ({action.value})")
        
        self.rules.extend(rules)
        logger.info(f"📜 Parsed {len(rules)} policy rules")
        
        return rules
    
    def is_in_scope(self, url: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a URL is in scope according to parsed policies.
        
        Args:
            url: URL to check
            
        Returns:
            Tuple of (in_scope: bool, reason: Optional[str])
        """
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        
        # Check domain rules
        for rule in self.rules:
            if rule.rule_type in ["exclude_domain", "include_domain"]:
                pattern = rule.pattern.replace("*", ".*")
                
                if re.match(pattern, domain):
                    if rule.action == PolicyAction.DENY:
                        return False, f"Domain {domain} matches exclusion rule: {rule.description}"
                    elif rule.rule_type == "include_domain" and rule.action == PolicyAction.ALLOW:
                        # Explicitly included
                        return True, f"Domain {domain} matches inclusion rule"
            
            # Check endpoint rules
            elif rule.rule_type == "exclude_endpoint":
                if rule.pattern in path:
                    return False, f"Path {path} contains excluded pattern: {rule.pattern}"
            
            # Check IP rules
            elif rule.rule_type == "exclude_ip":
                if rule.pattern in domain:
                    return False, f"IP {domain} matches exclusion rule"
        
        # Default: in scope
        return True, None
    
    def requires_approval(self, action: str) -> Tuple[bool, Optional[str]]:
        """
        Check if an action requires approval.
        
        Args:
            action: Action name or description
            
        Returns:
            Tuple of (requires_approval: bool, reason: Optional[str])
        """
        for rule in self.rules:
            if rule.rule_type in ["high_risk_action", "require_approval"]:
                if rule.pattern.lower() in action.lower():
                    return True, f"Action '{action}' matches rule: {rule.description}"
        
        return False, None
    
    def get_rate_limits(self) -> Dict[str, Any]:
        """
        Get rate limit configuration from policies.
        
        Returns:
            Dictionary with rate limit settings
        """
        limits = {
            "requests_per_minute": None,
            "delay_between_requests": None
        }
        
        for rule in self.rules:
            if rule.rule_type == "rate_limit":
                value = int(rule.metadata.get("value", 0))
                unit = rule.metadata.get("unit", "minute")
                
                if "minute" in unit:
                    limits["requests_per_minute"] = value
                elif "second" in unit:
                    limits["requests_per_minute"] = value * 60
                elif "hour" in unit:
                    limits["requests_per_minute"] = value / 60
            
            elif rule.rule_type == "delay":
                value = int(rule.metadata.get("value", 0))
                unit = rule.metadata.get("unit", "seconds")
                
                if "ms" in unit or "millisecond" in unit:
                    limits["delay_between_requests"] = value / 1000
                else:
                    limits["delay_between_requests"] = value
        
        return limits


class TargetScorer:
    """
    Scores targets based on signals to prioritize high-value targets.
    
    Signals include:
    - Technology stack (e.g., outdated versions)
    - HTTP status codes
    - Presence of WAF
    - Error messages
    - Security headers
    - Input vectors
    """
    
    def __init__(self, ai_core=None):
        """
        Initialize the target scorer.
        
        Args:
            ai_core: Optional AI core for advanced scoring
        """
        self.ai_core = ai_core
        
        # Signal weights
        self.signal_weights = {
            "outdated_technology": 3.0,
            "interesting_status_code": 2.0,
            "no_waf": 2.5,
            "waf_present": -1.5,
            "error_disclosure": 2.0,
            "missing_security_headers": 1.5,
            "input_vectors": 2.0,
            "authentication_present": 1.0,
            "api_endpoint": 1.5,
            "admin_panel": 3.0,
            "file_upload": 2.5,
            "database_interaction": 2.0
        }
    
    async def score_target(self, url: str, reconnaissance_data: Dict[str, Any]) -> ScoredTarget:
        """
        Score a target based on reconnaissance data.
        
        Args:
            url: Target URL
            reconnaissance_data: Data from reconnaissance phase
            
        Returns:
            ScoredTarget with calculated score and signals
        """
        logger.info(f"📊 Scoring target: {url}")
        
        signals = []
        
        # Analyze technology stack
        tech_signals = self._analyze_technology_stack(reconnaissance_data.get("technology_stack", []))
        signals.extend(tech_signals)
        
        # Analyze HTTP response
        http_signals = self._analyze_http_response(reconnaissance_data.get("http_response", {}))
        signals.extend(http_signals)
        
        # Analyze security headers
        header_signals = self._analyze_security_headers(reconnaissance_data.get("security_headers", {}))
        signals.extend(header_signals)
        
        # Analyze input vectors
        input_signals = self._analyze_input_vectors(reconnaissance_data.get("forms", []))
        signals.extend(input_signals)
        
        # Analyze WAF presence
        waf_signals = self._analyze_waf(reconnaissance_data)
        signals.extend(waf_signals)
        
        # Calculate total score
        total_score = 0.0
        for signal in signals:
            total_score += signal.score_impact * signal.confidence
        
        # Normalize score to 0-100 range
        normalized_score = min(100.0, max(0.0, total_score * 10))
        
        scored = ScoredTarget(
            url=url,
            score=normalized_score,
            signals=signals,
            metadata=reconnaissance_data
        )
        
        logger.info(f"📊 Target score: {normalized_score:.1f}/100 (based on {len(signals)} signals)")
        
        return scored
    
    def _analyze_technology_stack(self, tech_stack: List[str]) -> List[TargetSignal]:
        """Analyze technology stack for scoring signals"""
        signals = []
        
        # Look for potentially vulnerable technologies
        vulnerable_techs = {
            "apache": ["2.2", "2.4.1", "2.4.2"],
            "php": ["5.3", "5.4", "5.5"],
            "wordpress": ["4.", "5.0", "5.1"],
            "joomla": ["3.0", "3.1", "3.2"],
        }
        
        for tech in tech_stack:
            tech_lower = tech.lower()
            
            for tech_name, vulnerable_versions in vulnerable_techs.items():
                if tech_name in tech_lower:
                    # Check if version is disclosed
                    if any(v in tech_lower for v in vulnerable_versions):
                        signals.append(TargetSignal(
                            name="outdated_technology",
                            value=tech,
                            score_impact=self.signal_weights["outdated_technology"],
                            confidence=0.9,
                            description=f"Potentially outdated technology: {tech}"
                        ))
        
        return signals
    
    def _analyze_http_response(self, http_response: Dict[str, Any]) -> List[TargetSignal]:
        """Analyze HTTP response for scoring signals"""
        signals = []
        
        status_code = http_response.get("status_code", 0)
        
        # Interesting status codes
        interesting_codes = {
            403: "Forbidden (potential access control bypass)",
            401: "Unauthorized (authentication present)",
            500: "Internal Server Error (potential vulnerability)",
            503: "Service Unavailable (potential DoS)",
        }
        
        if status_code in interesting_codes:
            signals.append(TargetSignal(
                name="interesting_status_code",
                value=status_code,
                score_impact=self.signal_weights["interesting_status_code"],
                confidence=0.7,
                description=interesting_codes[status_code]
            ))
        
        # Check for error messages in response
        body = http_response.get("body", "").lower()
        error_keywords = ["error", "exception", "stack trace", "sql", "mysql", "postgres"]
        
        if any(keyword in body for keyword in error_keywords):
            signals.append(TargetSignal(
                name="error_disclosure",
                value="Error messages in response",
                score_impact=self.signal_weights["error_disclosure"],
                confidence=0.8,
                description="Response contains error messages"
            ))
        
        return signals
    
    def _analyze_security_headers(self, headers: Dict[str, Any]) -> List[TargetSignal]:
        """Analyze security headers"""
        signals = []
        
        # Missing security headers increase score (easier target)
        security_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options"
        ]
        
        missing_count = sum(1 for h in security_headers if h not in headers)
        
        if missing_count > 0:
            signals.append(TargetSignal(
                name="missing_security_headers",
                value=missing_count,
                score_impact=self.signal_weights["missing_security_headers"] * missing_count,
                confidence=1.0,
                description=f"{missing_count} security headers missing"
            ))
        
        return signals
    
    def _analyze_input_vectors(self, forms: List[Dict[str, Any]]) -> List[TargetSignal]:
        """Analyze input vectors (forms, parameters)"""
        signals = []
        
        if forms:
            # Count interesting input types
            file_uploads = sum(1 for form in forms 
                             for field in form.get("fields", []) 
                             if field.get("type") == "file")
            
            if file_uploads > 0:
                signals.append(TargetSignal(
                    name="file_upload",
                    value=file_uploads,
                    score_impact=self.signal_weights["file_upload"],
                    confidence=0.9,
                    description=f"{file_uploads} file upload field(s) found"
                ))
            
            # Database-related fields
            db_fields = sum(1 for form in forms 
                          for field in form.get("fields", []) 
                          if field.get("name", "").lower() in ["search", "query", "id", "user"])
            
            if db_fields > 0:
                signals.append(TargetSignal(
                    name="database_interaction",
                    value=db_fields,
                    score_impact=self.signal_weights["database_interaction"],
                    confidence=0.7,
                    description=f"{db_fields} database-related field(s) found"
                ))
        
        return signals
    
    def _analyze_waf(self, reconnaissance_data: Dict[str, Any]) -> List[TargetSignal]:
        """Analyze WAF presence"""
        signals = []
        
        headers = reconnaissance_data.get("http_response", {}).get("headers", {})
        
        # WAF indicators
        waf_headers = ["x-cdn", "x-waf", "cf-ray", "x-akamai"]
        
        waf_detected = any(h in headers for h in waf_headers)
        
        if waf_detected:
            signals.append(TargetSignal(
                name="waf_present",
                value=True,
                score_impact=self.signal_weights["waf_present"],
                confidence=0.85,
                description="WAF detected (harder target)"
            ))
        else:
            signals.append(TargetSignal(
                name="no_waf",
                value=False,
                score_impact=self.signal_weights["no_waf"],
                confidence=0.7,
                description="No WAF detected (easier target)"
            ))
        
        return signals
    
    def prioritize_targets(self, targets: List[ScoredTarget]) -> List[ScoredTarget]:
        """
        Prioritize targets by score.
        
        Args:
            targets: List of scored targets
            
        Returns:
            Sorted list (highest score first)
        """
        sorted_targets = sorted(targets, key=lambda t: t.score, reverse=True)
        
        logger.info(f"🎯 Prioritized {len(targets)} targets:")
        for i, target in enumerate(sorted_targets[:5], 1):
            logger.info(f"  {i}. {target.url} (score: {target.score:.1f})")
        
        return sorted_targets


def get_policy_parser() -> PolicyParser:
    """Get policy parser instance"""
    return PolicyParser()


def get_target_scorer(ai_core=None) -> TargetScorer:
    """Get target scorer instance"""
    return TargetScorer(ai_core)


# Example usage
async def example_policy_parsing():
    """Example of policy parsing and target scoring"""
    
    parser = get_policy_parser()
    
    policy_text = """
    Do not test login.example.com or admin.example.com.
    Focus on *.staging.corp.com.
    Avoid endpoints containing /admin/ or /delete/.
    Rate limit: max 10 requests per minute.
    Require approval before testing SQL injection.
    """
    
    rules = parser.parse_policy(policy_text)
    print(f"Parsed {len(rules)} rules")
    
    # Check scope
    in_scope, reason = parser.is_in_scope("https://api.staging.corp.com/search")
    print(f"In scope: {in_scope} - {reason}")
    
    # Check approval
    requires, reason = parser.requires_approval("SQL injection test")
    print(f"Requires approval: {requires} - {reason}")
    
    # Get rate limits
    limits = parser.get_rate_limits()
    print(f"Rate limits: {limits}")


if __name__ == "__main__":
    asyncio.run(example_policy_parsing())
