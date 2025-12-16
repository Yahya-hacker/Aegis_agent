#!/usr/bin/env python3
"""
AEGIS OMEGA PROTOCOL - Semantic Auditor Module
===============================================

Implements the Semantic Policy Engine and Auditor Agent:
- Ingests documentation (User Manuals, API docs) into RAG vector store
- Extracts "intended behavior" from documentation
- Compares intended behavior vs actual behavior
- Flags business logic bugs (e.g., "One coupon per user" but agent can use two)

This addresses the "Business Logic Gap" in security testing.
"""

import asyncio
import logging
import json
import re
import os
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class PolicyRule:
    """A business policy rule extracted from documentation"""
    id: str
    category: str  # rate_limit, access_control, data_validation, workflow, etc.
    description: str
    constraints: List[str]
    source_document: str
    source_text: str
    confidence: float
    keywords: List[str] = field(default_factory=list)


@dataclass
class BehaviorObservation:
    """An observed behavior from the application"""
    id: str
    action: str
    endpoint: str
    parameters: Dict[str, Any]
    response: Dict[str, Any]
    success: bool
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BusinessLogicViolation:
    """A detected business logic violation"""
    id: str
    policy_rule: PolicyRule
    observation: BehaviorObservation
    violation_type: str
    severity: str  # critical, high, medium, low
    description: str
    evidence: str
    exploitation_steps: List[str]
    impact: str
    confidence: float


class DocumentStore:
    """
    Enhanced document store for semantic policy extraction.
    Stores and indexes documentation for policy understanding.
    """
    
    def __init__(self, storage_path: str = "data/rag_docs"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True, parents=True)
        
        self.documents: List[Dict[str, Any]] = []
        self.policies: List[PolicyRule] = []
        self.index_file = self.storage_path / "semantic_index.json"
        self._load()
        
        logger.info(f"📚 Semantic Document Store initialized with {len(self.documents)} documents")
    
    def _load(self) -> None:
        """Load stored documents and policies"""
        if self.index_file.exists():
            try:
                with open(self.index_file, 'r') as f:
                    data = json.load(f)
                    self.documents = data.get("documents", [])
                    
                    for p in data.get("policies", []):
                        self.policies.append(PolicyRule(
                            id=p["id"],
                            category=p["category"],
                            description=p["description"],
                            constraints=p["constraints"],
                            source_document=p["source_document"],
                            source_text=p["source_text"],
                            confidence=p["confidence"],
                            keywords=p.get("keywords", [])
                        ))
            except Exception as e:
                logger.warning(f"Failed to load semantic index: {e}")
    
    def _save(self) -> None:
        """Save documents and policies"""
        try:
            data = {
                "documents": self.documents,
                "policies": [
                    {
                        "id": p.id,
                        "category": p.category,
                        "description": p.description,
                        "constraints": p.constraints,
                        "source_document": p.source_document,
                        "source_text": p.source_text,
                        "confidence": p.confidence,
                        "keywords": p.keywords
                    }
                    for p in self.policies
                ]
            }
            with open(self.index_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save semantic index: {e}")
    
    def add_document(
        self,
        source: str,
        content: str,
        doc_type: str,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Add a document to the store.
        
        Args:
            source: URL or path of the document
            content: Document content
            doc_type: Type (user_manual, api_doc, policy, faq, etc.)
            metadata: Additional metadata
            
        Returns:
            Document ID
        """
        doc_id = hashlib.md5(f"{source}{content[:100]}".encode()).hexdigest()[:12]
        
        # Chunk the content
        chunks = self._chunk_content(content)
        
        for i, chunk in enumerate(chunks):
            self.documents.append({
                "id": f"{doc_id}_{i}",
                "source": source,
                "content": chunk,
                "doc_type": doc_type,
                "chunk_index": i,
                "total_chunks": len(chunks),
                "metadata": metadata or {},
                "indexed_at": datetime.now().isoformat()
            })
        
        self._save()
        logger.info(f"📄 Added document: {source} ({len(chunks)} chunks)")
        
        return doc_id
    
    def _chunk_content(self, content: str, chunk_size: int = 1000) -> List[str]:
        """Chunk content into manageable pieces"""
        # Split by paragraphs first
        paragraphs = re.split(r'\n\s*\n', content)
        
        chunks = []
        current_chunk = []
        current_size = 0
        
        for para in paragraphs:
            para_size = len(para)
            
            if current_size + para_size > chunk_size and current_chunk:
                chunks.append('\n\n'.join(current_chunk))
                current_chunk = [para]
                current_size = para_size
            else:
                current_chunk.append(para)
                current_size += para_size
        
        if current_chunk:
            chunks.append('\n\n'.join(current_chunk))
        
        return chunks
    
    def search(
        self,
        query: str,
        doc_type: Optional[str] = None,
        max_results: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Search documents by keyword matching.
        
        Args:
            query: Search query
            doc_type: Optional type filter
            max_results: Maximum results
            
        Returns:
            List of matching documents
        """
        query_terms = set(query.lower().split())
        
        scored_docs = []
        for doc in self.documents:
            if doc_type and doc.get("doc_type") != doc_type:
                continue
            
            content_lower = doc["content"].lower()
            content_terms = set(content_lower.split())
            
            # Score by keyword overlap
            score = len(query_terms & content_terms)
            
            # Boost for exact substring match
            if query.lower() in content_lower:
                score += 10
            
            if score > 0:
                scored_docs.append((score, doc))
        
        scored_docs.sort(key=lambda x: x[0], reverse=True)
        return [doc for score, doc in scored_docs[:max_results]]
    
    def get_policies_by_category(self, category: str) -> List[PolicyRule]:
        """Get policies by category"""
        return [p for p in self.policies if p.category == category]
    
    def add_policy(self, policy: PolicyRule) -> None:
        """Add a policy rule"""
        # Check for duplicates
        existing_ids = {p.id for p in self.policies}
        if policy.id not in existing_ids:
            self.policies.append(policy)
            self._save()


class SemanticPolicyExtractor:
    """
    Extracts business policies from documentation using LLM analysis.
    """
    
    # Policy categories to extract
    POLICY_CATEGORIES = [
        "rate_limit",
        "access_control",
        "data_validation",
        "workflow_constraint",
        "business_rule",
        "usage_limit",
        "authentication",
        "authorization",
        "input_constraint",
        "output_constraint"
    ]
    
    # Keywords that indicate policies
    POLICY_KEYWORDS = {
        "rate_limit": ["limit", "per minute", "per hour", "throttle", "quota"],
        "access_control": ["only", "authorized", "permission", "role", "admin"],
        "data_validation": ["must be", "required", "valid", "format", "pattern"],
        "workflow_constraint": ["before", "after", "first", "then", "once"],
        "business_rule": ["cannot", "must not", "should not", "allowed", "prohibited"],
        "usage_limit": ["maximum", "minimum", "one per", "single", "unique"],
        "authentication": ["login", "password", "authenticate", "session", "token"],
        "authorization": ["privilege", "access", "restricted", "protected"],
    }
    
    def __init__(self, ai_core=None):
        """
        Initialize the policy extractor.
        
        Args:
            ai_core: EnhancedAegisAI instance for LLM access
        """
        self.ai_core = ai_core
    
    async def extract_policies(
        self,
        document_content: str,
        source: str,
        doc_type: str
    ) -> List[PolicyRule]:
        """
        Extract business policies from document content.
        
        Args:
            document_content: The document text
            source: Document source URL/path
            doc_type: Type of document
            
        Returns:
            List of extracted PolicyRule objects
        """
        policies = []
        
        # Quick keyword-based extraction
        keyword_policies = self._extract_by_keywords(document_content, source)
        policies.extend(keyword_policies)
        
        # LLM-based deep extraction if available
        if self.ai_core and self.ai_core.is_initialized:
            llm_policies = await self._extract_with_llm(document_content, source, doc_type)
            
            # Merge, avoiding duplicates
            existing_ids = {p.id for p in policies}
            for p in llm_policies:
                if p.id not in existing_ids:
                    policies.append(p)
        
        logger.info(f"📜 Extracted {len(policies)} policies from {source}")
        return policies
    
    def _extract_by_keywords(
        self,
        content: str,
        source: str
    ) -> List[PolicyRule]:
        """Extract policies using keyword matching"""
        policies = []
        sentences = re.split(r'[.!?]', content)
        
        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence or len(sentence) < 20:
                continue
            
            sentence_lower = sentence.lower()
            
            for category, keywords in self.POLICY_KEYWORDS.items():
                for keyword in keywords:
                    if keyword in sentence_lower:
                        # Found a potential policy
                        policy_id = hashlib.md5(
                            f"{source}{sentence[:50]}".encode()
                        ).hexdigest()[:12]
                        
                        policy = PolicyRule(
                            id=policy_id,
                            category=category,
                            description=sentence,
                            constraints=self._extract_constraints(sentence),
                            source_document=source,
                            source_text=sentence,
                            confidence=0.6,
                            keywords=[keyword]
                        )
                        policies.append(policy)
                        break  # Only count once per sentence
        
        return policies
    
    def _extract_constraints(self, text: str) -> List[str]:
        """Extract specific constraints from text"""
        constraints = []
        
        # Numeric constraints
        numbers = re.findall(r'\b(\d+)\s*(per|times|max|min|limit)', text.lower())
        for num, context in numbers:
            constraints.append(f"{num} {context}")
        
        # Boolean constraints (must/must not)
        if "must not" in text.lower() or "cannot" in text.lower():
            constraints.append("PROHIBITED")
        elif "must" in text.lower() or "required" in text.lower():
            constraints.append("REQUIRED")
        
        # Access constraints
        if "only" in text.lower() and ("admin" in text.lower() or "authorized" in text.lower()):
            constraints.append("RESTRICTED_ACCESS")
        
        return constraints
    
    async def _extract_with_llm(
        self,
        content: str,
        source: str,
        doc_type: str
    ) -> List[PolicyRule]:
        """Extract policies using LLM analysis"""
        policies = []
        
        extraction_prompt = f"""Analyze this documentation and extract all BUSINESS RULES and POLICIES that govern application behavior.

DOCUMENT TYPE: {doc_type}
SOURCE: {source}

DOCUMENT CONTENT:
{content[:4000]}  # Limit to first 4000 chars

Look for rules like:
- Rate limits (e.g., "5 requests per minute")
- Access controls (e.g., "Only admins can...")
- Usage limits (e.g., "One coupon per user")
- Workflow constraints (e.g., "Must verify email before...")
- Data validation rules (e.g., "Password must contain...")
- Business rules (e.g., "Cannot cancel after shipping")

For EACH policy found, extract:
1. The exact rule/constraint
2. The category (rate_limit, access_control, usage_limit, workflow_constraint, data_validation, business_rule)
3. Specific constraints (numbers, conditions)
4. Key words that indicate this policy

Respond in JSON format:
{{
    "policies": [
        {{
            "description": "Exact description of the policy",
            "category": "category_name",
            "constraints": ["constraint1", "constraint2"],
            "keywords": ["key", "words"],
            "source_text": "Original text from document",
            "confidence": 0.0-1.0
        }}
    ]
}}

If no policies found, return {{"policies": []}}
"""
        
        try:
            response = await self.ai_core.call_reasoning_specialist(
                prompt=extraction_prompt,
                context="Business policy extraction from documentation",
                temperature=0.4
            )
            
            from agents.enhanced_ai_core import parse_json_robust
            result = await parse_json_robust(
                response.get("content", ""),
                self.ai_core.orchestrator,
                "Policy extraction"
            )
            
            if result and "policies" in result:
                for p in result["policies"]:
                    policy_id = hashlib.md5(
                        f"{source}{p.get('description', '')[:50]}".encode()
                    ).hexdigest()[:12]
                    
                    policies.append(PolicyRule(
                        id=policy_id,
                        category=p.get("category", "business_rule"),
                        description=p.get("description", ""),
                        constraints=p.get("constraints", []),
                        source_document=source,
                        source_text=p.get("source_text", ""),
                        confidence=p.get("confidence", 0.7),
                        keywords=p.get("keywords", [])
                    ))
                    
        except Exception as e:
            logger.error(f"LLM policy extraction failed: {e}")
        
        return policies


class SemanticAuditor:
    """
    The Auditor Agent - Compares intended behavior (from docs) vs actual behavior.
    
    Workflow:
    1. Read "intended behavior" from ingested documentation
    2. Observe "actual behavior" during testing
    3. Flag discrepancies as potential business logic bugs
    
    Example:
    - Docs say: "One coupon per user"
    - Agent successfully applies two coupons
    - Auditor flags: "Business Logic Bug - Coupon Reuse Possible"
    """
    
    def __init__(self, ai_core=None, document_store: Optional[DocumentStore] = None):
        """
        Initialize the Semantic Auditor.
        
        Args:
            ai_core: EnhancedAegisAI for LLM access
            document_store: Document store for policies
        """
        self.ai_core = ai_core
        self.doc_store = document_store or DocumentStore()
        self.policy_extractor = SemanticPolicyExtractor(ai_core)
        
        # Track observations
        self.observations: List[BehaviorObservation] = []
        self.violations: List[BusinessLogicViolation] = []
        
        # Statistics
        self.stats = {
            "documents_ingested": 0,
            "policies_extracted": 0,
            "observations_recorded": 0,
            "violations_detected": 0
        }
        
        logger.info("🕵️ Semantic Auditor initialized")
    
    async def ingest_documentation(
        self,
        url: str,
        doc_type: str = "api_doc"
    ) -> Dict[str, Any]:
        """
        Ingest documentation from URL and extract policies.
        
        Args:
            url: URL of the documentation
            doc_type: Type of documentation
            
        Returns:
            Ingestion result with extracted policies
        """
        logger.info(f"📥 Ingesting documentation: {url}")
        
        result = {
            "status": "success",
            "url": url,
            "policies_extracted": 0,
            "chunks_added": 0
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=30),
                    ssl=False
                ) as resp:
                    if resp.status != 200:
                        result["status"] = "error"
                        result["error"] = f"HTTP {resp.status}"
                        return result
                    
                    content = await resp.text()
                    
                    # Clean HTML if needed
                    if content.strip().startswith("<"):
                        content = self._clean_html(content)
                    
                    # Add to document store
                    doc_id = self.doc_store.add_document(
                        source=url,
                        content=content,
                        doc_type=doc_type,
                        metadata={"ingested_at": datetime.now().isoformat()}
                    )
                    
                    result["document_id"] = doc_id
                    result["chunks_added"] = len([
                        d for d in self.doc_store.documents
                        if d["id"].startswith(doc_id)
                    ])
                    
                    # Extract policies
                    policies = await self.policy_extractor.extract_policies(
                        content,
                        url,
                        doc_type
                    )
                    
                    for policy in policies:
                        self.doc_store.add_policy(policy)
                    
                    result["policies_extracted"] = len(policies)
                    result["policies"] = [
                        {
                            "category": p.category,
                            "description": p.description[:100],
                            "constraints": p.constraints
                        }
                        for p in policies[:10]  # Preview
                    ]
                    
                    self.stats["documents_ingested"] += 1
                    self.stats["policies_extracted"] += len(policies)
                    
                    logger.info(f"✅ Ingested {url}: {len(policies)} policies extracted")
                    
        except Exception as e:
            logger.error(f"Ingestion failed: {e}")
            result["status"] = "error"
            result["error"] = str(e)
        
        return result
    
    def _clean_html(self, html: str) -> str:
        """Remove HTML tags and extract text content"""
        # Remove script and style blocks
        html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
        html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)
        
        # Remove HTML tags
        html = re.sub(r'<[^>]+>', ' ', html)
        
        # Clean up whitespace
        html = re.sub(r'\s+', ' ', html)
        
        # Decode HTML entities
        import html as html_module
        html = html_module.unescape(html)
        
        return html.strip()
    
    def record_observation(
        self,
        action: str,
        endpoint: str,
        parameters: Dict[str, Any],
        response: Dict[str, Any],
        success: bool
    ) -> str:
        """
        Record an observed behavior for later auditing.
        
        Args:
            action: Action performed (e.g., "apply_coupon", "create_order")
            endpoint: API endpoint
            parameters: Request parameters
            response: Response data
            success: Whether the action succeeded
            
        Returns:
            Observation ID
        """
        obs_id = hashlib.md5(
            f"{action}{endpoint}{time.time()}".encode()
        ).hexdigest()[:12]
        
        observation = BehaviorObservation(
            id=obs_id,
            action=action,
            endpoint=endpoint,
            parameters=parameters,
            response=response,
            success=success
        )
        
        self.observations.append(observation)
        self.stats["observations_recorded"] += 1
        
        return obs_id
    
    async def audit_observation(
        self,
        observation: BehaviorObservation
    ) -> List[BusinessLogicViolation]:
        """
        Audit a single observation against known policies.
        
        Args:
            observation: The behavior observation to audit
            
        Returns:
            List of detected violations
        """
        violations = []
        
        # Find relevant policies based on action keywords
        action_keywords = set(observation.action.lower().split("_"))
        
        relevant_policies = []
        for policy in self.doc_store.policies:
            policy_keywords = set(policy.keywords)
            policy_words = set(policy.description.lower().split())
            
            # Check for keyword overlap
            if action_keywords & policy_keywords or action_keywords & policy_words:
                relevant_policies.append(policy)
        
        # Also search by action name
        search_results = self.doc_store.search(observation.action, max_results=5)
        for doc in search_results:
            # Find policies from this document
            doc_policies = [
                p for p in self.doc_store.policies
                if p.source_document == doc["source"]
            ]
            relevant_policies.extend(doc_policies)
        
        # Deduplicate
        seen_ids = set()
        unique_policies = []
        for p in relevant_policies:
            if p.id not in seen_ids:
                seen_ids.add(p.id)
                unique_policies.append(p)
        
        # Check each policy for violations
        for policy in unique_policies:
            violation = await self._check_policy_violation(observation, policy)
            if violation:
                violations.append(violation)
                self.violations.append(violation)
                self.stats["violations_detected"] += 1
        
        return violations
    
    async def _check_policy_violation(
        self,
        observation: BehaviorObservation,
        policy: PolicyRule
    ) -> Optional[BusinessLogicViolation]:
        """
        Check if an observation violates a specific policy.
        
        Args:
            observation: The behavior observation
            policy: The policy to check against
            
        Returns:
            BusinessLogicViolation if violation detected, None otherwise
        """
        # Use LLM for intelligent comparison if available
        if self.ai_core and self.ai_core.is_initialized:
            return await self._llm_violation_check(observation, policy)
        
        # Fallback to heuristic checks
        return self._heuristic_violation_check(observation, policy)
    
    def _heuristic_violation_check(
        self,
        observation: BehaviorObservation,
        policy: PolicyRule
    ) -> Optional[BusinessLogicViolation]:
        """Heuristic-based violation check"""
        
        # Check usage limit violations
        if policy.category == "usage_limit":
            # Count similar successful observations
            similar_obs = [
                o for o in self.observations
                if o.action == observation.action and o.success
            ]
            
            # Extract limit from constraints
            for constraint in policy.constraints:
                match = re.search(r'(\d+)\s*(per|limit|max)', constraint.lower())
                if match:
                    limit = int(match.group(1))
                    if len(similar_obs) > limit:
                        return BusinessLogicViolation(
                            id=f"viol_{observation.id}_{policy.id}",
                            policy_rule=policy,
                            observation=observation,
                            violation_type="usage_limit_exceeded",
                            severity="high",
                            description=f"Action '{observation.action}' performed {len(similar_obs)} times, exceeding limit of {limit}",
                            evidence=f"Observations: {[o.id for o in similar_obs[:5]]}",
                            exploitation_steps=[
                                f"Perform {observation.action} multiple times",
                                f"Bypass {limit} limit check",
                                "Exploit unlimited access"
                            ],
                            impact=f"Users can bypass {limit} limit on {observation.action}",
                            confidence=0.7
                        )
        
        # Check access control violations
        if policy.category == "access_control":
            if "RESTRICTED_ACCESS" in policy.constraints:
                # If action succeeded but should be restricted
                if observation.success:
                    # Check if it mentions admin/authorized requirement
                    if "admin" in policy.description.lower() or "authorized" in policy.description.lower():
                        return BusinessLogicViolation(
                            id=f"viol_{observation.id}_{policy.id}",
                            policy_rule=policy,
                            observation=observation,
                            violation_type="unauthorized_access",
                            severity="critical",
                            description=f"Action '{observation.action}' succeeded without proper authorization",
                            evidence=f"Response: {str(observation.response)[:200]}",
                            exploitation_steps=[
                                "Access restricted endpoint without authorization",
                                "Perform privileged action",
                                "Bypass access control"
                            ],
                            impact="Unauthorized access to restricted functionality",
                            confidence=0.6
                        )
        
        return None
    
    async def _llm_violation_check(
        self,
        observation: BehaviorObservation,
        policy: PolicyRule
    ) -> Optional[BusinessLogicViolation]:
        """LLM-based intelligent violation check"""
        
        check_prompt = f"""You are a Security Auditor comparing INTENDED BEHAVIOR (from documentation) vs ACTUAL BEHAVIOR (observed).

POLICY/RULE FROM DOCUMENTATION:
Category: {policy.category}
Description: {policy.description}
Constraints: {policy.constraints}
Source: {policy.source_document}

OBSERVED BEHAVIOR:
Action: {observation.action}
Endpoint: {observation.endpoint}
Parameters: {json.dumps(observation.parameters, indent=2)[:500]}
Response: {json.dumps(observation.response, indent=2)[:500]}
Success: {observation.success}

ANALYSIS REQUIRED:
1. Does the observed behavior VIOLATE the documented policy?
2. If yes, what type of violation is it?
3. What is the security impact?
4. How can this be exploited?

Respond in JSON:
{{
    "is_violation": true|false,
    "violation_type": "type of violation if any",
    "severity": "critical|high|medium|low",
    "description": "Clear description of the violation",
    "evidence": "Specific evidence from the observation",
    "exploitation_steps": ["step1", "step2"],
    "impact": "Business/security impact",
    "confidence": 0.0-1.0
}}

If NOT a violation, return: {{"is_violation": false, "reason": "why not"}}
"""
        
        try:
            response = await self.ai_core.call_reasoning_specialist(
                prompt=check_prompt,
                context="Business logic violation detection",
                temperature=0.3
            )
            
            from agents.enhanced_ai_core import parse_json_robust
            result = await parse_json_robust(
                response.get("content", ""),
                self.ai_core.orchestrator,
                "Violation check"
            )
            
            if result and result.get("is_violation", False):
                return BusinessLogicViolation(
                    id=f"viol_{observation.id}_{policy.id}",
                    policy_rule=policy,
                    observation=observation,
                    violation_type=result.get("violation_type", "unknown"),
                    severity=result.get("severity", "medium"),
                    description=result.get("description", ""),
                    evidence=result.get("evidence", ""),
                    exploitation_steps=result.get("exploitation_steps", []),
                    impact=result.get("impact", ""),
                    confidence=result.get("confidence", 0.7)
                )
                
        except Exception as e:
            logger.error(f"LLM violation check failed: {e}")
        
        return None
    
    async def audit_all_observations(self) -> List[BusinessLogicViolation]:
        """
        Audit all recorded observations against policies.
        
        Returns:
            List of all detected violations
        """
        logger.info(f"🔍 Auditing {len(self.observations)} observations against {len(self.doc_store.policies)} policies")
        
        all_violations = []
        
        for observation in self.observations:
            violations = await self.audit_observation(observation)
            all_violations.extend(violations)
        
        logger.info(f"🚨 Found {len(all_violations)} violations")
        
        return all_violations
    
    async def test_business_logic(
        self,
        test_cases: List[Dict[str, Any]]
    ) -> List[BusinessLogicViolation]:
        """
        Execute test cases specifically designed to find business logic bugs.
        
        Args:
            test_cases: List of test case definitions
            
        Returns:
            List of detected violations
        """
        violations = []
        
        for test_case in test_cases:
            action = test_case.get("action")
            endpoint = test_case.get("endpoint")
            repeat_count = test_case.get("repeat", 1)
            params = test_case.get("parameters", {})
            expected_failure_on = test_case.get("expect_failure_on", None)
            
            logger.info(f"🧪 Testing: {action} x{repeat_count}")
            
            # Execute the action multiple times
            for i in range(repeat_count):
                # Simulate or execute the action
                # In real implementation, this would call the scanner
                obs_id = self.record_observation(
                    action=action,
                    endpoint=endpoint,
                    parameters={**params, "iteration": i + 1},
                    response={"status": "success", "iteration": i + 1},
                    success=True
                )
                
                # Get the observation
                observation = next(o for o in self.observations if o.id == obs_id)
                
                # Audit it
                obs_violations = await self.audit_observation(observation)
                violations.extend(obs_violations)
                
                # Check if we expected a failure at this point
                if expected_failure_on and i + 1 >= expected_failure_on:
                    if observation.success:
                        # Expected failure but succeeded - potential bug
                        logger.warning(f"⚠️ Expected failure at iteration {expected_failure_on}, but action {i+1} succeeded")
        
        return violations
    
    def get_policy_summary(self) -> str:
        """Get a summary of known policies for LLM context"""
        lines = ["[BUSINESS POLICIES - INTENDED BEHAVIOR]"]
        
        by_category = {}
        for policy in self.doc_store.policies:
            if policy.category not in by_category:
                by_category[policy.category] = []
            by_category[policy.category].append(policy)
        
        for category, policies in by_category.items():
            lines.append(f"\n{category.upper()} ({len(policies)} rules):")
            for p in policies[:5]:  # Show first 5 per category
                lines.append(f"  • {p.description[:80]}...")
                if p.constraints:
                    lines.append(f"    Constraints: {p.constraints}")
        
        lines.append(f"\nTotal: {len(self.doc_store.policies)} policies from {len(set(p.source_document for p in self.doc_store.policies))} documents")
        
        return "\n".join(lines)
    
    def get_violations_report(self) -> Dict[str, Any]:
        """Get a report of all detected violations"""
        report = {
            "total_violations": len(self.violations),
            "by_severity": {},
            "by_type": {},
            "violations": []
        }
        
        for violation in self.violations:
            # Count by severity
            sev = violation.severity
            report["by_severity"][sev] = report["by_severity"].get(sev, 0) + 1
            
            # Count by type
            vtype = violation.violation_type
            report["by_type"][vtype] = report["by_type"].get(vtype, 0) + 1
            
            # Add violation details
            report["violations"].append({
                "id": violation.id,
                "type": violation.violation_type,
                "severity": violation.severity,
                "description": violation.description,
                "policy": violation.policy_rule.description[:100],
                "impact": violation.impact,
                "confidence": violation.confidence
            })
        
        return report
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get auditor statistics"""
        return {
            **self.stats,
            "active_policies": len(self.doc_store.policies),
            "stored_documents": len(self.doc_store.documents),
            "pending_observations": len([
                o for o in self.observations
                if o.id not in {v.observation.id for v in self.violations}
            ])
        }


# Import time for observation recording
import time


# Singleton instance
_semantic_auditor: Optional[SemanticAuditor] = None


def get_semantic_auditor(ai_core=None) -> SemanticAuditor:
    """Get or create the global Semantic Auditor instance"""
    global _semantic_auditor
    if _semantic_auditor is None:
        _semantic_auditor = SemanticAuditor(ai_core=ai_core)
    elif ai_core is not None and _semantic_auditor.ai_core is None:
        _semantic_auditor.ai_core = ai_core
    return _semantic_auditor
