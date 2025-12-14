#!/usr/bin/env python3
"""
KNOW-THINK-TEST-VALIDATE Loop Architecture
==========================================

Implements the structured loop for professional penetration testing:
- KNOW: Assess confirmed facts
- THINK: Formulate hypothesis with confidence score
- TEST: Execute minimal necessary action
- VALIDATE: Analyze response and update state

This architecture ensures systematic and efficient vulnerability discovery.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# Import parse_json_robust at module level for better performance
try:
    from agents.enhanced_ai_core import parse_json_robust
except ImportError:
    # Fallback if not available
    async def parse_json_robust(content, orchestrator=None, context=""):
        import json
        try:
            return json.loads(content)
        except:
            return None

logger = logging.getLogger(__name__)


class ConfidenceLevel(Enum):
    """Confidence levels for hypotheses"""
    VERY_LOW = 0.2
    LOW = 0.4
    MEDIUM = 0.6
    HIGH = 0.8
    VERY_HIGH = 0.95


@dataclass
class Fact:
    """Represents a confirmed fact about the target"""
    id: str
    description: str
    source: str  # Where this fact came from
    timestamp: datetime
    category: str  # e.g., "technology", "vulnerability", "configuration"
    confidence: float = 1.0  # Facts are confirmed, so typically 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Hypothesis:
    """Represents a hypothesis to be tested"""
    id: str
    description: str
    confidence: float  # 0.0 to 1.0
    reasoning: str  # Why we think this might be true
    based_on_facts: List[str]  # IDs of facts that support this hypothesis
    test_action: Dict[str, Any]  # The action to execute to test this
    expected_outcome: str  # What we expect if hypothesis is true
    priority: int  # Higher = more important to test
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestResult:
    """Result of testing a hypothesis"""
    hypothesis_id: str
    success: bool  # Did we get the expected outcome?
    evidence: Dict[str, Any]  # The actual data/response
    new_facts: List[Fact]  # Facts confirmed by this test
    new_hypotheses: List[Hypothesis]  # New hypotheses generated
    timestamp: datetime
    cost: Dict[str, Any] = field(default_factory=dict)  # Tokens, time, requests


@dataclass
class KTVState:
    """Current state of the KNOW-THINK-TEST-VALIDATE loop"""
    facts: Dict[str, Fact] = field(default_factory=dict)
    hypotheses: Dict[str, Hypothesis] = field(default_factory=dict)
    tested_hypotheses: Dict[str, TestResult] = field(default_factory=dict)
    current_phase: str = "KNOW"  # KNOW, THINK, TEST, VALIDATE
    iteration: int = 0
    total_cost: Dict[str, Any] = field(default_factory=lambda: {"tokens": 0, "requests": 0, "time": 0.0})


class KTVLoop:
    """
    Implements the KNOW-THINK-TEST-VALIDATE loop for systematic penetration testing.
    
    This loop ensures that:
    1. We always work from confirmed facts
    2. We generate hypotheses with explicit confidence scores
    3. We execute minimal actions to test hypotheses
    4. We validate results and update our knowledge base
    """
    
    def __init__(self, ai_core, scanner):
        """
        Initialize the KTV loop.
        
        Args:
            ai_core: Enhanced AI core for reasoning
            scanner: Scanner for executing actions
        """
        self.ai_core = ai_core
        self.scanner = scanner
        self.state = KTVState()
        self._hypothesis_counter = 0
        self._fact_counter = 0
        
    def add_fact(self, description: str, source: str, category: str, 
                 confidence: float = 1.0, metadata: Optional[Dict] = None) -> Fact:
        """
        Add a confirmed fact to the knowledge base.
        
        Args:
            description: Description of the fact
            source: Where this fact came from
            category: Category of the fact
            confidence: Confidence level (default 1.0 for confirmed facts)
            metadata: Optional additional metadata
            
        Returns:
            The created Fact object
        """
        self._fact_counter += 1
        fact = Fact(
            id=f"fact_{self._fact_counter}",
            description=description,
            source=source,
            timestamp=datetime.now(),
            category=category,
            confidence=confidence,
            metadata=metadata or {}
        )
        self.state.facts[fact.id] = fact
        logger.info(f"✅ KNOW: Added fact - {description}")
        return fact
    
    async def think(self, context: Dict[str, Any]) -> List[Hypothesis]:
        """
        THINK phase: Generate hypotheses based on known facts.
        
        Uses the AI core to analyze current facts and generate testable hypotheses
        with confidence scores.
        
        Args:
            context: Current mission context
            
        Returns:
            List of generated hypotheses
        """
        self.state.current_phase = "THINK"
        logger.info("🧠 THINK: Generating hypotheses from known facts...")
        
        # Prepare facts summary for LLM
        facts_summary = self._format_facts_for_llm()
        
        # Use AI to generate hypotheses
        prompt = f"""Based on the confirmed facts about the target, generate testable hypotheses.

CONFIRMED FACTS:
{facts_summary}

CONTEXT:
{context.get('target', 'Unknown target')}
Rules: {context.get('rules', 'Standard penetration testing')}

Your task:
1. Analyze the facts to identify potential vulnerabilities or attack vectors
2. Generate 3-5 hypotheses that can be tested with minimal actions
3. Assign a confidence score (0.0 to 1.0) to each hypothesis
4. Prioritize based on likelihood and impact

Output format:
{{
  "hypotheses": [
    {{
      "description": "The /search endpoint may be vulnerable to SQL injection",
      "confidence": 0.7,
      "reasoning": "The endpoint accepts user input and returns database errors",
      "based_on_facts": ["fact_1", "fact_3"],
      "test_action": {{"tool": "sql_injection_test", "args": {{"endpoint": "/search"}}}},
      "expected_outcome": "Database error or unexpected behavior with SQLi payload",
      "priority": 9
    }}
  ]
}}
"""
        
        try:
            response = await self.ai_core.orchestrator.route_request(
                prompt=prompt,
                task_type="reasoning",
                context={"phase": "THINK", "facts_count": len(self.state.facts)}
            )
            
            # Parse response
            result = await parse_json_robust(response, self.ai_core.orchestrator, "hypothesis generation")
            
            if not result or "hypotheses" not in result:
                logger.warning("Failed to generate hypotheses - invalid response")
                return []
            
            # Convert to Hypothesis objects
            hypotheses = []
            for h_data in result["hypotheses"]:
                self._hypothesis_counter += 1
                hypothesis = Hypothesis(
                    id=f"hyp_{self._hypothesis_counter}",
                    description=h_data["description"],
                    confidence=float(h_data["confidence"]),
                    reasoning=h_data["reasoning"],
                    based_on_facts=h_data.get("based_on_facts", []),
                    test_action=h_data["test_action"],
                    expected_outcome=h_data["expected_outcome"],
                    priority=int(h_data.get("priority", 5)),
                    timestamp=datetime.now(),
                    metadata=h_data.get("metadata", {})
                )
                hypotheses.append(hypothesis)
                self.state.hypotheses[hypothesis.id] = hypothesis
                logger.info(f"💡 THINK: Hypothesis - {hypothesis.description} (confidence: {hypothesis.confidence:.0%})")
            
            return hypotheses
            
        except Exception as e:
            logger.error(f"Error in THINK phase: {e}", exc_info=True)
            return []
    
    async def test(self, hypothesis: Hypothesis) -> TestResult:
        """
        TEST phase: Execute the minimal necessary action to validate a hypothesis.
        
        This phase is designed to conserve computational resources (tokens) by
        executing only what's needed to test the hypothesis.
        
        Args:
            hypothesis: The hypothesis to test
            
        Returns:
            TestResult containing the outcome
        """
        self.state.current_phase = "TEST"
        logger.info(f"🧪 TEST: Testing hypothesis - {hypothesis.description}")
        
        start_time = datetime.now()
        
        try:
            # Execute the test action
            result = await self.scanner.execute_action(hypothesis.test_action)
            
            # Track cost
            end_time = datetime.now()
            cost = {
                "time": (end_time - start_time).total_seconds(),
                "requests": 1
            }
            
            # Store raw result
            test_result = TestResult(
                hypothesis_id=hypothesis.id,
                success=False,  # Will be determined in VALIDATE phase
                evidence=result,
                new_facts=[],
                new_hypotheses=[],
                timestamp=end_time,
                cost=cost
            )
            
            # Update total cost
            self.state.total_cost["requests"] += 1
            self.state.total_cost["time"] += cost["time"]
            
            logger.info(f"✅ TEST: Completed in {cost['time']:.2f}s")
            
            return test_result
            
        except Exception as e:
            logger.error(f"Error in TEST phase: {e}", exc_info=True)
            return TestResult(
                hypothesis_id=hypothesis.id,
                success=False,
                evidence={"error": str(e)},
                new_facts=[],
                new_hypotheses=[],
                timestamp=datetime.now(),
                cost={"time": 0, "requests": 0}
            )
    
    async def validate(self, hypothesis: Hypothesis, test_result: TestResult) -> TestResult:
        """
        VALIDATE phase: Analyze the server response and update internal state.
        
        This phase uses the AI to determine if the hypothesis was confirmed and
        extracts new facts and hypotheses from the results.
        
        Args:
            hypothesis: The tested hypothesis
            test_result: The result from the TEST phase
            
        Returns:
            Updated TestResult with validation analysis
        """
        self.state.current_phase = "VALIDATE"
        logger.info(f"🔍 VALIDATE: Analyzing results for - {hypothesis.description}")
        
        # Prepare validation prompt
        prompt = f"""Analyze the test results and determine if the hypothesis was confirmed.

HYPOTHESIS:
{hypothesis.description}

EXPECTED OUTCOME:
{hypothesis.expected_outcome}

ACTUAL RESULT:
{str(test_result.evidence)[:2000]}

Your task:
1. Determine if the hypothesis was confirmed (true/false)
2. Extract any new confirmed facts from the results
3. Generate follow-up hypotheses if needed
4. Provide reasoning for your conclusions

Output format:
{{
  "hypothesis_confirmed": true/false,
  "confidence_update": 0.0-1.0,
  "reasoning": "Why the hypothesis was/wasn't confirmed",
  "new_facts": [
    {{"description": "...", "category": "...", "source": "test_result"}}
  ],
  "new_hypotheses": [
    {{"description": "...", "confidence": 0.0-1.0, "reasoning": "...", "test_action": {{...}}, "expected_outcome": "...", "priority": 1-10}}
  ]
}}
"""
        
        try:
            response = await self.ai_core.orchestrator.route_request(
                prompt=prompt,
                task_type="reasoning",
                context={"phase": "VALIDATE", "hypothesis_id": hypothesis.id}
            )
            
            # Parse response
            validation = await parse_json_robust(response, self.ai_core.orchestrator, "validation analysis")
            
            if not validation:
                logger.warning("Failed to validate - invalid response")
                test_result.success = False
                return test_result
            
            # Update test result
            test_result.success = validation.get("hypothesis_confirmed", False)
            
            # Add new facts
            for fact_data in validation.get("new_facts", []):
                fact = self.add_fact(
                    description=fact_data["description"],
                    source="test_result",
                    category=fact_data.get("category", "discovered"),
                    confidence=validation.get("confidence_update", 0.8),
                    metadata={"from_hypothesis": hypothesis.id}
                )
                test_result.new_facts.append(fact)
            
            # Add new hypotheses
            for hyp_data in validation.get("new_hypotheses", []):
                self._hypothesis_counter += 1
                new_hypothesis = Hypothesis(
                    id=f"hyp_{self._hypothesis_counter}",
                    description=hyp_data["description"],
                    confidence=float(hyp_data["confidence"]),
                    reasoning=hyp_data["reasoning"],
                    based_on_facts=[f.id for f in test_result.new_facts],
                    test_action=hyp_data["test_action"],
                    expected_outcome=hyp_data["expected_outcome"],
                    priority=int(hyp_data.get("priority", 5)),
                    timestamp=datetime.now(),
                    metadata={"parent_hypothesis": hypothesis.id}
                )
                test_result.new_hypotheses.append(new_hypothesis)
                self.state.hypotheses[new_hypothesis.id] = new_hypothesis
            
            # Store validated result
            self.state.tested_hypotheses[hypothesis.id] = test_result
            
            if test_result.success:
                logger.info(f"✅ VALIDATE: Hypothesis CONFIRMED - {hypothesis.description}")
            else:
                logger.info(f"❌ VALIDATE: Hypothesis REJECTED - {hypothesis.description}")
            
            logger.info(f"📊 VALIDATE: {len(test_result.new_facts)} new facts, {len(test_result.new_hypotheses)} new hypotheses")
            
            return test_result
            
        except Exception as e:
            logger.error(f"Error in VALIDATE phase: {e}", exc_info=True)
            test_result.success = False
            return test_result
    
    async def execute_loop(self, context: Dict[str, Any], max_iterations: int = 10) -> Dict[str, Any]:
        """
        Execute the complete KNOW-THINK-TEST-VALIDATE loop.
        
        Args:
            context: Mission context (target, rules, etc.)
            max_iterations: Maximum number of loop iterations
            
        Returns:
            Summary of findings
        """
        logger.info("🔄 Starting KNOW-THINK-TEST-VALIDATE loop")
        
        findings = {
            "confirmed_vulnerabilities": [],
            "total_hypotheses_tested": 0,
            "total_facts_discovered": len(self.state.facts),
            "iterations": 0
        }
        
        for iteration in range(max_iterations):
            self.state.iteration = iteration + 1
            logger.info(f"\n{'='*80}\n🔄 ITERATION {iteration + 1}/{max_iterations}\n{'='*80}")
            
            # KNOW phase - Review current facts
            logger.info(f"📚 KNOW: {len(self.state.facts)} confirmed facts")
            
            # THINK phase - Generate hypotheses
            hypotheses = await self.think(context)
            
            if not hypotheses:
                logger.info("No more hypotheses to test - loop complete")
                break
            
            # Sort hypotheses by priority
            hypotheses.sort(key=lambda h: (h.priority, h.confidence), reverse=True)
            
            # TEST and VALIDATE the top hypothesis
            top_hypothesis = hypotheses[0]
            
            # TEST phase
            test_result = await self.test(top_hypothesis)
            
            # VALIDATE phase
            validated_result = await self.validate(top_hypothesis, test_result)
            
            findings["total_hypotheses_tested"] += 1
            
            if validated_result.success:
                findings["confirmed_vulnerabilities"].append({
                    "description": top_hypothesis.description,
                    "confidence": top_hypothesis.confidence,
                    "evidence": validated_result.evidence
                })
            
            # Update iteration count
            findings["iterations"] = iteration + 1
            findings["total_facts_discovered"] = len(self.state.facts)
            
            # Check if we should continue
            if not self.state.hypotheses or iteration >= max_iterations - 1:
                break
            
            # Small delay to avoid overwhelming the system
            await asyncio.sleep(0.5)
        
        logger.info(f"\n{'='*80}\n✅ KTV Loop Complete\n{'='*80}")
        logger.info(f"📊 Results: {findings['total_hypotheses_tested']} hypotheses tested, "
                   f"{len(findings['confirmed_vulnerabilities'])} vulnerabilities confirmed")
        
        return findings
    
    def _format_facts_for_llm(self) -> str:
        """Format facts for LLM consumption"""
        if not self.state.facts:
            return "No facts confirmed yet."
        
        formatted = []
        for fact_id, fact in self.state.facts.items():
            formatted.append(f"[{fact_id}] {fact.description} (source: {fact.source}, confidence: {fact.confidence:.0%})")
        
        return "\n".join(formatted)
    
    def get_state_summary(self) -> Dict[str, Any]:
        """Get a summary of the current KTV loop state"""
        return {
            "current_phase": self.state.current_phase,
            "iteration": self.state.iteration,
            "facts_count": len(self.state.facts),
            "active_hypotheses": len([h for h in self.state.hypotheses.values() if h.id not in self.state.tested_hypotheses]),
            "tested_hypotheses": len(self.state.tested_hypotheses),
            "confirmed_hypotheses": len([r for r in self.state.tested_hypotheses.values() if r.success]),
            "total_cost": self.state.total_cost
        }
