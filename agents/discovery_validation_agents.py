#!/usr/bin/env python3
"""
Discovery and Validation Agents
================================

Implements the separation of discovery from verification:
- Discovery Agent: Identifies potential vulnerabilities
- Validation Agent: Generates reproducible PoCs and verifies impact

This architecture prevents false positives by ensuring that findings
are only reported after successful exploitation with demonstrable impact.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class FindingSeverity(Enum):
    """Severity levels for findings"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class PotentialFinding:
    """Represents a potential vulnerability found by Discovery Agent"""
    id: str
    type: str  # e.g., "SQLi", "XSS", "IDOR", etc.
    endpoint: str
    description: str
    indicators: List[str]  # What made us think this is vulnerable
    confidence: float  # Initial confidence from discovery
    discovered_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PoC:
    """Proof of Concept for a vulnerability"""
    finding_id: str
    steps: List[Dict[str, Any]]  # Reproducible steps
    payload: str  # The actual payload used
    expected_outcome: str
    actual_outcome: str
    impact_demonstrated: bool
    impact_description: str  # What was achieved (e.g., "Extracted data", "Executed code")
    reproducible: bool
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidatedFinding:
    """A fully validated vulnerability with PoC"""
    id: str
    original_finding: PotentialFinding
    poc: PoC
    severity: FindingSeverity
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    validated_at: datetime = field(default_factory=datetime.now)


class DiscoveryAgent:
    """
    Discovery Agent: Identifies potential vulnerabilities.
    
    This agent is optimized for breadth - it quickly scans and identifies
    potential issues without deep validation. It passes findings to the
    Validation Agent for verification.
    """
    
    def __init__(self, ai_core, scanner):
        """
        Initialize the Discovery Agent.
        
        Args:
            ai_core: Enhanced AI core for reasoning
            scanner: Scanner for executing reconnaissance
        """
        self.ai_core = ai_core
        self.scanner = scanner
        self.findings = []
        self._finding_counter = 0
        
    async def scan_for_vulnerabilities(self, target: str, context: Dict[str, Any]) -> List[PotentialFinding]:
        """
        Scan target for potential vulnerabilities.
        
        This is a broad scan that identifies indicators of vulnerabilities
        without attempting exploitation.
        
        Args:
            target: Target URL or domain
            context: Scan context and parameters
            
        Returns:
            List of potential findings
        """
        logger.info(f"🔍 Discovery Agent: Scanning {target} for vulnerabilities")
        
        findings = []
        
        # 1. Technology Stack Analysis
        tech_findings = await self._analyze_technology_stack(target, context)
        findings.extend(tech_findings)
        
        # 2. Input Vector Discovery
        input_findings = await self._discover_input_vectors(target, context)
        findings.extend(input_findings)
        
        # 3. Error Message Analysis
        error_findings = await self._analyze_error_messages(target, context)
        findings.extend(error_findings)
        
        # 4. Security Header Analysis
        header_findings = await self._analyze_security_headers(target, context)
        findings.extend(header_findings)
        
        # 5. Authentication/Authorization Analysis
        auth_findings = await self._analyze_authentication(target, context)
        findings.extend(auth_findings)
        
        # Store findings
        self.findings.extend(findings)
        
        logger.info(f"🔍 Discovery Agent: Found {len(findings)} potential vulnerabilities")
        
        return findings
    
    async def _analyze_technology_stack(self, target: str, context: Dict[str, Any]) -> List[PotentialFinding]:
        """Analyze technology stack for known vulnerabilities"""
        findings = []
        
        try:
            # Get technology fingerprint
            tech_action = {
                "tool": "http_request",
                "args": {"url": target, "method": "GET"}
            }
            
            result = await self.scanner.execute_action(tech_action)
            
            if result.get("status") == "success":
                headers = result.get("headers", {})
                
                # Check for version disclosure
                server_header = headers.get("server", "")
                if server_header and any(char.isdigit() for char in server_header):
                    self._finding_counter += 1
                    findings.append(PotentialFinding(
                        id=f"finding_{self._finding_counter}",
                        type="Information Disclosure",
                        endpoint=target,
                        description=f"Server version disclosed: {server_header}",
                        indicators=["Server header contains version info"],
                        confidence=0.9,
                        discovered_at=datetime.now(),
                        metadata={"server_header": server_header}
                    ))
                
                # Check for known vulnerable headers
                x_powered_by = headers.get("x-powered-by", "")
                if x_powered_by:
                    self._finding_counter += 1
                    findings.append(PotentialFinding(
                        id=f"finding_{self._finding_counter}",
                        type="Information Disclosure",
                        endpoint=target,
                        description=f"X-Powered-By header discloses: {x_powered_by}",
                        indicators=["X-Powered-By header present"],
                        confidence=0.85,
                        discovered_at=datetime.now(),
                        metadata={"x_powered_by": x_powered_by}
                    ))
        
        except Exception as e:
            logger.error(f"Error analyzing technology stack: {e}")
        
        return findings
    
    async def _discover_input_vectors(self, target: str, context: Dict[str, Any]) -> List[PotentialFinding]:
        """Discover input vectors (forms, parameters, etc.)"""
        findings = []
        
        try:
            # Discover forms
            form_action = {
                "tool": "find_forms",
                "args": {"url": target}
            }
            
            result = await self.scanner.execute_action(form_action)
            
            if result.get("status") == "success":
                forms = result.get("forms", [])
                
                for form in forms:
                    # Check for potential SQLi
                    if any(field.get("name", "").lower() in ["search", "query", "id", "user", "username"] 
                           for field in form.get("fields", [])):
                        self._finding_counter += 1
                        findings.append(PotentialFinding(
                            id=f"finding_{self._finding_counter}",
                            type="Potential SQL Injection",
                            endpoint=form.get("action", target),
                            description=f"Form with database-related fields detected",
                            indicators=["Database-related field names", "Form accepts user input"],
                            confidence=0.6,
                            discovered_at=datetime.now(),
                            metadata={"form": form}
                        ))
                    
                    # Check for potential XSS
                    if any(field.get("type") == "text" for field in form.get("fields", [])):
                        self._finding_counter += 1
                        findings.append(PotentialFinding(
                            id=f"finding_{self._finding_counter}",
                            type="Potential XSS",
                            endpoint=form.get("action", target),
                            description=f"Form with text input fields detected",
                            indicators=["Text input fields", "Form reflects user input"],
                            confidence=0.5,
                            discovered_at=datetime.now(),
                            metadata={"form": form}
                        ))
        
        except Exception as e:
            logger.error(f"Error discovering input vectors: {e}")
        
        return findings
    
    async def _analyze_error_messages(self, target: str, context: Dict[str, Any]) -> List[PotentialFinding]:
        """Analyze error messages for information disclosure"""
        findings = []
        
        try:
            # Try invalid input to trigger errors
            error_action = {
                "tool": "http_request",
                "args": {
                    "url": f"{target}?id='",  # Simple SQLi probe
                    "method": "GET"
                }
            }
            
            result = await self.scanner.execute_action(error_action)
            
            if result.get("status") == "success":
                body = result.get("body", "").lower()
                
                # Check for database errors
                db_errors = ["sql", "mysql", "postgres", "oracle", "syntax error", "sqlite"]
                if any(err in body for err in db_errors):
                    self._finding_counter += 1
                    findings.append(PotentialFinding(
                        id=f"finding_{self._finding_counter}",
                        type="Database Error Disclosure",
                        endpoint=target,
                        description="Database error messages exposed in response",
                        indicators=["Database error keywords in response"],
                        confidence=0.85,
                        discovered_at=datetime.now(),
                        metadata={"error_snippet": body[:200]}
                    ))
        
        except Exception as e:
            logger.error(f"Error analyzing error messages: {e}")
        
        return findings
    
    async def _analyze_security_headers(self, target: str, context: Dict[str, Any]) -> List[PotentialFinding]:
        """Analyze security headers"""
        findings = []
        
        try:
            header_action = {
                "tool": "http_request",
                "args": {"url": target, "method": "GET"}
            }
            
            result = await self.scanner.execute_action(header_action)
            
            if result.get("status") == "success":
                headers = result.get("headers", {})
                
                # Check for missing security headers
                security_headers = {
                    "strict-transport-security": "HSTS",
                    "content-security-policy": "CSP",
                    "x-frame-options": "Clickjacking Protection",
                    "x-content-type-options": "MIME Sniffing Protection"
                }
                
                for header, name in security_headers.items():
                    if header not in headers:
                        self._finding_counter += 1
                        findings.append(PotentialFinding(
                            id=f"finding_{self._finding_counter}",
                            type="Missing Security Header",
                            endpoint=target,
                            description=f"Missing {name} header",
                            indicators=[f"{header} header not present"],
                            confidence=0.7,
                            discovered_at=datetime.now(),
                            metadata={"missing_header": header}
                        ))
        
        except Exception as e:
            logger.error(f"Error analyzing security headers: {e}")
        
        return findings
    
    async def _analyze_authentication(self, target: str, context: Dict[str, Any]) -> List[PotentialFinding]:
        """Analyze authentication mechanisms"""
        findings = []
        
        # This would include checks for:
        # - Weak password policies
        # - Session management issues
        # - CSRF vulnerabilities
        # - etc.
        
        # Placeholder for now
        return findings


class ValidationAgent:
    """
    Validation Agent: Generates reproducible PoCs and verifies impact.
    
    This agent receives potential findings from the Discovery Agent and
    attempts to exploit them to demonstrate real impact. Only findings
    with successful PoCs are reported as vulnerabilities.
    """
    
    def __init__(self, ai_core, scanner):
        """
        Initialize the Validation Agent.
        
        Args:
            ai_core: Enhanced AI core for generating exploits
            scanner: Scanner for executing PoC attempts
        """
        self.ai_core = ai_core
        self.scanner = scanner
        self.validated_findings = []
        
    async def validate_finding(self, finding: PotentialFinding) -> Optional[ValidatedFinding]:
        """
        Validate a potential finding by generating and executing a PoC.
        
        Args:
            finding: Potential finding from Discovery Agent
            
        Returns:
            ValidatedFinding if PoC successful, None otherwise
        """
        logger.info(f"🔬 Validation Agent: Testing {finding.type} at {finding.endpoint}")
        
        # Generate PoC
        poc = await self._generate_poc(finding)
        
        if not poc:
            logger.info(f"❌ Validation Agent: Failed to generate PoC for {finding.id}")
            return None
        
        # Execute PoC
        success = await self._execute_poc(poc)
        
        if not success or not poc.impact_demonstrated:
            logger.info(f"❌ Validation Agent: PoC failed to demonstrate impact for {finding.id}")
            return None
        
        # Calculate severity
        severity = self._calculate_severity(finding, poc)
        
        # Create validated finding
        validated = ValidatedFinding(
            id=finding.id,
            original_finding=finding,
            poc=poc,
            severity=severity,
            cvss_score=self._calculate_cvss(finding, poc),
            remediation=await self._generate_remediation(finding, poc)
        )
        
        self.validated_findings.append(validated)
        
        logger.info(f"✅ Validation Agent: Validated {finding.type} ({severity.value}) at {finding.endpoint}")
        
        return validated
    
    async def _generate_poc(self, finding: PotentialFinding) -> Optional[PoC]:
        """Generate a PoC for the finding"""
        
        prompt = f"""Generate a reproducible Proof of Concept (PoC) for the following potential vulnerability.

FINDING:
Type: {finding.type}
Endpoint: {finding.endpoint}
Description: {finding.description}
Indicators: {', '.join(finding.indicators)}

Your task:
1. Generate a step-by-step PoC that demonstrates the vulnerability
2. Include the specific payload to use
3. Describe the expected outcome (what proves the vulnerability)
4. Describe the impact that should be demonstrated (e.g., data extraction, code execution)

Requirements:
- The PoC must be reproducible
- The PoC must demonstrate actual impact, not just indicators
- The steps should be minimal but sufficient

Output format:
{{
  "steps": [
    {{"step": 1, "action": "Send GET request to endpoint", "details": "..."}},
    {{"step": 2, "action": "Inject payload", "details": "..."}}
  ],
  "payload": "The actual payload string",
  "expected_outcome": "What response indicates success",
  "impact_description": "What this proves (e.g., 'SQL injection allows data extraction')"
}}
"""
        
        try:
            response = await self.ai_core.orchestrator.route_request(
                prompt=prompt,
                task_type="code",  # Use code LLM for exploit generation
                context={"phase": "POC_GENERATION", "finding_type": finding.type}
            )
            
            from agents.enhanced_ai_core import parse_json_robust
            result = await parse_json_robust(response, self.ai_core.orchestrator, "PoC generation")
            
            if not result:
                return None
            
            poc = PoC(
                finding_id=finding.id,
                steps=result["steps"],
                payload=result["payload"],
                expected_outcome=result["expected_outcome"],
                actual_outcome="",  # Will be filled after execution
                impact_demonstrated=False,  # Will be set after execution
                impact_description=result["impact_description"],
                reproducible=True,
                timestamp=datetime.now(),
                metadata={}
            )
            
            return poc
            
        except Exception as e:
            logger.error(f"Error generating PoC: {e}", exc_info=True)
            return None
    
    async def _execute_poc(self, poc: PoC) -> bool:
        """Execute the PoC and verify impact"""
        
        try:
            logger.info(f"🧪 Executing PoC with {len(poc.steps)} steps")
            
            results = []
            
            # Execute each step
            for step in poc.steps:
                step_action = step.get("details", {})
                
                if isinstance(step_action, dict) and "tool" in step_action:
                    result = await self.scanner.execute_action(step_action)
                    results.append(result)
            
            # Analyze results to determine if impact was demonstrated
            final_result = results[-1] if results else {}
            poc.actual_outcome = str(final_result)
            
            # Use AI to determine if impact was demonstrated
            validation_prompt = f"""Analyze if the PoC successfully demonstrated impact.

EXPECTED OUTCOME:
{poc.expected_outcome}

ACTUAL OUTCOME:
{str(final_result)[:1000]}

EXPECTED IMPACT:
{poc.impact_description}

Did the PoC successfully demonstrate the vulnerability impact?
Respond with: {{"impact_demonstrated": true/false, "reasoning": "why or why not"}}
"""
            
            validation_response = await self.ai_core.orchestrator.route_request(
                prompt=validation_prompt,
                task_type="reasoning",
                context={"phase": "POC_VALIDATION"}
            )
            
            from agents.enhanced_ai_core import parse_json_robust
            validation = await parse_json_robust(validation_response, self.ai_core.orchestrator, "PoC validation")
            
            if validation and validation.get("impact_demonstrated"):
                poc.impact_demonstrated = True
                logger.info(f"✅ PoC successfully demonstrated impact: {validation.get('reasoning')}")
                return True
            else:
                logger.info(f"❌ PoC failed to demonstrate impact: {validation.get('reasoning') if validation else 'Unknown'}")
                return False
            
        except Exception as e:
            logger.error(f"Error executing PoC: {e}", exc_info=True)
            return False
    
    def _calculate_severity(self, finding: PotentialFinding, poc: PoC) -> FindingSeverity:
        """Calculate severity based on finding type and demonstrated impact"""
        
        severity_map = {
            "SQL Injection": FindingSeverity.CRITICAL,
            "Remote Code Execution": FindingSeverity.CRITICAL,
            "Authentication Bypass": FindingSeverity.CRITICAL,
            "XSS": FindingSeverity.HIGH,
            "CSRF": FindingSeverity.MEDIUM,
            "Information Disclosure": FindingSeverity.LOW,
            "Missing Security Header": FindingSeverity.INFO
        }
        
        return severity_map.get(finding.type, FindingSeverity.MEDIUM)
    
    def _calculate_cvss(self, finding: PotentialFinding, poc: PoC) -> float:
        """Calculate CVSS score (simplified)"""
        
        base_scores = {
            FindingSeverity.CRITICAL: 9.0,
            FindingSeverity.HIGH: 7.0,
            FindingSeverity.MEDIUM: 5.0,
            FindingSeverity.LOW: 3.0,
            FindingSeverity.INFO: 0.0
        }
        
        severity = self._calculate_severity(finding, poc)
        return base_scores.get(severity, 5.0)
    
    async def _generate_remediation(self, finding: PotentialFinding, poc: PoC) -> str:
        """Generate remediation advice"""
        
        prompt = f"""Generate remediation advice for the following validated vulnerability.

VULNERABILITY:
Type: {finding.type}
Description: {finding.description}
Demonstrated Impact: {poc.impact_description}

Provide clear, actionable remediation steps.
"""
        
        try:
            response = await self.ai_core.orchestrator.route_request(
                prompt=prompt,
                task_type="reasoning",
                context={"phase": "REMEDIATION"}
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Error generating remediation: {e}")
            return "Remediation advice not available"


class DiscoveryValidationOrchestrator:
    """
    Orchestrates the Discovery and Validation agents.
    
    Manages the workflow of discovering potential vulnerabilities and
    validating them with PoCs before reporting.
    """
    
    def __init__(self, ai_core, scanner):
        """
        Initialize the orchestrator.
        
        Args:
            ai_core: Enhanced AI core
            scanner: Scanner for executing actions
        """
        self.discovery_agent = DiscoveryAgent(ai_core, scanner)
        self.validation_agent = ValidationAgent(ai_core, scanner)
        
    async def scan_and_validate(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Complete scan and validation workflow.
        
        Args:
            target: Target to scan
            context: Scan context
            
        Returns:
            Dictionary with validated findings
        """
        logger.info(f"🚀 Starting Discovery/Validation workflow for {target}")
        
        # Phase 1: Discovery
        potential_findings = await self.discovery_agent.scan_for_vulnerabilities(target, context)
        
        logger.info(f"📊 Discovery complete: {len(potential_findings)} potential findings")
        
        if not potential_findings:
            return {
                "target": target,
                "potential_findings": 0,
                "validated_findings": 0,
                "vulnerabilities": []
            }
        
        # Phase 2: Validation
        validated = []
        
        for finding in potential_findings:
            # Only validate findings with sufficient confidence
            if finding.confidence >= 0.5:
                validated_finding = await self.validation_agent.validate_finding(finding)
                
                if validated_finding:
                    validated.append(validated_finding)
                
                # Small delay between validations
                await asyncio.sleep(0.5)
        
        logger.info(f"✅ Validation complete: {len(validated)}/{len(potential_findings)} findings validated")
        
        return {
            "target": target,
            "potential_findings": len(potential_findings),
            "validated_findings": len(validated),
            "vulnerabilities": [
                {
                    "type": v.original_finding.type,
                    "endpoint": v.original_finding.endpoint,
                    "severity": v.severity.value,
                    "cvss_score": v.cvss_score,
                    "poc": {
                        "payload": v.poc.payload,
                        "steps": v.poc.steps,
                        "impact": v.poc.impact_description
                    },
                    "remediation": v.remediation
                }
                for v in validated
            ]
        }
