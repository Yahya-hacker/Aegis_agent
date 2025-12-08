"""
Logic Tester Tool for Aegis AI
Tests application-specific business logic flows for vulnerabilities
"""

import asyncio
import httpx
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class LogicTesterTool:
    """
    Tests business logic flows for security vulnerabilities
    
    This tool executes authenticated HTTP requests to test application logic
    for flaws like sequence bypasses, state manipulation, and business rule violations.
    """
    
    def __init__(self):
        """Initialize the logic tester tool"""
        self.timeout = 30.0
        self.max_redirects = 5
        logger.info("LogicTesterTool initialized")
    
    def _load_session_data(self) -> Optional[Dict]:
        """
        Load session data from file if it exists
        Copied from tools/tool_manager.py for authenticated requests
        
        Returns:
            Session data dictionary or None if not found
        """
        session_file = Path("data/session.json")
        if session_file.exists():
            try:
                with open(session_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load session data: {e}")
        
        return None
    
    def _build_cookie_header(self, session_data: Dict) -> str:
        """
        Build cookie header from session data
        Copied from tools/tool_manager.py for authenticated requests
        
        Args:
            session_data: Session data dictionary with cookies
            
        Returns:
            Cookie header string
        """
        if not session_data or 'cookies' not in session_data:
            return ""
        
        cookie_pairs = []
        for cookie in session_data['cookies']:
            cookie_pairs.append(f"{cookie['name']}={cookie['value']}")
        
        return "; ".join(cookie_pairs)
    
    def _build_headers(self, additional_headers: Optional[Dict] = None) -> Dict[str, str]:
        """
        Build HTTP headers including session cookies
        
        Args:
            additional_headers: Optional additional headers to include
            
        Returns:
            Dictionary of headers
        """
        headers = {
            "User-Agent": "Aegis-AI/7.0 Logic Testing Tool",
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9",
        }
        
        # Load and inject session cookies
        session_data = self._load_session_data()
        if session_data:
            cookie_header = self._build_cookie_header(session_data)
            if cookie_header:
                headers["Cookie"] = cookie_header
                logger.info("🔐 Session cookies loaded for authenticated logic testing")
        
        # Add any additional headers
        if additional_headers:
            headers.update(additional_headers)
        
        return headers
    
    async def test_logic_flow(
        self,
        flow_name: str,
        steps: List[Dict[str, Any]],
        expected_behavior: str,
        test_type: str = "sequence_bypass"
    ) -> Dict[str, Any]:
        """
        Test a business logic flow for vulnerabilities
        
        Args:
            flow_name: Name of the logic flow being tested
            steps: List of HTTP request steps to execute
                Each step should have:
                - method: HTTP method (GET, POST, etc.)
                - url: Target URL
                - data: Optional request body (for POST, PUT)
                - headers: Optional additional headers
                - description: What this step does
            expected_behavior: Description of expected secure behavior
            test_type: Type of logic test (sequence_bypass, state_manipulation, etc.)
            
        Returns:
            Dictionary with test results
        """
        logger.info(f"🧪 Testing business logic flow: {flow_name} ({test_type})")
        
        results = {
            "flow_name": flow_name,
            "test_type": test_type,
            "expected_behavior": expected_behavior,
            "steps_executed": 0,
            "steps_total": len(steps),
            "vulnerable": False,
            "findings": [],
            "step_results": []
        }
        
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                max_redirects=self.max_redirects
            ) as client:
                
                for idx, step in enumerate(steps, 1):
                    step_result = await self._execute_step(client, idx, step)
                    results["step_results"].append(step_result)
                    results["steps_executed"] = idx
                    
                    # Analyze step result for vulnerabilities
                    if step_result["status"] == "success":
                        vulnerability = self._analyze_step_for_vulnerabilities(
                            step_result, 
                            step, 
                            test_type
                        )
                        if vulnerability:
                            results["vulnerable"] = True
                            results["findings"].append(vulnerability)
            
            # Final analysis
            if results["vulnerable"]:
                logger.warning(f"⚠️ Logic vulnerability detected in {flow_name}")
            else:
                logger.info(f"✅ No logic vulnerabilities detected in {flow_name}")
            
            return results
            
        except Exception as e:
            logger.error(f"Error testing logic flow {flow_name}: {e}", exc_info=True)
            results["error"] = str(e)
            return results
    
    async def _execute_step(
        self, 
        client: httpx.AsyncClient, 
        step_num: int, 
        step: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a single step in a logic flow test
        
        Args:
            client: HTTPX async client
            step_num: Step number
            step: Step configuration
            
        Returns:
            Dictionary with step execution results
        """
        method = step.get("method", "GET").upper()
        url = step.get("url", "")
        data = step.get("data", {})
        additional_headers = step.get("headers", {})
        description = step.get("description", f"Step {step_num}")
        
        logger.info(f"  Step {step_num}: {description} - {method} {url}")
        
        step_result = {
            "step_num": step_num,
            "description": description,
            "method": method,
            "url": url,
            "status": "pending"
        }
        
        try:
            headers = self._build_headers(additional_headers)
            
            # Execute request based on method
            if method == "GET":
                response = await client.get(url, headers=headers)
            elif method == "POST":
                response = await client.post(url, json=data, headers=headers)
            elif method == "PUT":
                response = await client.put(url, json=data, headers=headers)
            elif method == "DELETE":
                response = await client.delete(url, headers=headers)
            elif method == "PATCH":
                response = await client.patch(url, json=data, headers=headers)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            step_result["status"] = "success"
            step_result["status_code"] = response.status_code
            step_result["response_time"] = response.elapsed.total_seconds()
            step_result["response_headers"] = dict(response.headers)
            
            # Try to parse response body
            try:
                step_result["response_body"] = response.json()
            except (ValueError, AttributeError):
                step_result["response_body"] = response.text[:500]  # First 500 chars
            
            logger.info(f"    ✓ Status: {response.status_code}")
            
        except Exception as e:
            logger.error(f"    ✗ Error: {e}")
            step_result["status"] = "error"
            step_result["error"] = str(e)
        
        return step_result
    
    def _analyze_step_for_vulnerabilities(
        self, 
        step_result: Dict[str, Any], 
        step_config: Dict[str, Any],
        test_type: str
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze a step result for logic vulnerabilities
        
        Args:
            step_result: Result from executing the step
            step_config: Original step configuration
            test_type: Type of logic test being performed
            
        Returns:
            Vulnerability finding dictionary or None
        """
        status_code = step_result.get("status_code", 0)
        
        # Check for unexpected success (e.g., bypassed authentication/authorization)
        if test_type == "sequence_bypass":
            # If we got a 200/201/204 when we should have been blocked
            if status_code in [200, 201, 204]:
                expected_block = step_config.get("should_be_blocked", False)
                if expected_block:
                    return {
                        "type": "sequence_bypass",
                        "severity": "high",
                        "description": f"Sequence bypass vulnerability: {step_result['description']}",
                        "evidence": f"Step succeeded with {status_code} when it should have been blocked",
                        "step_num": step_result["step_num"],
                        "url": step_result["url"]
                    }
        
        # Check for state manipulation
        elif test_type == "state_manipulation":
            if status_code in [200, 201, 204]:
                invalid_state = step_config.get("invalid_state", False)
                if invalid_state:
                    return {
                        "type": "state_manipulation",
                        "severity": "high",
                        "description": f"State manipulation vulnerability: {step_result['description']}",
                        "evidence": f"Operation succeeded in invalid state with {status_code}",
                        "step_num": step_result["step_num"],
                        "url": step_result["url"]
                    }
        
        # Check for business rule violations
        elif test_type == "business_rule_violation":
            response_body = step_result.get("response_body", {})
            rule_violated = step_config.get("violates_rule", "")
            
            if status_code in [200, 201, 204] and rule_violated:
                return {
                    "type": "business_rule_violation",
                    "severity": "medium",
                    "description": f"Business rule violation: {rule_violated}",
                    "evidence": f"Rule '{rule_violated}' was bypassed, got {status_code}",
                    "step_num": step_result["step_num"],
                    "url": step_result["url"]
                }
        
        return None
    
    async def test_sequence_bypass(
        self,
        base_url: str,
        normal_sequence: List[str],
        bypass_sequence: List[str]
    ) -> Dict[str, Any]:
        """
        Test if a multi-step process can be bypassed by skipping steps
        
        Args:
            base_url: Base URL of the application
            normal_sequence: List of endpoint paths in correct order
            bypass_sequence: List of endpoint paths attempting to skip steps
            
        Returns:
            Test results dictionary
        """
        # Build steps for bypass attempt
        steps = []
        for idx, endpoint in enumerate(bypass_sequence, 1):
            steps.append({
                "method": "GET",
                "url": f"{base_url}{endpoint}",
                "description": f"Bypass step {idx}: Access {endpoint}",
                "should_be_blocked": idx > 1  # Steps after first should be blocked
            })
        
        return await self.test_logic_flow(
            flow_name="Sequence Bypass Test",
            steps=steps,
            expected_behavior="Later steps should be blocked without completing earlier steps",
            test_type="sequence_bypass"
        )


# Singleton instance
_logic_tester_instance = None


def get_logic_tester() -> LogicTesterTool:
    """Get singleton logic tester instance"""
    global _logic_tester_instance
    if _logic_tester_instance is None:
        _logic_tester_instance = LogicTesterTool()
    return _logic_tester_instance
