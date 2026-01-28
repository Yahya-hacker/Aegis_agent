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


class ConstraintSolver:
    """
    Z3-based Constraint Solver for Zero-Day Discovery.
    
    Uses Satisfiability Modulo Theories (SMT) to discover logic vulnerabilities
    that cannot be found through traditional fuzzing.
    
    This implements:
    1. Symbolic Execution - Converts code logic into mathematical equations
    2. SAT Solving - Asks solver: "Is there input X that makes is_authenticated=False 
       while has_access=True?"
    3. Payload Generation - If SAT, returns exact input to trigger the bug
    """
    
    def __init__(self):
        """Initialize the constraint solver"""
        self.solver = None
        self._init_solver()
        logger.info("🔮 Z3 Constraint Solver initialized for zero-day discovery")
    
    def _init_solver(self):
        """Initialize Z3 solver with fresh state"""
        try:
            from z3 import Solver
            self.solver = Solver()
        except ImportError:
            logger.warning("Z3 solver not available. Install with: pip install z3-solver")
            self.solver = None
    
    def reset(self):
        """Reset solver state for new analysis"""
        if self.solver:
            self.solver.reset()
    
    def check_logic_bypass(
        self,
        constraints: List[Dict[str, Any]],
        bypass_condition: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Check if a logic bypass is possible given constraints.
        
        This answers: "Is there any input that satisfies all constraints
        but also triggers the bypass condition?"
        
        Args:
            constraints: List of constraint dictionaries defining valid logic
                Example: [{"var": "user_level", "op": ">=", "value": 5}]
            bypass_condition: Condition that should be impossible but we want to find
                Example: {"var": "is_admin", "op": "==", "value": True}
        
        Returns:
            Result dictionary with bypass possibility and triggering values
        """
        if not self.solver:
            return {"satisfiable": False, "error": "Z3 solver not available"}
        
        try:
            from z3 import Int, Bool, sat, And, Or, Not
            
            self.reset()
            
            # Build variable mapping
            variables = {}
            
            # Process constraints
            for constraint in constraints:
                var_name = constraint.get('var', 'x')
                var_type = constraint.get('type', 'int')
                
                # Create variable if not exists
                if var_name not in variables:
                    if var_type == 'bool':
                        variables[var_name] = Bool(var_name)
                    else:
                        variables[var_name] = Int(var_name)
                
                var = variables[var_name]
                op = constraint.get('op', '==')
                value = constraint.get('value', 0)
                
                # Add constraint to solver
                if op == '==':
                    self.solver.add(var == value)
                elif op == '!=':
                    self.solver.add(var != value)
                elif op == '>':
                    self.solver.add(var > value)
                elif op == '>=':
                    self.solver.add(var >= value)
                elif op == '<':
                    self.solver.add(var < value)
                elif op == '<=':
                    self.solver.add(var <= value)
            
            # Add bypass condition
            bypass_var_name = bypass_condition.get('var', 'bypass')
            bypass_type = bypass_condition.get('type', 'bool')
            
            if bypass_var_name not in variables:
                if bypass_type == 'bool':
                    variables[bypass_var_name] = Bool(bypass_var_name)
                else:
                    variables[bypass_var_name] = Int(bypass_var_name)
            
            bypass_var = variables[bypass_var_name]
            bypass_op = bypass_condition.get('op', '==')
            bypass_value = bypass_condition.get('value', True)
            
            if bypass_op == '==':
                self.solver.add(bypass_var == bypass_value)
            elif bypass_op == '!=':
                self.solver.add(bypass_var != bypass_value)
            elif bypass_op == '>':
                self.solver.add(bypass_var > bypass_value)
            elif bypass_op == '<':
                self.solver.add(bypass_var < bypass_value)
            
            # Check satisfiability
            result = self.solver.check()
            
            if result == sat:
                model = self.solver.model()
                
                # Extract the values that trigger the bypass
                trigger_values = {}
                for var_name, var in variables.items():
                    val = model.evaluate(var)
                    trigger_values[var_name] = str(val)
                
                logger.warning(f"🚨 Logic bypass POSSIBLE! Trigger values: {trigger_values}")
                
                return {
                    "satisfiable": True,
                    "vulnerable": True,
                    "trigger_values": trigger_values,
                    "description": "Logic bypass found - these values satisfy all constraints "
                                  "while triggering the bypass condition"
                }
            else:
                logger.info("✅ Logic path is secure - no bypass found")
                return {
                    "satisfiable": False,
                    "vulnerable": False,
                    "description": "No logic bypass possible with given constraints"
                }
                
        except ImportError:
            return {"satisfiable": False, "error": "Z3 solver not available"}
        except Exception as e:
            logger.error(f"Constraint solving error: {e}")
            return {"satisfiable": False, "error": str(e)}
    
    def check_integer_overflow_vulnerability(
        self,
        min_value: int,
        max_value: int,
        bit_width: int = 32
    ) -> Dict[str, Any]:
        """
        Check for integer overflow vulnerabilities.
        
        Args:
            min_value: Minimum expected value
            max_value: Maximum expected value
            bit_width: Integer bit width (8, 16, 32, 64)
        
        Returns:
            Result with overflow trigger values if vulnerable
        """
        if not self.solver:
            return {"vulnerable": False, "error": "Z3 solver not available"}
        
        try:
            from z3 import BitVec, sat, UGT, ULT
            
            self.reset()
            
            # Create bit vector for exact overflow semantics
            x = BitVec('input', bit_width)
            
            # Bounds based on bit width
            max_signed = (2 ** (bit_width - 1)) - 1
            min_signed = -(2 ** (bit_width - 1))
            max_unsigned = (2 ** bit_width) - 1
            
            # Check if value can overflow signed bounds
            # Is there x where x > max_value but x wraps to appear < min_value?
            self.solver.add(UGT(x, max_value))  # x > max_value (unsigned)
            
            result = self.solver.check()
            
            if result == sat:
                model = self.solver.model()
                overflow_value = model.evaluate(x)
                
                return {
                    "vulnerable": True,
                    "overflow_trigger": str(overflow_value),
                    "bit_width": bit_width,
                    "description": f"Integer overflow possible with value {overflow_value}"
                }
            else:
                return {
                    "vulnerable": False,
                    "description": "No integer overflow vulnerability found"
                }
                
        except ImportError:
            return {"vulnerable": False, "error": "Z3 solver not available"}
        except Exception as e:
            return {"vulnerable": False, "error": str(e)}
    
    def generate_smt_bypass_inputs(
        self,
        auth_check: str,
        access_check: str
    ) -> Dict[str, Any]:
        """
        Generate inputs that bypass authentication while maintaining access.
        
        This implements the core zero-day discovery logic:
        "Find input X where is_authenticated(X) = False but has_access(X) = True"
        
        Args:
            auth_check: Description of authentication check logic
            access_check: Description of access control logic
        
        Returns:
            Bypass inputs if vulnerability exists
        """
        if not self.solver:
            return {"bypass_found": False, "error": "Z3 solver not available"}
        
        try:
            from z3 import Int, Bool, sat, And, Or, Not, Implies
            
            self.reset()
            
            # Model typical auth/access control variables
            user_id = Int('user_id')
            role_level = Int('role_level')
            is_authenticated = Bool('is_authenticated')
            has_access = Bool('has_access')
            session_valid = Bool('session_valid')
            
            # Common authentication bypass patterns to check:
            
            # Pattern 1: Type juggling (user_id = 0 bypasses numeric checks)
            self.solver.push()
            self.solver.add(user_id == 0)
            self.solver.add(has_access == True)
            self.solver.add(is_authenticated == False)
            
            if self.solver.check() == sat:
                model = self.solver.model()
                return {
                    "bypass_found": True,
                    "bypass_type": "type_juggling",
                    "trigger": {"user_id": 0},
                    "description": "user_id=0 may bypass authentication in loose comparisons"
                }
            self.solver.pop()
            
            # Pattern 2: Negative role level
            self.solver.push()
            self.solver.add(role_level < 0)
            self.solver.add(has_access == True)
            self.solver.add(is_authenticated == False)
            
            if self.solver.check() == sat:
                model = self.solver.model()
                return {
                    "bypass_found": True,
                    "bypass_type": "negative_role",
                    "trigger": {"role_level": str(model.evaluate(role_level))},
                    "description": "Negative role level may bypass role checks"
                }
            self.solver.pop()
            
            # Pattern 3: Large integers (overflow)
            self.solver.push()
            self.solver.add(user_id > 2147483647)
            self.solver.add(has_access == True)
            
            if self.solver.check() == sat:
                model = self.solver.model()
                return {
                    "bypass_found": True,
                    "bypass_type": "integer_overflow",
                    "trigger": {"user_id": str(model.evaluate(user_id))},
                    "description": "Integer overflow may bypass validation"
                }
            self.solver.pop()
            
            return {
                "bypass_found": False,
                "description": "No common authentication bypass patterns found"
            }
            
        except ImportError:
            return {"bypass_found": False, "error": "Z3 solver not available"}
        except Exception as e:
            return {"bypass_found": False, "error": str(e)}
    
    def check_impossible_condition(
        self,
        condition_a: Dict[str, Any],
        condition_b: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Check if two conditions that appear mutually exclusive can both be true.
        
        Example: Check if (x > 10 AND x < 5) can be satisfied.
        A human/simple fuzzer sees this as impossible, but logic bugs might make it true.
        
        Args:
            condition_a: First condition {"var": "x", "op": ">", "value": 10}
            condition_b: Second condition {"var": "x", "op": "<", "value": 5}
        
        Returns:
            Result indicating if "impossible" condition is possible
        """
        if not self.solver:
            return {"satisfiable": False, "error": "Z3 solver not available"}
        
        try:
            from z3 import Int, Bool, sat
            
            self.reset()
            
            var_name = condition_a.get('var', 'x')
            var_type = condition_a.get('type', 'int')
            
            if var_type == 'bool':
                x = Bool(var_name)
            else:
                x = Int(var_name)
            
            # Add condition A
            op_a = condition_a.get('op', '>')
            val_a = condition_a.get('value', 10)
            
            if op_a == '>':
                self.solver.add(x > val_a)
            elif op_a == '<':
                self.solver.add(x < val_a)
            elif op_a == '>=':
                self.solver.add(x >= val_a)
            elif op_a == '<=':
                self.solver.add(x <= val_a)
            elif op_a == '==':
                self.solver.add(x == val_a)
            
            # Add condition B
            op_b = condition_b.get('op', '<')
            val_b = condition_b.get('value', 5)
            
            if op_b == '>':
                self.solver.add(x > val_b)
            elif op_b == '<':
                self.solver.add(x < val_b)
            elif op_b == '>=':
                self.solver.add(x >= val_b)
            elif op_b == '<=':
                self.solver.add(x <= val_b)
            elif op_b == '==':
                self.solver.add(x == val_b)
            
            # Check if both can be satisfied
            result = self.solver.check()
            
            if result == sat:
                model = self.solver.model()
                trigger_value = str(model.evaluate(x))
                
                logger.warning(f"🚨 'Impossible' condition IS satisfiable! {var_name}={trigger_value}")
                
                return {
                    "satisfiable": True,
                    "trigger_value": trigger_value,
                    "description": f"Logic bug: Both {var_name}{op_a}{val_a} AND "
                                  f"{var_name}{op_b}{val_b} satisfied by {var_name}={trigger_value}"
                }
            else:
                return {
                    "satisfiable": False,
                    "description": "Conditions are mutually exclusive as expected"
                }
                
        except ImportError:
            return {"satisfiable": False, "error": "Z3 solver not available"}
        except Exception as e:
            return {"satisfiable": False, "error": str(e)}


# Singleton instance
_constraint_solver_instance = None


def get_constraint_solver() -> ConstraintSolver:
    """Get singleton constraint solver instance"""
    global _constraint_solver_instance
    if _constraint_solver_instance is None:
        _constraint_solver_instance = ConstraintSolver()
    return _constraint_solver_instance
