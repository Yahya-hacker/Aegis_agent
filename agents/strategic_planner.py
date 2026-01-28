#!/usr/bin/env python3
"""
Aegis Strategic Planner
========================

Advanced strategic planning module that analyzes targets and creates
customized execution plans before launching attacks.

Key Features:
- Deep target reconnaissance and analysis
- SoM (Set-of-Mark) visual analysis integration
- Technology stack fingerprinting
- Attack surface mapping
- Strategic plan generation with Chain of Thought
- User confirmation workflow
"""

import logging
import json
import asyncio
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class StrategicPlanner:
    """
    Strategic planner that performs deep reconnaissance and creates
    customized execution plans before initiating attacks.
    """
    
    def __init__(self, ai_core, scanner):
        """
        Initialize the strategic planner.
        
        Args:
            ai_core: Enhanced AI core instance
            scanner: Scanner instance for executing reconnaissance tools
        """
        self.ai_core = ai_core
        self.scanner = scanner
        self.reconnaissance_data = {}
        self.plan = None
        
    async def analyze_target(self, target: str, rules: str) -> Dict[str, Any]:
        """
        Perform comprehensive target analysis using multiple reconnaissance methods.
        
        This is Phase 0 - Deep Reconnaissance before any exploitation attempts.
        
        Args:
            target: Target URL or domain
            rules: Mission rules and scope
            
        Returns:
            Dictionary containing reconnaissance data
        """
        logger.info(f"🔍 Starting strategic reconnaissance for {target}")
        print("\n" + "="*80)
        print(f"🔍 PHASE 0: STRATEGIC RECONNAISSANCE - {target}")
        print("="*80)
        
        reconnaissance = {
            "target": target,
            "rules": rules,
            "visual_analysis": None,
            "technology_stack": [],
            "attack_surface": {},
            "security_headers": {},
            "forms": [],
            "endpoints": [],
            "interactive_elements": 0,
            "javascript_libraries": [],
            "cookies": [],
            "error_messages": []
        }
        
        # 1. Visual Reconnaissance with SoM
        print("\n📸 Step 1: Visual Analysis with Set-of-Mark (SoM)")
        visual_result = await self._perform_visual_analysis(target)
        reconnaissance["visual_analysis"] = visual_result
        
        if visual_result.get("status") == "success":
            element_count = len(visual_result.get("element_mapping", {}))
            reconnaissance["interactive_elements"] = element_count
            print(f"   ✅ Identified {element_count} interactive elements")
        else:
            print(f"   ⚠️  Visual analysis failed: {visual_result.get('error')}")
        
        # 2. Technology Fingerprinting
        print("\n🔧 Step 2: Technology Stack Fingerprinting")
        tech_stack = await self._fingerprint_technologies(target)
        reconnaissance["technology_stack"] = tech_stack
        print(f"   ✅ Detected {len(tech_stack)} technologies")
        for tech in tech_stack[:5]:  # Show first 5
            print(f"      • {tech}")
        
        # 3. Attack Surface Mapping
        print("\n🗺️  Step 3: Attack Surface Mapping")
        attack_surface = await self._map_attack_surface(target)
        reconnaissance["attack_surface"] = attack_surface
        
        # 4. Security Headers Analysis
        print("\n🛡️  Step 4: Security Headers Analysis")
        security_headers = await self._analyze_security_headers(target)
        reconnaissance["security_headers"] = security_headers
        
        # 5. Form Discovery
        print("\n📝 Step 5: Form Discovery and Analysis")
        forms = await self._discover_forms(target)
        reconnaissance["forms"] = forms
        print(f"   ✅ Found {len(forms)} forms")
        
        # Store reconnaissance data
        self.reconnaissance_data = reconnaissance
        
        print("\n" + "="*80)
        print("✅ RECONNAISSANCE COMPLETE")
        print("="*80)
        
        return reconnaissance
    
    async def _perform_visual_analysis(self, target: str) -> Dict[str, Any]:
        """Perform visual analysis using SoM (Set-of-Mark)."""
        try:
            visual_action = {
                "tool": "capture_screenshot_som",
                "args": {
                    "url": target,
                    "full_page": True
                }
            }
            
            result = await self.scanner.execute_action(visual_action)
            return result
        except Exception as e:
            logger.error(f"Visual analysis error: {e}")
            return {"status": "error", "error": str(e)}
    
    async def _fingerprint_technologies(self, target: str) -> List[str]:
        """Fingerprint technology stack of the target."""
        try:
            # Use scanner to get headers and analyze
            tech_action = {
                "tool": "http_request",
                "args": {
                    "url": target,
                    "method": "GET"
                }
            }
            
            result = await self.scanner.execute_action(tech_action)
            
            if result.get("status") == "success":
                headers = result.get("headers", {})
                body = result.get("body", "")
                
                technologies = []
                
                # Analyze headers
                if "X-Powered-By" in headers:
                    technologies.append(f"Backend: {headers['X-Powered-By']}")
                if "Server" in headers:
                    technologies.append(f"Server: {headers['Server']}")
                
                # Analyze body for frameworks
                if "django" in body.lower():
                    technologies.append("Framework: Django")
                if "flask" in body.lower():
                    technologies.append("Framework: Flask")
                if "react" in body.lower():
                    technologies.append("Frontend: React")
                if "vue" in body.lower():
                    technologies.append("Frontend: Vue.js")
                if "angular" in body.lower():
                    technologies.append("Frontend: Angular")
                
                return technologies
            
            return []
        except Exception as e:
            logger.error(f"Technology fingerprinting error: {e}")
            return []
    
    async def _map_attack_surface(self, target: str) -> Dict[str, Any]:
        """Map the attack surface of the target."""
        attack_surface = {
            "authentication": False,
            "file_upload": False,
            "search_functionality": False,
            "api_endpoints": [],
            "dynamic_content": False,
            "user_input_points": 0
        }
        
        try:
            # This would use the application spider in a real implementation
            # For now, we'll return basic structure
            logger.info("Attack surface mapping initiated")
        except Exception as e:
            logger.error(f"Attack surface mapping error: {e}")
        
        return attack_surface
    
    async def _analyze_security_headers(self, target: str) -> Dict[str, Any]:
        """Analyze security headers."""
        try:
            action = {
                "tool": "http_request",
                "args": {
                    "url": target,
                    "method": "GET"
                }
            }
            
            result = await self.scanner.execute_action(action)
            
            if result.get("status") == "success":
                headers = result.get("headers", {})
                
                security_analysis = {
                    "csp": headers.get("Content-Security-Policy", "Not set"),
                    "xfo": headers.get("X-Frame-Options", "Not set"),
                    "hsts": headers.get("Strict-Transport-Security", "Not set"),
                    "x_content_type": headers.get("X-Content-Type-Options", "Not set"),
                    "referrer_policy": headers.get("Referrer-Policy", "Not set"),
                }
                
                return security_analysis
            
            return {}
        except Exception as e:
            logger.error(f"Security headers analysis error: {e}")
            return {}
    
    async def _discover_forms(self, target: str) -> List[Dict[str, Any]]:
        """Discover and analyze forms on the target."""
        try:
            # This would use BeautifulSoup or Playwright in a real implementation
            logger.info("Form discovery initiated")
            return []
        except Exception as e:
            logger.error(f"Form discovery error: {e}")
            return []
    
    async def generate_strategic_plan(self, target: str, rules: str, 
                                     reconnaissance: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a strategic execution plan using LLM with Chain of Thought reasoning.
        
        Args:
            target: Target URL or domain
            rules: Mission rules and scope
            reconnaissance: Reconnaissance data from analysis
            
        Returns:
            Dictionary containing the strategic plan
        """
        logger.info("📋 Generating strategic execution plan")
        print("\n" + "="*80)
        print("📋 PHASE 1: STRATEGIC PLAN GENERATION")
        print("="*80)
        
        # Prepare context for LLM
        context = self._prepare_planning_context(target, rules, reconnaissance)
        
        # Use strategic LLM for deep reasoning
        planning_prompt = f"""You are an expert penetration tester creating a strategic execution plan.

TARGET INFORMATION:
{json.dumps(reconnaissance, indent=2)}

MISSION RULES:
{rules}

YOUR TASK:
Generate a comprehensive, customized execution plan for this target. Think step-by-step using Chain of Thought reasoning.

<thinking>
1. Analyze the target's technology stack
2. Identify high-value attack vectors based on reconnaissance
3. Consider the mission rules and constraints
4. Prioritize vulnerabilities by likelihood and impact
5. Design a testing sequence that builds knowledge progressively
</thinking>

OUTPUT REQUIREMENTS:
Provide a JSON plan with the following structure:
{{
    "executive_summary": "Brief summary of target and approach",
    "risk_assessment": "Overall security posture assessment",
    "priority_vectors": [
        {{
            "name": "Vector name",
            "description": "Why this is important",
            "priority": "High/Medium/Low",
            "estimated_time": "Time estimate"
        }}
    ],
    "execution_phases": [
        {{
            "phase": 1,
            "name": "Phase name",
            "objectives": ["Objective 1", "Objective 2"],
            "tools": ["tool1", "tool2"],
            "expected_findings": ["Potential finding 1"]
        }}
    ],
    "stealth_considerations": "Approach to avoid detection",
    "fallback_strategies": "What to do if stuck"
}}

Generate the strategic plan now:"""

        try:
            # Call strategic LLM with enhanced reasoning
            response = await self.ai_core.orchestrator.call_llm(
                messages=[{"role": "user", "content": planning_prompt}],
                llm_type="strategic",  # Use strategic LLM for planning
                temperature=0.7,  # Moderate creativity
                max_tokens=4096
            )
            
            content = response.get("content", "")
            
            # Parse the plan
            from agents.enhanced_ai_core import parse_json_robust
            plan = await parse_json_robust(
                content,
                orchestrator=self.ai_core.orchestrator,
                context="Strategic execution plan"
            )
            
            if plan:
                self.plan = plan
                print("\n✅ Strategic plan generated successfully")
                self._display_plan(plan)
                return plan
            else:
                logger.error("Failed to parse strategic plan from LLM response")
                return self._generate_fallback_plan(target, rules)
                
        except Exception as e:
            logger.error(f"Plan generation error: {e}")
            return self._generate_fallback_plan(target, rules)
    
    def _prepare_planning_context(self, target: str, rules: str, 
                                  reconnaissance: Dict[str, Any]) -> str:
        """Prepare context for planning LLM."""
        context_parts = [
            f"Target: {target}",
            f"Rules: {rules}",
            f"Technologies: {', '.join(reconnaissance.get('technology_stack', []))}",
            f"Interactive Elements: {reconnaissance.get('interactive_elements', 0)}",
            f"Forms: {len(reconnaissance.get('forms', []))}",
        ]
        
        return "\n".join(context_parts)
    
    def _display_plan(self, plan: Dict[str, Any]):
        """Display the strategic plan in a readable format."""
        print("\n" + "─"*80)
        
        if "executive_summary" in plan:
            print(f"\n📊 EXECUTIVE SUMMARY:")
            print(f"   {plan['executive_summary']}")
        
        if "priority_vectors" in plan:
            print(f"\n🎯 PRIORITY ATTACK VECTORS:")
            for i, vector in enumerate(plan['priority_vectors'], 1):
                print(f"   {i}. {vector.get('name')} [{vector.get('priority', 'Unknown')}]")
                print(f"      {vector.get('description', '')}")
        
        if "execution_phases" in plan:
            print(f"\n📋 EXECUTION PHASES:")
            for phase in plan['execution_phases']:
                print(f"   Phase {phase.get('phase')}: {phase.get('name')}")
                objectives = phase.get('objectives', [])
                if objectives:
                    print(f"      Objectives: {', '.join(objectives[:3])}")
        
        if "stealth_considerations" in plan:
            print(f"\n🥷 STEALTH APPROACH:")
            print(f"   {plan['stealth_considerations']}")
        
        print("\n" + "─"*80)
    
    def _generate_fallback_plan(self, target: str, rules: str) -> Dict[str, Any]:
        """Generate a basic fallback plan if LLM generation fails."""
        return {
            "executive_summary": f"Standard reconnaissance and testing plan for {target}",
            "risk_assessment": "Unknown - will assess during testing",
            "priority_vectors": [
                {
                    "name": "Authentication Testing",
                    "description": "Test login mechanisms and access controls",
                    "priority": "High",
                    "estimated_time": "30 minutes"
                },
                {
                    "name": "Input Validation",
                    "description": "Test for XSS, SQL injection, and other injection flaws",
                    "priority": "High",
                    "estimated_time": "45 minutes"
                },
                {
                    "name": "Business Logic",
                    "description": "Test business logic flaws and authorization issues",
                    "priority": "Medium",
                    "estimated_time": "60 minutes"
                }
            ],
            "execution_phases": [
                {
                    "phase": 1,
                    "name": "Initial Reconnaissance",
                    "objectives": ["Map application structure", "Identify entry points"],
                    "tools": ["spider", "screenshot"],
                    "expected_findings": ["Application map", "Technologies"]
                },
                {
                    "phase": 2,
                    "name": "Vulnerability Discovery",
                    "objectives": ["Test common vulnerabilities", "Fuzz inputs"],
                    "tools": ["fuzzer", "nuclei"],
                    "expected_findings": ["Security issues"]
                }
            ],
            "stealth_considerations": "Use standard stealth options and respect rate limits",
            "fallback_strategies": "If stuck, analyze errors and adjust approach"
        }
    
    async def request_user_confirmation(self, plan: Dict[str, Any]) -> bool:
        """
        Present the plan to the user and request confirmation.
        
        Args:
            plan: Strategic plan to present
            
        Returns:
            True if user confirms, False otherwise
        """
        print("\n" + "="*80)
        print("⏸️  MISSION AUTHORIZATION REQUIRED")
        print("="*80)
        
        print("\nThe agent has analyzed the target and generated a strategic plan.")
        print("Please review the plan above and decide whether to proceed.")
        
        print(f"\n{Colors.WARNING}This will execute real security tests against the target.{Colors.ENDC}")
        print(f"{Colors.WARNING}Ensure you have proper authorization before proceeding.{Colors.ENDC}")
        
        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: input("\n❓ Do you approve this plan and authorize execution? (yes/no): ").strip().lower()
            )
            
            if response in ['yes', 'y', 'approve', 'confirm']:
                print(f"\n{Colors.OKGREEN}✅ Plan approved. Initiating execution...{Colors.ENDC}")
                return True
            else:
                print(f"\n{Colors.WARNING}❌ Plan rejected. Mission aborted.{Colors.ENDC}")
                return False
                
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Colors.WARNING}❌ Input cancelled. Mission aborted.{Colors.ENDC}")
            return False
    
    async def proactive_tree_of_thought(
        self,
        tech_stack: List[str],
        attack_surface: Dict[str, Any],
        objective: str = "vulnerability_discovery"
    ) -> Dict[str, Any]:
        """
        Use Tree-of-Thought reasoning BEFORE taking any action to select the best approach.
        
        This implements proactive ToT:
        1. Divergence: Propose 3 distinct attack vectors
        2. Simulation: Estimate outcomes based on tech stack
        3. Pruning: Discard costly branches (MFA, honeypots, etc.)
        4. Selection: Execute branch with highest success probability
        
        Args:
            tech_stack: Detected technologies on target
            attack_surface: Mapped attack surface
            objective: Mission objective
        
        Returns:
            Dictionary with selected attack vector and reasoning
        """
        logger.info("🌳 Running proactive Tree-of-Thought analysis")
        print("\n" + "─"*60)
        print("🌳 TREE-OF-THOUGHT: STRATEGIC DECISION")
        print("─"*60)
        
        # Define attack vector templates
        attack_vectors = [
            {
                "id": "auth_bypass",
                "name": "Authentication Bypass",
                "description": "Test login mechanisms for bypass vulnerabilities",
                "techniques": ["SQL injection in login", "JWT manipulation", "Session fixation"],
                "high_cost_indicators": ["mfa", "2fa", "two-factor", "captcha", "recaptcha"],
                "base_probability": 0.3
            },
            {
                "id": "injection",
                "name": "Injection Attacks",
                "description": "Test input validation for SQLi, XSS, Command injection",
                "techniques": ["SQL injection", "XSS", "Command injection", "SSTI"],
                "high_cost_indicators": ["waf", "cloudflare", "akamai", "f5"],
                "base_probability": 0.4
            },
            {
                "id": "ssrf_lfi",
                "name": "SSRF/LFI/Path Traversal",
                "description": "Test file access and server-side requests",
                "techniques": ["Local file inclusion", "Path traversal", "SSRF"],
                "high_cost_indicators": ["aws", "gcp", "azure", "kubernetes"],  # Cloud = valuable SSRF target
                "base_probability": 0.25
            },
            {
                "id": "business_logic",
                "name": "Business Logic Flaws",
                "description": "Test application-specific logic vulnerabilities",
                "techniques": ["IDOR", "Race conditions", "Price manipulation"],
                "high_cost_indicators": [],  # Logic flaws rarely have defenses
                "base_probability": 0.35
            }
        ]
        
        # Phase 1: Divergence - Score each vector based on context
        print("\n📊 Phase 1: DIVERGENCE (Scoring Attack Vectors)")
        
        scored_vectors = []
        for vector in attack_vectors:
            score = vector["base_probability"]
            reasoning = []
            
            # Adjust based on tech stack
            tech_lower = [t.lower() for t in tech_stack]
            
            # SQL injection more likely with certain backends
            if vector["id"] == "injection":
                if any(t in tech_lower for t in ["mysql", "postgres", "mssql", "oracle"]):
                    score += 0.15
                    reasoning.append("Database detected - injection likely")
                if any(t in tech_lower for t in ["php", "asp"]):
                    score += 0.1
                    reasoning.append("PHP/ASP detected - historically vulnerable")
            
            # Auth bypass more likely with custom auth
            if vector["id"] == "auth_bypass":
                if attack_surface.get("authentication"):
                    score += 0.1
                    reasoning.append("Authentication detected")
                if any(t in tech_lower for t in ["jwt", "oauth"]):
                    score += 0.05
                    reasoning.append("JWT/OAuth present")
            
            # SSRF valuable in cloud environments
            if vector["id"] == "ssrf_lfi":
                if any(t in tech_lower for t in ["aws", "gcp", "azure", "docker", "kubernetes"]):
                    score += 0.2  # Bonus: cloud metadata access
                    reasoning.append("Cloud environment - SSRF high value")
            
            # Check for costly defenses
            for indicator in vector["high_cost_indicators"]:
                if indicator in str(tech_stack).lower():
                    if vector["id"] != "ssrf_lfi":  # SSRF benefits from cloud
                        score -= 0.15
                        reasoning.append(f"Defense detected: {indicator}")
            
            scored_vectors.append({
                **vector,
                "adjusted_score": min(score, 0.95),  # Cap at 95%
                "reasoning": reasoning
            })
            
            print(f"  • {vector['name']}: {score:.0%}")
            for r in reasoning:
                print(f"    └─ {r}")
        
        # Phase 2: Simulation - Estimate outcomes
        print("\n🎯 Phase 2: SIMULATION (Estimating Outcomes)")
        
        for vector in scored_vectors:
            # Simulate potential outcomes
            if vector["adjusted_score"] > 0.5:
                vector["simulated_outcome"] = "HIGH probability of findings"
            elif vector["adjusted_score"] > 0.3:
                vector["simulated_outcome"] = "MEDIUM probability of findings"
            else:
                vector["simulated_outcome"] = "LOW probability - consider alternatives"
            
            print(f"  • {vector['name']}: {vector['simulated_outcome']}")
        
        # Phase 3: Pruning - Remove low-value branches
        print("\n✂️ Phase 3: PRUNING (Removing Low-Value Branches)")
        
        pruned_vectors = [v for v in scored_vectors if v["adjusted_score"] >= 0.2]
        pruned_count = len(scored_vectors) - len(pruned_vectors)
        
        if pruned_count > 0:
            print(f"  Pruned {pruned_count} low-probability vectors")
        else:
            print("  No vectors pruned - all viable")
        
        # Phase 4: Selection - Choose best branch
        print("\n🏆 Phase 4: SELECTION (Best Attack Vector)")
        
        if not pruned_vectors:
            pruned_vectors = scored_vectors  # Fallback to all if all pruned
        
        best_vector = max(pruned_vectors, key=lambda v: v["adjusted_score"])
        
        print(f"  ✅ SELECTED: {best_vector['name']}")
        print(f"     Confidence: {best_vector['adjusted_score']:.0%}")
        print(f"     Techniques: {', '.join(best_vector['techniques'][:3])}")
        
        # Sort alternatives
        alternatives = sorted(
            [v for v in pruned_vectors if v["id"] != best_vector["id"]],
            key=lambda v: v["adjusted_score"],
            reverse=True
        )[:2]  # Top 2 alternatives
        
        if alternatives:
            print(f"     Fallbacks: {', '.join(v['name'] for v in alternatives)}")
        
        print("─"*60)
        
        return {
            "selected_vector": best_vector,
            "alternatives": alternatives,
            "pruned_count": pruned_count,
            "total_evaluated": len(attack_vectors),
            "decision_reasoning": best_vector.get("reasoning", []),
            "recommended_tools": self._get_tools_for_vector(best_vector["id"])
        }
    
    def _get_tools_for_vector(self, vector_id: str) -> List[str]:
        """Get recommended tools for an attack vector"""
        tool_mapping = {
            "auth_bypass": ["nuclei", "hydra", "jwt_tool", "burp_intruder"],
            "injection": ["sqlmap", "genesis_fuzzer", "xsstrike", "commix"],
            "ssrf_lfi": ["ffuf", "genesis_fuzzer", "nuclei"],
            "business_logic": ["logic_tester", "race_engine", "burp_repeater"]
        }
        return tool_mapping.get(vector_id, ["genesis_fuzzer", "nuclei"])


# Color codes for output
class Colors:
    WARNING = '\033[93m'
    OKGREEN = '\033[92m'
    ENDC = '\033[0m'
