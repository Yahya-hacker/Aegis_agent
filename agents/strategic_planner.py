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


# Color codes for output
class Colors:
    WARNING = '\033[93m'
    OKGREEN = '\033[92m'
    ENDC = '\033[0m'
