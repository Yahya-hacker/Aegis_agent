# agents/cognitive_mechanisms.py
"""
Advanced Cognitive Architecture for Aegis v8.0
Implements three major cognitive mechanisms to maximize agent intelligence:
1. God Mode System Prompt (Structured Chain of Thought)
2. Pre-Execution Auditor (Self-Correction)
3. Tree of Thoughts for Debugging (Failure Analysis)

Everything must be in English - Professional AI security agent implementation
"""

import asyncio
import json
import re
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


# =============================================================================
# 1. GOD MODE SYSTEM PROMPT - STRUCTURED CHAIN OF THOUGHT
# =============================================================================

ADVANCED_REASONING_PROMPT = """You are an advanced AI security agent with enhanced reasoning capabilities.

BEFORE you output the final JSON response, you MUST think through the problem using the following structured approach inside <think></think> tags:

=== PHASE 1: DIVERGENCE (Generate Multiple Approaches) ===
List exactly 3 DISTINCT approaches to solve this problem:
- Approach A: [Describe first approach]
- Approach B: [Describe second approach - must be fundamentally different from A]
- Approach C: [Describe third approach - must be fundamentally different from A and B]

=== PHASE 2: CRITIQUE (Devil's Advocate) ===
Select the BEST approach from Phase 1, then act as a harsh critic:
- Best Approach: [Which approach seems most promising and why]
- Critical Attack 1: [What could go wrong with this approach]
- Critical Attack 2: [What assumptions might be wrong]
- Critical Attack 3: [What edge cases could break this]

=== PHASE 3: CONVERGENCE (Refined Final Plan) ===
Based on the critique, refine the plan:
- Refined Approach: [How to address the criticisms]
- Mitigation Strategies: [How to handle potential failures]
- Success Criteria: [How to verify the approach works]

ONLY AFTER completing all 3 phases inside <think></think> tags, output your final JSON response.

Example structure:
<think>
=== PHASE 1: DIVERGENCE ===
Approach A: Use directory bruteforcing...
Approach B: Analyze robots.txt and sitemap...
Approach C: Search for exposed .git directory...

=== PHASE 2: CRITIQUE ===
Best Approach: Approach B seems most efficient
Critical Attack 1: robots.txt might not exist
Critical Attack 2: Could be a honeypot...
Critical Attack 3: May miss hidden endpoints...

=== PHASE 3: CONVERGENCE ===
Refined Approach: Start with B, fallback to A if needed...
Mitigation Strategies: Timeout limits, error handling...
Success Criteria: Found valid endpoints or exhausted options...
</think>

{
  "tool": "selected_tool",
  "args": {...}
}
"""


# =============================================================================
# 2. PRE-EXECUTION AUDITOR - SELF-CORRECTION MECHANISM
# =============================================================================

class AuditResult(Enum):
    """Audit result types"""
    APPROVED = "approved"
    REJECTED = "rejected"
    WARNING = "warning"


@dataclass
class AuditResponse:
    """Response from action audit"""
    result: AuditResult
    reason: str
    suggestions: List[str]
    safety_score: float  # 0.0 to 1.0


class PreExecutionAuditor:
    """
    Self-correction mechanism that audits proposed actions before execution.
    Acts as a code reviewer to catch errors, dangerous commands, and logic issues.
    """
    
    # Configurable safety thresholds
    REJECTION_THRESHOLD = 0.4  # Below this score, action is rejected
    WARNING_THRESHOLD = 0.7    # Below this score, action gets warnings
    
    # Configurable circular logic detection
    DEFAULT_CIRCULAR_WINDOW = 3  # Number of recent actions to check
    DEFAULT_CIRCULAR_THRESHOLD = 2  # Number of repetitions to trigger warning
    
    # Dangerous command patterns that should trigger rejection
    # Each pattern has a description for user-friendly error messages
    DANGEROUS_PATTERNS = {
        r'rm\s+-rf\s+/(?:\s|$)': "Recursive delete of root directory",
        r'rm\s+-rf\s+/\*': "Recursive delete with root wildcard",
        r'rm\s+-rf\s+\*': "Recursive delete with wildcard",
        r'dd\s+if=.*of=/dev/sd': "Disk wiping operation",
        r'mkfs\.': "Filesystem formatting operation",
        r':(){ :|:& };:': "Fork bomb attack",
        r'chmod\s+-R\s+777': "Dangerous permission change (777)",
        r'curl.*\|\s*sh': "Piping curl output to shell",
        r'wget.*\|\s*sh': "Piping wget output to shell",
        r'eval\s*\(': "Use of eval() function",
        r'exec\s*\(': "Use of exec() function",
        r'__import__\s*\(': "Dynamic import operation",
    }
    
    # Syntax error patterns
    SYNTAX_ERROR_PATTERNS = [
        r'[\{\[](?!\s*[\}\]])[^\}\]]*$',  # Unclosed brackets
        r'^[^\{]*\}',  # Closing bracket without opening
        r',,',  # Double commas
        r':,',  # Colon followed by comma
        r',\s*[\}\]]',  # Trailing comma before closing bracket
    ]
    
    def __init__(
        self,
        llm_callable: Optional[Any] = None,
        rejection_threshold: float = 0.4,
        warning_threshold: float = 0.7,
        circular_window: int = 3,
        circular_threshold: int = 2
    ):
        """
        Initialize the auditor.
        
        Args:
            llm_callable: Optional async callable for LLM-based auditing
                         Should accept (system_prompt, user_message) and return response
            rejection_threshold: Safety score below which actions are rejected (default: 0.4)
            warning_threshold: Safety score below which warnings are issued (default: 0.7)
            circular_window: Number of recent actions to check for circular logic (default: 3)
            circular_threshold: Number of repetitions to trigger circular logic warning (default: 2)
        """
        self.llm_callable = llm_callable
        self.audit_history: List[Dict[str, Any]] = []
        
        # Configurable thresholds
        self.rejection_threshold = rejection_threshold
        self.warning_threshold = warning_threshold
        self.circular_window = circular_window
        self.circular_threshold = circular_threshold
    
    async def audit_proposed_action(
        self,
        action_payload: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, AuditResponse]:
        """
        Audit a proposed action before execution.
        
        This method performs multiple checks:
        1. Static analysis for dangerous patterns
        2. Syntax validation for code/commands
        3. Logic validation (circular dependencies, invalid sequences)
        4. Optional LLM-based deep review
        
        Args:
            action_payload: The proposed action dict with 'tool' and 'args'
            context: Optional context about previous actions and state
            
        Returns:
            Tuple of (is_approved: bool, audit_response: AuditResponse)
        """
        suggestions = []
        issues = []
        safety_score = 1.0
        
        # Extract action details
        tool = action_payload.get('tool', '')
        args = action_payload.get('args', {})
        
        # Check 1: Dangerous command patterns
        dangerous_check = await self._check_dangerous_patterns(tool, args)
        if not dangerous_check['safe']:
            issues.extend(dangerous_check['issues'])
            safety_score *= 0.3
        
        # Check 2: Syntax validation
        syntax_check = await self._check_syntax(action_payload)
        if not syntax_check['valid']:
            issues.extend(syntax_check['issues'])
            suggestions.extend(syntax_check['suggestions'])
            safety_score *= 0.5
        
        # Check 3: Logic validation (circular dependencies, repetition)
        logic_check = await self._check_logic(action_payload, context)
        if not logic_check['valid']:
            issues.extend(logic_check['issues'])
            suggestions.extend(logic_check['suggestions'])
            safety_score *= 0.7
        
        # Check 4: LLM-based deep review (if available)
        if self.llm_callable and safety_score < 0.8:
            llm_check = await self._llm_deep_review(action_payload, context, issues)
            if llm_check:
                suggestions.extend(llm_check.get('suggestions', []))
                safety_score = min(safety_score, llm_check.get('safety_score', safety_score))
        
        # Record audit
        self.audit_history.append({
            'action': action_payload,
            'safety_score': safety_score,
            'issues': issues,
            'timestamp': asyncio.get_event_loop().time()
        })
        
        # Determine result
        if safety_score < self.rejection_threshold:
            result = AuditResult.REJECTED
            is_approved = False
            reason = f"Action rejected due to safety concerns: {'; '.join(issues[:3])}"
        elif safety_score < self.warning_threshold:
            result = AuditResult.WARNING
            is_approved = True
            reason = f"Action approved with warnings: {'; '.join(issues[:2])}"
        else:
            result = AuditResult.APPROVED
            is_approved = True
            reason = "Action approved - no significant issues detected"
        
        audit_response = AuditResponse(
            result=result,
            reason=reason,
            suggestions=suggestions[:5],  # Limit to top 5 suggestions
            safety_score=safety_score
        )
        
        logger.info(f"🔍 Audit Result: {result.value} (safety: {safety_score:.2f}) - {tool}")
        if issues:
            logger.warning(f"   Issues: {'; '.join(issues[:3])}")
        if suggestions:
            logger.info(f"   Suggestions: {'; '.join(suggestions[:3])}")
        
        return is_approved, audit_response
    
    async def _check_dangerous_patterns(
        self,
        tool: str,
        args: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check for dangerous command patterns"""
        issues = []
        
        # Check all string arguments for dangerous patterns
        for key, value in args.items():
            if isinstance(value, str):
                for pattern, description in self.DANGEROUS_PATTERNS.items():
                    if re.search(pattern, value, re.IGNORECASE):
                        issues.append(f"Dangerous operation in '{key}': {description}")
        
        # Tool-specific checks
        if tool in ['execute_command', 'shell_exec', 'run_script']:
            command = args.get('command', '') or args.get('script', '')
            # Check for truly dangerous rm -rf operations (root or wildcard)
            if 'rm -rf' in command:
                # Only flag if it's targeting root, wildcard, or system directories
                if re.search(r'rm\s+-rf\s+/(?:\s|$)', command) or \
                   re.search(r'rm\s+-rf\s+/\*', command) or \
                   re.search(r'rm\s+-rf\s+\*', command):
                    issues.append("Potentially destructive rm -rf command targeting critical paths")
        
        return {
            'safe': len(issues) == 0,
            'issues': issues
        }
    
    async def _check_syntax(
        self,
        action_payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check for syntax errors in the action payload"""
        issues = []
        suggestions = []
        
        # Try to validate JSON structure
        try:
            json_str = json.dumps(action_payload)
            json.loads(json_str)  # Verify it round-trips
        except (json.JSONDecodeError, TypeError, ValueError) as e:
            issues.append(f"JSON structure error: {str(e)}")
            suggestions.append("Ensure action payload is valid JSON")
        
        # Check for common syntax patterns
        args = action_payload.get('args', {})
        for key, value in args.items():
            if isinstance(value, str):
                # Check for unclosed quotes, brackets, etc.
                for pattern in self.SYNTAX_ERROR_PATTERNS:
                    if re.search(pattern, value):
                        issues.append(f"Potential syntax error in '{key}'")
                        break
        
        # Check required fields
        if 'tool' not in action_payload:
            issues.append("Missing required field: 'tool'")
            suggestions.append("Add 'tool' field to action payload")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'suggestions': suggestions
        }
    
    async def _check_logic(
        self,
        action_payload: Dict[str, Any],
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Check for logical errors and circular dependencies"""
        issues = []
        suggestions = []
        
        if not context:
            return {'valid': True, 'issues': [], 'suggestions': []}
        
        tool = action_payload.get('tool', '')
        
        # Check for circular logic
        recent_actions = context.get('recent_actions', [])
        if len(recent_actions) >= self.circular_window:
            # Check if we're repeating the same action too many times
            recent_tools = [a.get('tool', '') for a in recent_actions[-self.circular_window:]]
            if recent_tools.count(tool) >= self.circular_threshold:
                issues.append(f"Circular logic detected: '{tool}' repeated {recent_tools.count(tool)} times")
                suggestions.append(f"Consider using a different tool or changing approach")
        
        # Check for invalid sequences
        previous_action = recent_actions[-1] if recent_actions else None
        if previous_action:
            prev_tool = previous_action.get('tool', '')
            
            # Example: Don't try to exploit before reconnaissance
            if prev_tool in ['nmap_scan', 'directory_scan'] and tool == 'exploit':
                if not context.get('vulnerabilities_found'):
                    issues.append("Attempting exploitation before finding vulnerabilities")
                    suggestions.append("Complete reconnaissance and vulnerability identification first")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'suggestions': suggestions
        }
    
    async def _llm_deep_review(
        self,
        action_payload: Dict[str, Any],
        context: Optional[Dict[str, Any]],
        existing_issues: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Perform deep review using LLM as a code reviewer"""
        if not self.llm_callable:
            return None
        
        try:
            review_prompt = f"""You are a security code reviewer. Review this proposed action for errors and safety issues.

PROPOSED ACTION:
{json.dumps(action_payload, indent=2)}

EXISTING ISSUES DETECTED:
{chr(10).join(f'- {issue}' for issue in existing_issues) if existing_issues else 'None'}

CONTEXT:
{json.dumps(context, indent=2) if context else 'No context available'}

Please analyze:
1. Syntax errors or malformed commands
2. Security risks or dangerous operations
3. Logic errors or circular dependencies
4. Better alternative approaches

Respond in JSON format:
{{
  "is_safe": true/false,
  "safety_score": 0.0-1.0,
  "issues": ["issue1", "issue2"],
  "suggestions": ["suggestion1", "suggestion2"]
}}
"""
            
            system_prompt = "You are an expert security code reviewer for penetration testing operations."
            
            response = await self.llm_callable(system_prompt, review_prompt)
            
            # Parse LLM response
            content = response.get('content', '')
            
            # Try to extract JSON from response
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group(0))
                return result
            
        except Exception as e:
            logger.warning(f"LLM deep review failed: {e}")
        
        return None


# =============================================================================
# 3. TREE OF THOUGHTS FOR DEBUGGING - FAILURE ANALYSIS
# =============================================================================

class FailureBranch(Enum):
    """Tree of Thoughts failure analysis branches"""
    SYNTAX_TOOL = "A"  # Syntax or tool configuration issue
    DEFENSE_ACTIVE = "B"  # Active defense (WAF, filters, IDS)
    FALSE_ASSUMPTION = "C"  # Wrong base assumption


@dataclass
class FailureAnalysis:
    """Result of Tree of Thoughts failure analysis"""
    most_likely_branch: FailureBranch
    branch_probabilities: Dict[FailureBranch, float]
    recommended_action: str
    reasoning: str
    alternative_actions: List[str]


class TreeOfThoughtsDebugger:
    """
    Tree of Thoughts mechanism for analyzing and recovering from failures.
    When a command fails, explores three parallel reasoning branches to diagnose the issue.
    """
    
    def __init__(self, llm_callable: Optional[Any] = None):
        """
        Initialize the ToT debugger.
        
        Args:
            llm_callable: Async callable for LLM reasoning
                         Should accept (system_prompt, user_message) and return response
        """
        self.llm_callable = llm_callable
        self.failure_history: List[Dict[str, Any]] = []
    
    async def analyze_failure_with_tot(
        self,
        previous_action: Dict[str, Any],
        error_output: str,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Analyze a failure using Tree of Thoughts methodology.
        
        Explores three parallel reasoning branches:
        - Branch A: Syntax/Tool issues (misconfigured command, wrong arguments)
        - Branch B: Active Defense (WAF, filters, rate limiting, IDS)
        - Branch C: False Assumption (wrong target, misunderstood vulnerability)
        
        Args:
            previous_action: The action that failed (dict with 'tool' and 'args')
            error_output: The error message or output from the failed action
            context: Optional context about the mission state
            
        Returns:
            Recommended corrective action as a string description
        """
        tool = previous_action.get('tool', 'unknown')
        args = previous_action.get('args', {})
        
        logger.info(f"🌳 Tree of Thoughts: Analyzing failure of '{tool}'")
        
        # Record failure
        self.failure_history.append({
            'action': previous_action,
            'error': error_output,
            'timestamp': asyncio.get_event_loop().time()
        })
        
        # If LLM is available, use it for deep analysis
        if self.llm_callable:
            analysis = await self._llm_tot_analysis(previous_action, error_output, context)
            if analysis:
                return self._format_corrective_action(analysis)
        
        # Fallback to heuristic analysis
        analysis = await self._heuristic_tot_analysis(previous_action, error_output, context)
        return self._format_corrective_action(analysis)
    
    async def _llm_tot_analysis(
        self,
        previous_action: Dict[str, Any],
        error_output: str,
        context: Optional[Dict[str, Any]]
    ) -> Optional[FailureAnalysis]:
        """Perform Tree of Thoughts analysis using LLM"""
        if not self.llm_callable:
            return None
        
        try:
            tot_prompt = f"""You are debugging a failed security testing action using Tree of Thoughts methodology.

FAILED ACTION:
Tool: {previous_action.get('tool', 'unknown')}
Arguments: {json.dumps(previous_action.get('args', {}), indent=2)}

ERROR OUTPUT:
{error_output[:1000]}

CONTEXT:
{json.dumps(context, indent=2) if context else 'No context available'}

Analyze this failure by exploring THREE parallel reasoning branches:

=== BRANCH A: SYNTAX/TOOL ISSUE ===
Could this be a syntax error, wrong tool usage, or misconfigured command?
- Evidence supporting this branch:
- Likelihood (0.0-1.0):
- If true, corrective action:

=== BRANCH B: ACTIVE DEFENSE ===
Could this be active defense mechanisms (WAF, rate limiting, filtering, IDS)?
- Evidence supporting this branch:
- Likelihood (0.0-1.0):
- If true, corrective action:

=== BRANCH C: FALSE ASSUMPTION ===
Could this be a wrong base assumption about the target or vulnerability?
- Evidence supporting this branch:
- Likelihood (0.0-1.0):
- If true, corrective action:

=== CONCLUSION ===
Based on the analysis, provide:
{{
  "most_likely_branch": "A" or "B" or "C",
  "branch_a_probability": 0.0-1.0,
  "branch_b_probability": 0.0-1.0,
  "branch_c_probability": 0.0-1.0,
  "recommended_action": "Specific corrective action to take",
  "reasoning": "Why this branch is most likely",
  "alternative_actions": ["action1", "action2"]
}}
"""
            
            system_prompt = "You are an expert debugger for penetration testing operations."
            
            response = await self.llm_callable(system_prompt, tot_prompt)
            
            # Parse response
            content = response.get('content', '')
            
            # Extract JSON conclusion
            json_match = re.search(r'\{[^{]*"most_likely_branch"[^}]*\}', content, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group(0))
                
                branch_map = {
                    'A': FailureBranch.SYNTAX_TOOL,
                    'B': FailureBranch.DEFENSE_ACTIVE,
                    'C': FailureBranch.FALSE_ASSUMPTION
                }
                
                most_likely = branch_map.get(result['most_likely_branch'], FailureBranch.SYNTAX_TOOL)
                
                return FailureAnalysis(
                    most_likely_branch=most_likely,
                    branch_probabilities={
                        FailureBranch.SYNTAX_TOOL: result.get('branch_a_probability', 0.33),
                        FailureBranch.DEFENSE_ACTIVE: result.get('branch_b_probability', 0.33),
                        FailureBranch.FALSE_ASSUMPTION: result.get('branch_c_probability', 0.34)
                    },
                    recommended_action=result.get('recommended_action', 'Try alternative approach'),
                    reasoning=result.get('reasoning', 'Based on error analysis'),
                    alternative_actions=result.get('alternative_actions', [])
                )
        
        except Exception as e:
            logger.warning(f"LLM ToT analysis failed: {e}")
        
        return None
    
    async def _heuristic_tot_analysis(
        self,
        previous_action: Dict[str, Any],
        error_output: str,
        context: Optional[Dict[str, Any]]
    ) -> FailureAnalysis:
        """Perform heuristic Tree of Thoughts analysis without LLM"""
        error_lower = error_output.lower()
        
        # Initialize probabilities
        prob_a = 0.33  # Syntax/Tool
        prob_b = 0.33  # Defense
        prob_c = 0.34  # False Assumption
        
        # Branch A: Syntax/Tool indicators
        syntax_indicators = [
            'syntax error', 'invalid argument', 'command not found',
            'usage:', 'invalid option', 'unknown flag', 'parse error',
            'unexpected token', 'invalid syntax'
        ]
        if any(ind in error_lower for ind in syntax_indicators):
            prob_a += 0.4
        
        # Branch B: Active Defense indicators
        defense_indicators = [
            'forbidden', '403', 'blocked', 'filtered', 'firewall',
            'waf', 'rate limit', 'too many requests', '429',
            'access denied', 'unauthorized', '401', 'captcha'
        ]
        if any(ind in error_lower for ind in defense_indicators):
            prob_b += 0.4
        
        # Branch C: False Assumption indicators
        assumption_indicators = [
            'not found', '404', 'no such file', 'does not exist',
            'connection refused', 'timeout', 'unreachable',
            'no route to host', 'invalid target'
        ]
        if any(ind in error_lower for ind in assumption_indicators):
            prob_c += 0.4
        
        # Normalize probabilities
        total = prob_a + prob_b + prob_c
        prob_a /= total
        prob_b /= total
        prob_c /= total
        
        # Determine most likely branch
        if prob_a >= prob_b and prob_a >= prob_c:
            most_likely = FailureBranch.SYNTAX_TOOL
            action = "Review and fix command syntax or tool configuration"
            reasoning = "Error indicates syntax or tool usage issues"
        elif prob_b >= prob_c:
            most_likely = FailureBranch.DEFENSE_ACTIVE
            action = "Bypass or adapt to active defense mechanisms"
            reasoning = "Error indicates filtering or blocking by security controls"
        else:
            most_likely = FailureBranch.FALSE_ASSUMPTION
            action = "Re-evaluate target or change approach strategy"
            reasoning = "Error indicates target/assumption mismatch"
        
        return FailureAnalysis(
            most_likely_branch=most_likely,
            branch_probabilities={
                FailureBranch.SYNTAX_TOOL: prob_a,
                FailureBranch.DEFENSE_ACTIVE: prob_b,
                FailureBranch.FALSE_ASSUMPTION: prob_c
            },
            recommended_action=action,
            reasoning=reasoning,
            alternative_actions=self._generate_alternative_actions(most_likely, previous_action)
        )
    
    def _generate_alternative_actions(
        self,
        branch: FailureBranch,
        previous_action: Dict[str, Any]
    ) -> List[str]:
        """Generate alternative actions based on the identified branch"""
        tool = previous_action.get('tool', '')
        
        if branch == FailureBranch.SYNTAX_TOOL:
            return [
                f"Check {tool} documentation for correct syntax",
                f"Use simpler arguments for {tool}",
                "Try alternative tool with similar functionality"
            ]
        elif branch == FailureBranch.DEFENSE_ACTIVE:
            return [
                "Add delays between requests to avoid rate limiting",
                "Change user-agent or request headers",
                "Try different encoding or obfuscation techniques"
            ]
        else:  # FALSE_ASSUMPTION
            return [
                "Verify target is reachable and correct",
                "Scan for actual attack surface before exploitation",
                "Consider completely different attack vector"
            ]
    
    def _format_corrective_action(self, analysis: FailureAnalysis) -> str:
        """Format the analysis into a corrective action description"""
        branch_name = {
            FailureBranch.SYNTAX_TOOL: "Syntax/Tool Issue",
            FailureBranch.DEFENSE_ACTIVE: "Active Defense",
            FailureBranch.FALSE_ASSUMPTION: "False Assumption"
        }[analysis.most_likely_branch]
        
        probabilities = analysis.branch_probabilities
        
        logger.info(f"🌳 ToT Analysis Complete:")
        logger.info(f"   Most Likely: {branch_name} ({probabilities[analysis.most_likely_branch]:.2f})")
        logger.info(f"   Branch A (Syntax): {probabilities[FailureBranch.SYNTAX_TOOL]:.2f}")
        logger.info(f"   Branch B (Defense): {probabilities[FailureBranch.DEFENSE_ACTIVE]:.2f}")
        logger.info(f"   Branch C (Assumption): {probabilities[FailureBranch.FALSE_ASSUMPTION]:.2f}")
        logger.info(f"   Recommendation: {analysis.recommended_action}")
        
        return analysis.recommended_action


# =============================================================================
# UTILITY FUNCTIONS FOR PARSING LLM OUTPUT WITH <think> TAGS
# =============================================================================

def extract_thinking_and_json(llm_output: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse LLM output to separate <think> content from JSON response.
    
    Args:
        llm_output: The raw output from the LLM
        
    Returns:
        Tuple of (thinking_content, json_content)
        thinking_content will be None if no <think> tags found
        json_content will be None if no JSON found
    """
    thinking_content = None
    json_content = None
    
    # Extract thinking content from <think> tags
    think_match = re.search(r'<think>(.*?)</think>', llm_output, re.DOTALL | re.IGNORECASE)
    if think_match:
        thinking_content = think_match.group(1).strip()
    
    # Extract JSON (try multiple patterns)
    # Pattern 1: JSON in code block
    json_match = re.search(r'```json\s*(\{.*?\})\s*```', llm_output, re.DOTALL)
    if json_match:
        json_content = json_match.group(1)
    else:
        # Pattern 2: Raw JSON object (after </think> if present)
        search_start = llm_output.find('</think>') + 8 if '</think>' in llm_output else 0
        remaining = llm_output[search_start:]
        json_match = re.search(r'\{.*\}', remaining, re.DOTALL)
        if json_match:
            json_content = json_match.group(0)
    
    return thinking_content, json_content


def log_thinking_process(thinking_content: str, logger_instance: logging.Logger = logger) -> None:
    """
    Log the thinking process from <think> tags in a structured way.
    
    Args:
        thinking_content: The content from <think> tags
        logger_instance: Logger instance to use for logging
    """
    if not thinking_content:
        return
    
    logger_instance.info("=" * 70)
    logger_instance.info("💭 ADVANCED REASONING PROCESS")
    logger_instance.info("=" * 70)
    
    # Split by phases
    phases = {
        'PHASE 1': 'DIVERGENCE',
        'PHASE 2': 'CRITIQUE',
        'PHASE 3': 'CONVERGENCE'
    }
    
    for phase_marker, phase_name in phases.items():
        if phase_marker in thinking_content:
            logger_instance.info(f"\n🔹 {phase_name}:")
            # Extract content for this phase
            start = thinking_content.find(phase_marker)
            # Find next phase or end
            next_phase_pos = len(thinking_content)
            for next_marker in phases.keys():
                if next_marker != phase_marker:
                    pos = thinking_content.find(next_marker, start + 1)
                    if pos != -1 and pos < next_phase_pos:
                        next_phase_pos = pos
            
            phase_content = thinking_content[start:next_phase_pos].strip()
            # Log each line with indentation
            for line in phase_content.split('\n')[1:]:  # Skip the phase marker line
                if line.strip():
                    logger_instance.info(f"  {line}")
    
    logger_instance.info("=" * 70)


# =============================================================================
# INTEGRATION HELPERS
# =============================================================================

async def create_auditor_from_orchestrator(orchestrator: Any) -> PreExecutionAuditor:
    """
    Create a PreExecutionAuditor with LLM capabilities from an orchestrator.
    
    Args:
        orchestrator: MultiLLMOrchestrator instance
        
    Returns:
        PreExecutionAuditor instance configured with LLM callback
    """
    async def llm_callback(system_prompt: str, user_message: str) -> Dict[str, Any]:
        """Wrapper for orchestrator LLM call"""
        response = await orchestrator.call_llm(
            role='coder',  # Use coder for technical review
            system_prompt=system_prompt,
            user_message=user_message,
            temperature=0.3,  # Lower temperature for more focused review
            max_tokens=2000
        )
        return response
    
    return PreExecutionAuditor(llm_callable=llm_callback)


async def create_tot_debugger_from_orchestrator(orchestrator: Any) -> TreeOfThoughtsDebugger:
    """
    Create a TreeOfThoughtsDebugger with LLM capabilities from an orchestrator.
    
    Args:
        orchestrator: MultiLLMOrchestrator instance
        
    Returns:
        TreeOfThoughtsDebugger instance configured with LLM callback
    """
    async def llm_callback(system_prompt: str, user_message: str) -> Dict[str, Any]:
        """Wrapper for orchestrator LLM call"""
        response = await orchestrator.call_llm(
            role='vulnerability',  # Use vulnerability analyzer for debugging
            system_prompt=system_prompt,
            user_message=user_message,
            temperature=0.5,
            max_tokens=3000
        )
        return response
    
    return TreeOfThoughtsDebugger(llm_callable=llm_callback)
