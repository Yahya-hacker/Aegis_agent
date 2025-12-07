#!/usr/bin/env python3
"""
Usage Example: Advanced Cognitive Architecture Integration
Demonstrates how to integrate the three cognitive mechanisms into Aegis operations.
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import Dict, Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import cognitive mechanisms
from agents.cognitive_mechanisms import (
    ADVANCED_REASONING_PROMPT,
    PreExecutionAuditor,
    TreeOfThoughtsDebugger,
    extract_thinking_and_json,
    log_thinking_process,
    create_auditor_from_orchestrator,
    create_tot_debugger_from_orchestrator
)


async def example_1_god_mode_prompt():
    """
    Example 1: Using the God Mode System Prompt for enhanced reasoning
    
    This shows how to use ADVANCED_REASONING_PROMPT in your LLM calls
    to force structured chain-of-thought reasoning.
    """
    print("=" * 70)
    print("EXAMPLE 1: God Mode System Prompt Integration")
    print("=" * 70)
    print()
    
    # When making LLM calls, inject the ADVANCED_REASONING_PROMPT
    # into your system prompt
    
    base_system_prompt = """You are a penetration testing AI agent.
Your goal is to find and exploit security vulnerabilities."""
    
    # Combine with the God Mode prompt
    enhanced_system_prompt = f"""{base_system_prompt}

{ADVANCED_REASONING_PROMPT}"""
    
    print("📋 Enhanced System Prompt Preview (first 500 chars):")
    print(enhanced_system_prompt[:500] + "...")
    print()
    
    # Simulate an LLM response with <think> tags
    simulated_llm_response = """
<think>
=== PHASE 1: DIVERGENCE ===
Approach A: Use directory bruteforcing with common wordlists
Approach B: Analyze robots.txt and sitemap.xml for hidden paths
Approach C: Check for exposed .git directory and source code

=== PHASE 2: CRITIQUE ===
Best Approach: Approach B (least intrusive, fastest)
Critical Attack 1: robots.txt might not exist or be misleading
Critical Attack 2: Could miss dynamic routes not in sitemap
Critical Attack 3: Target might have rate limiting

=== PHASE 3: CONVERGENCE ===
Refined Approach: Start with B, fallback to A if needed, check C opportunistically
Mitigation Strategies: Implement delays, use stealth mode, timeout after 60s
Success Criteria: Found at least 5 valid endpoints OR exhausted all methods
</think>

{
  "tool": "check_robots_txt",
  "args": {
    "target": "https://example.com",
    "timeout": 10
  }
}
"""
    
    # Extract and log the thinking process
    thinking, json_content = extract_thinking_and_json(simulated_llm_response)
    
    if thinking:
        print("💭 Extracted Thinking Process:")
        log_thinking_process(thinking)
        print()
    
    if json_content:
        print("📦 Extracted Action:")
        print(json_content)
        print()
    
    print("✅ Example 1 Complete")
    print()


async def example_2_pre_execution_auditor():
    """
    Example 2: Using the Pre-Execution Auditor for self-correction
    
    This shows how to audit actions before executing them.
    """
    print("=" * 70)
    print("EXAMPLE 2: Pre-Execution Auditor Integration")
    print("=" * 70)
    print()
    
    # Create an auditor (without LLM for this example)
    auditor = PreExecutionAuditor()
    
    # Example proposed actions
    actions = [
        {
            "name": "Safe reconnaissance",
            "action": {
                "tool": "nmap_scan",
                "args": {"target": "192.168.1.1", "ports": "80,443"}
            }
        },
        {
            "name": "Dangerous command",
            "action": {
                "tool": "execute_command",
                "args": {"command": "rm -rf /tmp/test"}
            }
        },
        {
            "name": "Repeated action (circular logic)",
            "action": {
                "tool": "sql_injection",
                "args": {"target": "example.com"}
            },
            "context": {
                "recent_actions": [
                    {"tool": "sql_injection", "args": {"target": "example.com"}},
                    {"tool": "sql_injection", "args": {"target": "example.com"}},
                ]
            }
        }
    ]
    
    for item in actions:
        print(f"🔍 Auditing: {item['name']}")
        
        context = item.get("context")
        is_approved, response = await auditor.audit_proposed_action(
            item["action"],
            context
        )
        
        print(f"   Result: {response.result.value}")
        print(f"   Safety Score: {response.safety_score:.2f}")
        print(f"   Reason: {response.reason}")
        
        if response.suggestions:
            print(f"   Suggestions:")
            for suggestion in response.suggestions:
                print(f"     - {suggestion}")
        
        print()
    
    print("✅ Example 2 Complete")
    print()


async def example_3_tree_of_thoughts_debugger():
    """
    Example 3: Using Tree of Thoughts for debugging failures
    
    This shows how to analyze failures and get corrective actions.
    """
    print("=" * 70)
    print("EXAMPLE 3: Tree of Thoughts Debugger Integration")
    print("=" * 70)
    print()
    
    # Create a ToT debugger (without LLM for this example)
    debugger = TreeOfThoughtsDebugger()
    
    # Example failure scenarios
    failures = [
        {
            "name": "Syntax Error",
            "action": {"tool": "nmap_scan", "args": {"target": "invalid target"}},
            "error": "nmap: invalid option -- 'i'\nUsage: nmap [options] target"
        },
        {
            "name": "WAF Block",
            "action": {"tool": "sql_injection", "args": {"payload": "' OR 1=1--"}},
            "error": "403 Forbidden - WAF Blocked Request"
        },
        {
            "name": "Target Not Found",
            "action": {"tool": "exploit_vuln", "args": {"target": "nonexistent.example.com"}},
            "error": "404 Not Found - Target does not exist"
        }
    ]
    
    for failure in failures:
        print(f"🌳 Analyzing: {failure['name']}")
        
        corrective_action = await debugger.analyze_failure_with_tot(
            failure["action"],
            failure["error"]
        )
        
        print(f"   Recommended Action: {corrective_action}")
        print()
    
    print("✅ Example 3 Complete")
    print()


async def example_4_full_integration():
    """
    Example 4: Full integration showing all three mechanisms working together
    
    This simulates a complete operation flow with all cognitive mechanisms.
    """
    print("=" * 70)
    print("EXAMPLE 4: Full Integration - Complete Operation Flow")
    print("=" * 70)
    print()
    
    # Initialize components
    auditor = PreExecutionAuditor()
    debugger = TreeOfThoughtsDebugger()
    
    print("🎯 MISSION: Test example.com for vulnerabilities")
    print()
    
    # Step 1: Get action from LLM (with God Mode prompt)
    print("📋 Step 1: LLM proposes action using God Mode prompt")
    simulated_llm_response = """
<think>
=== PHASE 1: DIVERGENCE ===
Approach A: Scan all ports with nmap
Approach B: Check common web vulnerabilities (XSS, SQLi)
Approach C: Analyze SSL/TLS configuration

=== PHASE 2: CRITIQUE ===
Best Approach: A (most comprehensive)
Critical Attack 1: Full port scan might trigger IDS
Critical Attack 2: Could take too long
Critical Attack 3: Might miss application-layer vulns

=== PHASE 3: CONVERGENCE ===
Refined Approach: Start with top 1000 ports, then targeted scans
</think>

{
  "tool": "nmap_scan",
  "args": {"target": "example.com", "ports": "top-1000"}
}
"""
    
    thinking, json_content = extract_thinking_and_json(simulated_llm_response)
    import json
    proposed_action = json.loads(json_content)
    print(f"   Proposed: {proposed_action['tool']}")
    print()
    
    # Step 2: Audit the proposed action
    print("🔍 Step 2: Pre-Execution Auditor reviews the action")
    is_approved, audit_response = await auditor.audit_proposed_action(proposed_action)
    print(f"   Audit Result: {audit_response.result.value}")
    print(f"   Safety Score: {audit_response.safety_score:.2f}")
    
    if not is_approved:
        print(f"   ❌ Action REJECTED: {audit_response.reason}")
        print("   Agent must propose a different action")
        return
    else:
        print(f"   ✅ Action APPROVED")
    print()
    
    # Step 3: Execute action (simulated)
    print("⚙️  Step 3: Execute the action")
    # In real implementation, you would execute the tool here
    # For this example, we simulate a failure
    execution_failed = True
    error_output = "nmap: failed to resolve 'example.com': Name or service not known"
    
    if execution_failed:
        print(f"   ❌ Execution failed: {error_output[:80]}...")
        print()
        
        # Step 4: Analyze failure with Tree of Thoughts
        print("🌳 Step 4: Tree of Thoughts analyzes the failure")
        corrective_action = await debugger.analyze_failure_with_tot(
            proposed_action,
            error_output
        )
        print(f"   Recommendation: {corrective_action}")
        print()
        print("   🔄 Agent should retry with corrective action")
    else:
        print("   ✅ Execution successful")
    
    print()
    print("✅ Example 4 Complete - Full cognitive loop demonstrated")
    print()


async def example_5_integration_with_orchestrator():
    """
    Example 5: Integration with MultiLLMOrchestrator
    
    Shows how to create cognitive mechanisms from an orchestrator instance.
    """
    print("=" * 70)
    print("EXAMPLE 5: Integration with MultiLLMOrchestrator")
    print("=" * 70)
    print()
    
    print("📝 In your actual code, you would do:")
    print()
    
    code_example = """
# Import the orchestrator
from agents.multi_llm_orchestrator import MultiLLMOrchestrator
from agents.cognitive_mechanisms import (
    create_auditor_from_orchestrator,
    create_tot_debugger_from_orchestrator
)

# Initialize orchestrator
orchestrator = MultiLLMOrchestrator()
await orchestrator.initialize()

# Create cognitive mechanisms with LLM support
auditor = await create_auditor_from_orchestrator(orchestrator)
tot_debugger = await create_tot_debugger_from_orchestrator(orchestrator)

# Now they can use the LLM for deep analysis
is_approved, response = await auditor.audit_proposed_action(action, context)
corrective_action = await tot_debugger.analyze_failure_with_tot(action, error)
"""
    
    print(code_example)
    print()
    
    print("💡 Benefits:")
    print("   - Auditor can perform LLM-based code review")
    print("   - ToT debugger can use LLM for advanced reasoning")
    print("   - Seamless integration with existing architecture")
    print()
    
    print("✅ Example 5 Complete")
    print()


async def main():
    """Run all usage examples"""
    print("\n")
    print("*" * 70)
    print("AEGIS v8.0 - ADVANCED COGNITIVE ARCHITECTURE USAGE EXAMPLES")
    print("*" * 70)
    print("\n")
    
    await example_1_god_mode_prompt()
    await example_2_pre_execution_auditor()
    await example_3_tree_of_thoughts_debugger()
    await example_4_full_integration()
    await example_5_integration_with_orchestrator()
    
    print("*" * 70)
    print("ALL EXAMPLES COMPLETE")
    print("*" * 70)
    print()
    print("📚 Next Steps:")
    print("   1. Review agents/cognitive_mechanisms.py for full API")
    print("   2. Run tests with: python3 tests/test_cognitive_mechanisms.py")
    print("   3. Integrate into your Aegis workflow")
    print()


if __name__ == "__main__":
    asyncio.run(main())
