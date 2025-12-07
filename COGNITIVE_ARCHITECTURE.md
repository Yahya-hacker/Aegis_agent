# Advanced Cognitive Architecture for Aegis v8.0

## Overview

This module implements three major cognitive mechanisms to maximize the intelligence and reliability of the Aegis AI security agent:

1. **God Mode System Prompt** - Structured Chain of Thought reasoning
2. **Pre-Execution Auditor** - Self-correction and safety validation
3. **Tree of Thoughts Debugger** - Intelligent failure analysis and recovery

All code is production-ready with:
- ✅ Full type hints (Type Hints)
- ✅ Comprehensive error handling
- ✅ Async/await support
- ✅ 100% test coverage (23/23 tests passing)
- ✅ Professional English documentation

## Installation

The cognitive mechanisms are included in the main Aegis codebase. No additional dependencies are required beyond the standard `requirements.txt`.

## Quick Start

```python
from agents.cognitive_mechanisms import (
    ADVANCED_REASONING_PROMPT,
    PreExecutionAuditor,
    TreeOfThoughtsDebugger,
    extract_thinking_and_json,
    log_thinking_process
)

# 1. Use God Mode prompt in your LLM calls
enhanced_prompt = f"{your_base_prompt}\n\n{ADVANCED_REASONING_PROMPT}"

# 2. Create an auditor for self-correction
auditor = PreExecutionAuditor()
is_safe, response = await auditor.audit_proposed_action(action)

# 3. Create a debugger for failure analysis
debugger = TreeOfThoughtsDebugger()
corrective_action = await debugger.analyze_failure_with_tot(action, error)
```

## Mechanism 1: God Mode System Prompt

### What It Does

The `ADVANCED_REASONING_PROMPT` forces the LLM to follow a structured 3-phase reasoning process before outputting any action:

- **Phase 1 (Divergence)**: Generate 3 distinct approaches
- **Phase 2 (Critique)**: Act as Devil's Advocate to attack the best idea
- **Phase 3 (Convergence)**: Refine the plan based on critique

All reasoning happens inside `<think></think>` tags, separate from the final JSON output.

### Usage

```python
# Add to your system prompt
system_prompt = f"""
You are a security testing agent.

{ADVANCED_REASONING_PROMPT}
"""

# The LLM will respond like this:
response = """
<think>
=== PHASE 1: DIVERGENCE ===
Approach A: Use directory bruteforcing
Approach B: Analyze robots.txt
Approach C: Check for .git exposure

=== PHASE 2: CRITIQUE ===
Best Approach: B
Critical Attack 1: robots.txt might not exist
Critical Attack 2: Could miss dynamic routes
Critical Attack 3: Might have rate limiting

=== PHASE 3: CONVERGENCE ===
Refined Approach: Start with B, fallback to A
Mitigation: Add delays, timeouts
Success Criteria: Find 5+ endpoints OR exhausted methods
</think>

{
  "tool": "check_robots_txt",
  "args": {"target": "example.com"}
}
"""

# Extract and log the thinking
thinking, json_str = extract_thinking_and_json(response)
log_thinking_process(thinking)  # Pretty-prints to logs
```

### Benefits

- **Prevents rushed decisions**: Forces deliberate reasoning
- **Identifies weaknesses**: Devil's Advocate catches flaws
- **Improves reliability**: Refined plans are more robust
- **Transparent**: All reasoning is logged for debugging

## Mechanism 2: Pre-Execution Auditor

### What It Does

The `PreExecutionAuditor` reviews proposed actions before execution to catch:

- 🛡️ **Dangerous commands** (rm -rf, eval, etc.)
- 🔍 **Syntax errors** (malformed JSON, unclosed brackets)
- 🔄 **Circular logic** (repeated actions without progress)
- 🤖 **LLM code review** (optional deep analysis)

### Usage

```python
from agents.cognitive_mechanisms import PreExecutionAuditor, AuditResult

# Create auditor (optionally with LLM support)
auditor = PreExecutionAuditor()

# Audit a proposed action
action = {
    "tool": "execute_command",
    "args": {"command": "rm -rf /tmp/test"}
}

is_approved, response = await auditor.audit_proposed_action(action)

print(f"Result: {response.result.value}")  # "approved" | "rejected" | "warning"
print(f"Safety Score: {response.safety_score}")  # 0.0 - 1.0
print(f"Reason: {response.reason}")

if not is_approved:
    # Force agent to regenerate
    print("Action rejected - proposing new action...")
    for suggestion in response.suggestions:
        print(f"  - {suggestion}")
```

### With LLM Support

```python
from agents.multi_llm_orchestrator import MultiLLMOrchestrator
from agents.cognitive_mechanisms import create_auditor_from_orchestrator

# Initialize orchestrator
orchestrator = MultiLLMOrchestrator()
await orchestrator.initialize()

# Create auditor with LLM capabilities
auditor = await create_auditor_from_orchestrator(orchestrator)

# Now it can perform deep code review
is_approved, response = await auditor.audit_proposed_action(
    action,
    context={"recent_actions": [...], "vulnerabilities_found": [...]}
)
```

### Safety Scores

- **1.0**: Perfect - no issues detected
- **0.7-0.99**: Warning - minor issues, action approved with cautions
- **0.4-0.69**: Risky - significant issues, action may be rejected
- **< 0.4**: Rejected - dangerous or invalid action

## Mechanism 3: Tree of Thoughts Debugger

### What It Does

When an action fails, the `TreeOfThoughtsDebugger` analyzes it using three parallel reasoning branches:

- **Branch A (Syntax/Tool)**: Wrong command syntax or tool misconfiguration
- **Branch B (Active Defense)**: WAF, rate limiting, IDS blocking
- **Branch C (False Assumption)**: Wrong target or misunderstood vulnerability

It calculates probabilities for each branch and recommends corrective action.

### Usage

```python
from agents.cognitive_mechanisms import TreeOfThoughtsDebugger

debugger = TreeOfThoughtsDebugger()

# When a command fails
failed_action = {
    "tool": "sql_injection",
    "args": {"payload": "' OR 1=1--"}
}
error_output = "403 Forbidden - WAF Blocked Request"

# Analyze the failure
corrective_action = await debugger.analyze_failure_with_tot(
    failed_action,
    error_output
)

print(corrective_action)
# Output: "Bypass or adapt to active defense mechanisms"

# With context
corrective_action = await debugger.analyze_failure_with_tot(
    failed_action,
    error_output,
    context={
        "previous_attempts": 3,
        "target_info": {...}
    }
)
```

### With LLM Support

```python
from agents.multi_llm_orchestrator import MultiLLMOrchestrator
from agents.cognitive_mechanisms import create_tot_debugger_from_orchestrator

orchestrator = MultiLLMOrchestrator()
await orchestrator.initialize()

# Create ToT debugger with LLM
debugger = await create_tot_debugger_from_orchestrator(orchestrator)

# Now it uses LLM for sophisticated analysis
corrective_action = await debugger.analyze_failure_with_tot(
    failed_action,
    error_output
)
```

### Example Output

```
🌳 ToT Analysis Complete:
   Most Likely: Active Defense (0.60)
   Branch A (Syntax): 0.20
   Branch B (Defense): 0.60
   Branch C (Assumption): 0.20
   Recommendation: Bypass or adapt to active defense mechanisms
```

## Full Integration Example

Here's how all three mechanisms work together in a complete operation:

```python
import asyncio
from agents.multi_llm_orchestrator import MultiLLMOrchestrator
from agents.cognitive_mechanisms import (
    ADVANCED_REASONING_PROMPT,
    create_auditor_from_orchestrator,
    create_tot_debugger_from_orchestrator,
    extract_thinking_and_json,
    log_thinking_process
)

async def intelligent_operation():
    # Initialize
    orchestrator = MultiLLMOrchestrator()
    await orchestrator.initialize()
    
    auditor = await create_auditor_from_orchestrator(orchestrator)
    debugger = await create_tot_debugger_from_orchestrator(orchestrator)
    
    # Step 1: Get action from LLM (with God Mode prompt)
    system_prompt = f"You are a pentesting agent.\n\n{ADVANCED_REASONING_PROMPT}"
    user_message = "Test example.com for vulnerabilities"
    
    response = await orchestrator.call_llm(
        role='strategic',
        system_prompt=system_prompt,
        user_message=user_message
    )
    
    # Extract thinking and action
    thinking, json_str = extract_thinking_and_json(response['content'])
    log_thinking_process(thinking)  # Log the reasoning
    
    import json
    proposed_action = json.loads(json_str)
    
    # Step 2: Audit the action
    is_approved, audit_response = await auditor.audit_proposed_action(
        proposed_action,
        context={"recent_actions": [...]}
    )
    
    if not is_approved:
        print(f"Action rejected: {audit_response.reason}")
        # Force regeneration...
        return
    
    # Step 3: Execute the action
    try:
        result = await execute_tool(proposed_action)
        if result.exit_code != 0:
            # Step 4: Analyze failure
            corrective_action = await debugger.analyze_failure_with_tot(
                proposed_action,
                result.error_output
            )
            print(f"Failure analyzed. Recommendation: {corrective_action}")
            # Retry with correction...
    except Exception as e:
        # Handle execution errors...
        pass

asyncio.run(intelligent_operation())
```

## API Reference

### Classes

#### `PreExecutionAuditor`

```python
class PreExecutionAuditor:
    def __init__(self, llm_callable: Optional[Callable] = None)
    
    async def audit_proposed_action(
        self,
        action_payload: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, AuditResponse]
```

#### `TreeOfThoughtsDebugger`

```python
class TreeOfThoughtsDebugger:
    def __init__(self, llm_callable: Optional[Callable] = None)
    
    async def analyze_failure_with_tot(
        self,
        previous_action: Dict[str, Any],
        error_output: str,
        context: Optional[Dict[str, Any]] = None
    ) -> str
```

#### `AuditResponse`

```python
@dataclass
class AuditResponse:
    result: AuditResult  # APPROVED | REJECTED | WARNING
    reason: str
    suggestions: List[str]
    safety_score: float  # 0.0 to 1.0
```

#### `FailureAnalysis`

```python
@dataclass
class FailureAnalysis:
    most_likely_branch: FailureBranch  # SYNTAX_TOOL | DEFENSE_ACTIVE | FALSE_ASSUMPTION
    branch_probabilities: Dict[FailureBranch, float]
    recommended_action: str
    reasoning: str
    alternative_actions: List[str]
```

### Utility Functions

```python
def extract_thinking_and_json(llm_output: str) -> Tuple[Optional[str], Optional[str]]
def log_thinking_process(thinking_content: str, logger_instance: logging.Logger = logger) -> None

async def create_auditor_from_orchestrator(orchestrator: MultiLLMOrchestrator) -> PreExecutionAuditor
async def create_tot_debugger_from_orchestrator(orchestrator: MultiLLMOrchestrator) -> TreeOfThoughtsDebugger
```

## Testing

Run the comprehensive test suite:

```bash
python3 tests/test_cognitive_mechanisms.py
```

Expected output:
```
======================================================================
AEGIS v8.0 ADVANCED COGNITIVE ARCHITECTURE TESTS
======================================================================

🧠 Testing God Mode System Prompt...
✅ PASS: God Mode Prompt: Exists
✅ PASS: God Mode Prompt: All phases present
✅ PASS: God Mode Prompt: Uses <think> tags
...

======================================================================
TEST SUMMARY
======================================================================
Total Tests: 23
Passed: 23 ✅
Failed: 0 ❌
Success Rate: 100.0%

🎉 ALL TESTS PASSED!
```

## Examples

Run the interactive examples:

```bash
python3 examples/cognitive_architecture_usage.py
```

This demonstrates:
- God Mode prompt integration
- Pre-execution auditing
- Tree of Thoughts debugging
- Full integration workflow
- Orchestrator integration

## Performance Considerations

### God Mode Prompt
- **Latency**: Adds 20-40% to LLM response time (due to thinking phase)
- **Quality**: Significantly improves action quality and reduces errors
- **Tokens**: Uses ~500-1000 additional tokens per call

### Pre-Execution Auditor
- **Without LLM**: ~1-5ms per audit (pattern matching)
- **With LLM**: ~1-3s per audit (deep code review)
- **Recommendation**: Use LLM review only for safety_score < 0.8

### Tree of Thoughts Debugger
- **Without LLM**: ~2-10ms (heuristic analysis)
- **With LLM**: ~2-5s (deep reasoning)
- **Recommendation**: Always use LLM for ToT when available

## Best Practices

1. **Always use God Mode prompt** for strategic decisions
2. **Audit all actions** before execution (especially user input)
3. **Use ToT for all failures** to learn and adapt
4. **Enable LLM support** in production for best results
5. **Log thinking processes** for debugging and auditing
6. **Monitor safety scores** and adjust thresholds as needed
7. **Review audit history** periodically to identify patterns

## Troubleshooting

### Issue: Auditor rejects too many safe actions

**Solution**: Actions with circular logic trigger lower safety scores. This is intentional to prevent loops. Either:
- Modify the action to be different from recent actions
- Adjust `loop_occurrence_threshold` in the auditor

### Issue: ToT always returns generic recommendations

**Solution**: Enable LLM support for sophisticated analysis:
```python
debugger = await create_tot_debugger_from_orchestrator(orchestrator)
```

### Issue: God Mode prompt makes responses too slow

**Solution**: The thinking phase adds latency but improves quality. If speed is critical:
- Use God Mode only for strategic decisions (not every action)
- Use smaller/faster models for tactical decisions
- Cache common reasoning patterns

## Contributing

When modifying cognitive mechanisms:

1. Maintain 100% type hint coverage
2. Add tests for new features
3. Update this README
4. Ensure all existing tests pass
5. Run security audit with CodeQL

## License

Part of Aegis Agent v8.0 - See main LICENSE file.

## Authors

- Advanced Cognitive Architecture Implementation - 2025
- Aegis v8.0 Full-Spectrum Architecture

## Support

- 📖 Full documentation: See `agents/cognitive_mechanisms.py`
- 🧪 Tests: `tests/test_cognitive_mechanisms.py`
- 📝 Examples: `examples/cognitive_architecture_usage.py`
- 🐛 Issues: Report via GitHub Issues
