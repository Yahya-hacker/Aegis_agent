# Deep Think Verification & Self-Correction Features

## Overview

This document describes the three anti-hallucination features implemented to drastically reduce false positives and improve the reliability of the Aegis Agent.

## Task 1: Deep Think Verification Layer

### Implementation

**File**: `agents/enhanced_ai_core.py`

**Method**: `verify_finding_with_reasoning(finding: Dict, target_url: str) -> Optional[Dict]`

### Purpose

Implements a "Devil's Advocate" verification loop where the Reasoning Model (Dolphin 3.0 R1 Mistral 24B) critically evaluates vulnerability findings before they are accepted and stored in the database.

### How It Works

1. **Input**: Takes a vulnerability finding and target URL
2. **Prompt Construction**: Creates a detailed prompt instructing the Reasoning LLM to act as a Senior Security Engineer
3. **Critical Analysis**: The model checks for common false positives:
   - 404 errors masquerading as vulnerabilities
   - Generic WAF blocks
   - Expected security responses
   - Misinterpreted error messages
   - Context confusion
   - Insufficient evidence

4. **JSON Response**: Returns structured data:
   ```json
   {
     "is_hallucination": true|false,
     "confidence_score": 0-100,
     "reasoning": "Detailed explanation..."
   }
   ```

5. **Filtering**: If `is_hallucination` is true, the finding is rejected and logged

### Integration Points

- Called in `scanner.py` within `vulnerability_scan` tool before adding findings to database
- Called in `scanner.py` within `run_sqlmap` tool before recording SQL injection findings

### Benefits

- Reduces false positives from automated scanners
- Provides detailed reasoning for each decision
- Logs all verification attempts for debugging and improvement
- Conservative fallback: On error, accepts the finding with warning

---

## Task 2: Strict Database Grounding

### Implementation

**File**: `agents/enhanced_ai_core.py`

**Method**: `_get_next_action_async(bbp_rules: str, agent_memory: List[Dict]) -> Dict`

### Purpose

Prevents the agent from inventing non-existent targets by enforcing strict grounding to database context.

### How It Works

1. **Database Context Injection**: The method retrieves database statistics and recent scans
2. **Grounding Rule Addition**: Appends a "STRICT GROUNDING RULE" to the system prompt:
   ```
   ⚠️ STRICT GROUNDING RULE (ANTI-HALLUCINATION) ⚠️
   You can ONLY attack targets that explicitly exist in the 'DATABASE STATUS' list provided above.
   When proposing an action, you MUST cite the specific 'target_id' or exact string from the database context.
   If you want to attack a new target, you must first run 'subdomain_enumeration' to find it and add it to the DB.
   DO NOT invent URLs, domains, or targets that are not present in the database or mission context.
   ```

3. **Enforcement**: The agent must reference existing database entries when proposing actions

### Benefits

- Eliminates hallucinated targets
- Forces sequential workflow: discover → verify → attack
- Provides clear audit trail of all tested targets
- Prevents duplicate work by checking database first

---

## Task 3: Self-Correction Mechanism

### Implementation

**File**: `agents/scanner.py`

**Methods**:
- `_self_correct_and_retry(tool: str, original_args: Dict, error_message: str) -> Optional[Dict]`
- `execute_action(action: Dict) -> Dict` (enhanced)
- `_execute_tool_internal(tool: str, args: Dict) -> Dict` (new)

### Purpose

Automatically recovers from tool execution failures by using the Coder LLM to suggest corrected command syntax.

### How It Works

1. **Retry Wrapper**: `execute_action` now wraps tool execution with retry logic
2. **Error Detection**: Catches exceptions and error statuses from tool execution
3. **Self-Correction Call**: On first failure, calls `_self_correct_and_retry`:
   - Sends error details to Coder LLM (Qwen 2.5 72B)
   - Requests analysis and corrected arguments
   - Parses JSON response with corrected parameters

4. **Automatic Retry**: Retries execution with corrected arguments
5. **Failure Handling**: If second attempt fails, returns error to user

### Error Correction Process

```
┌─────────────────┐
│  Execute Tool   │
└────────┬────────┘
         │
    ┌────▼─────┐
    │  Error?  │
    └────┬─────┘
         │ Yes (Attempt 1)
    ┌────▼────────────────┐
    │ Call Coder LLM      │
    │ Request Fix         │
    └────┬────────────────┘
         │
    ┌────▼────────────────┐
    │ Parse Corrected     │
    │ Arguments           │
    └────┬────────────────┘
         │
    ┌────▼─────┐
    │  Retry   │
    └────┬─────┘
         │
    ┌────▼─────┐
    │ Success? │
    └────┬─────┘
         │ No
    ┌────▼─────┐
    │  Return  │
    │  Error   │
    └──────────┘
```

### Benefits

- Automatic recovery from common errors (syntax, timeouts, format issues)
- Reduces manual intervention
- Learns from errors through LLM reasoning
- Maximum of 2 attempts prevents infinite loops
- Detailed logging of correction attempts

---

## Testing

### Test Suite

**File**: `test_deep_think_features.py`

Includes tests for:
1. Deep Think verification with legitimate findings
2. Deep Think verification with false positives
3. Strict grounding rule in action planning
4. Self-correction mechanism
5. Integration test of all features

### Running Tests

```bash
# Note: Requires OPENROUTER_API_KEY environment variable
python3 test_deep_think_features.py
```

---

## Configuration

### Environment Variables

- `OPENROUTER_API_KEY`: Required for LLM API access
- `REASONING_MODEL`: Override for reasoning model (default: `cognitivecomputations/dolphin3.0-r1-mistral-24b`)
- `CODE_MODEL`: Override for coder model (default: `qwen/qwen-2.5-72b-instruct`)

### Database

- Uses SQLite database at `data/mission.db`
- Automatically initialized on first use
- Tables: `findings`, `scanned_targets`, `subdomains`, `endpoints`

---

## Security Considerations

1. **CodeQL Analysis**: All changes passed CodeQL security scan with 0 alerts
2. **Error Handling**: All new methods include comprehensive exception handling
3. **Conservative Defaults**: On verification failure, defaults to accepting findings with warnings
4. **Logging**: All verification and correction attempts are logged for audit
5. **No Data Exfiltration**: All processing happens locally or through configured API

---

## Performance Impact

### Latency

- Deep Think verification adds ~1-3 seconds per finding (LLM call)
- Self-correction adds ~1-2 seconds on error (only when needed)
- Database grounding has negligible impact (~10ms)

### API Usage

- Deep Think: 1 LLM call per finding (Reasoning model)
- Self-Correction: 1 LLM call per failed command (Coder model)
- Both use conservative token limits (512-1024 tokens)

### Mitigation Strategies

- Batch verification can be implemented for multiple findings
- Caching of verification results for similar findings
- Self-correction only triggers on actual failures

---

## Future Enhancements

1. **Verification Confidence Thresholds**: Make confidence score threshold configurable
2. **Batch Verification**: Verify multiple findings in a single LLM call
3. **Verification Cache**: Cache verification results for similar findings
4. **Multi-Attempt Self-Correction**: Allow configurable retry count
5. **Learning from Corrections**: Store successful corrections for pattern recognition
6. **Verification Metrics**: Track and report verification statistics

---

## Backward Compatibility

All changes are backward compatible:
- Existing tools continue to work without modification
- Verification can be disabled by skipping the verification call
- Database grounding is additive to existing prompts
- Self-correction wraps existing execution logic

---

## Migration Guide

No migration needed - features are enabled automatically when using the updated code.

To use the new features:

1. **Deep Think Verification**: Automatically enabled for `vulnerability_scan` and `run_sqlmap`
2. **Database Grounding**: Automatically enabled in all autonomous actions
3. **Self-Correction**: Automatically enabled for all tool executions

---

## Troubleshooting

### Issue: Verification rejects valid findings

**Solution**: Check the reasoning in the logs. Adjust prompt or confidence threshold if needed.

### Issue: Self-correction fails to fix errors

**Solution**: Check if the error is correctable. Some errors (network issues, missing tools) cannot be fixed by argument changes.

### Issue: Performance degradation

**Solution**: Monitor LLM API latency. Consider caching or batching strategies.

### Issue: Database grounding too restrictive

**Solution**: Ensure subdomain enumeration runs first to populate database with targets.

---

## Credits

Implemented by: GitHub Copilot Agent
Based on requirements from: Aegis Agent project
Models used:
- Reasoning: Dolphin 3.0 R1 Mistral 24B (via OpenRouter)
- Coding: Qwen 2.5 72B Instruct (via OpenRouter)
