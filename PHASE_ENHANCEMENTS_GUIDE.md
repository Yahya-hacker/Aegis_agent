# Phase 1-4 Enhancements - Usage Guide

This guide demonstrates how to use the new features added in Phases 1-4.

## Phase 1: Environment-Based Model Configuration

The model configuration now supports environment variables, allowing you to customize the LLMs without modifying code.

### Using Default Models

By default, the system uses the approved models:
- `ORCHESTRATOR_MODEL`: nousresearch/hermes-3-llama-3.1-70b
- `CODE_MODEL`: qwen/qwen-2.5-72b-instruct  
- `REASONING_MODEL`: cognitivecomputations/dolphin3.0-r1-mistral-24b

### Overriding Models

Create a `.env` file in the project root:

```bash
# Override the code model for specialized tasks
CODE_MODEL=cognitivecomputations/dolphin-2.9-deepseek-coder-33b

# Or override all models
ORCHESTRATOR_MODEL=your/custom-orchestrator-model
REASONING_MODEL=your/custom-reasoning-model
```

The system will use your custom models while falling back to defaults if not specified.

---

## Phase 2: Business Logic Testing

### Business Logic Mapper

Define application-specific logic flows for intelligent testing:

```python
from utils.business_logic_mapper import get_business_logic_mapper

# Get the mapper instance
mapper = get_business_logic_mapper()

# Define your application's business logic
logic_definition = {
    "authentication": {
        "flows": ["login", "register", "password_reset", "2fa_verification"],
        "rules": ["rate_limiting", "session_validation", "brute_force_protection"],
        "endpoints": ["/api/login", "/api/register", "/api/reset-password"]
    },
    "payment": {
        "flows": ["add_to_cart", "checkout", "payment", "order_confirmation"],
        "rules": ["inventory_check", "price_validation", "payment_verification"],
        "endpoints": ["/api/cart", "/api/checkout", "/api/payment"]
    },
    "account_management": {
        "flows": ["view_profile", "edit_profile", "delete_account"],
        "rules": ["authorization_check", "data_validation"],
        "endpoints": ["/api/profile", "/api/account"]
    }
}

# Load the definition
mapper.load_logic_definition(logic_definition)

# Get a formatted summary for AI prompts
summary = mapper.get_testable_functions()
print(summary)
```

### Logic Tester Tool

Test business logic flows for security vulnerabilities:

```python
import asyncio
from tools.logic_tester import get_logic_tester

async def test_checkout_flow():
    tester = get_logic_tester()
    
    # Define the test steps
    steps = [
        {
            "method": "POST",
            "url": "https://example.com/api/cart/add",
            "data": {"product_id": 123, "quantity": 1},
            "description": "Add item to cart"
        },
        {
            "method": "GET",
            "url": "https://example.com/api/checkout",
            "description": "Access checkout page",
            "should_be_blocked": False  # This should succeed
        },
        {
            "method": "POST",
            "url": "https://example.com/api/payment",
            "data": {"amount": 99.99, "card": "4111111111111111"},
            "description": "Process payment",
            "should_be_blocked": False
        }
    ]
    
    # Test the flow
    results = await tester.test_logic_flow(
        flow_name="Standard Checkout Flow",
        steps=steps,
        expected_behavior="Payment should only succeed after cart and checkout steps",
        test_type="sequence_bypass"
    )
    
    # Check results
    if results["vulnerable"]:
        print(f"⚠️ Vulnerability found!")
        for finding in results["findings"]:
            print(f"  - {finding['type']}: {finding['description']}")
    else:
        print("✅ No vulnerabilities detected")

# Run the test
asyncio.run(test_checkout_flow())
```

### Test Sequence Bypass

Quickly test if workflow steps can be bypassed:

```python
async def test_payment_bypass():
    tester = get_logic_tester()
    
    # Normal sequence
    normal_sequence = ["/cart", "/checkout", "/payment", "/confirmation"]
    
    # Try to skip directly to payment
    bypass_sequence = ["/payment"]
    
    results = await tester.test_sequence_bypass(
        base_url="https://example.com",
        normal_sequence=normal_sequence,
        bypass_sequence=bypass_sequence
    )
    
    return results

asyncio.run(test_payment_bypass())
```

---

## Phase 3: AI-Enhanced Triage

The system now uses the Reasoning LLM to intelligently re-assess vulnerability priorities based on mission context.

### How It Works

1. The VulnerabilityAnalyzer performs initial analysis
2. The AI Triage system re-assesses each finding with mission context
3. Priority is adjusted based on:
   - Mission-specific context
   - Real-world exploitability
   - Business impact
   - Required effort vs. potential gain

### Programmatic Usage

```python
import asyncio
from agents.enhanced_ai_core import EnhancedAegisAI

async def triage_finding():
    ai = EnhancedAegisAI()
    await ai.initialize()
    
    # Example vulnerability finding
    finding = {
        "type": "sql_injection",
        "url": "https://example.com/search?q=test",
        "description": "SQL injection in search parameter",
        "severity": "high",
        "evidence": "Error: MySQL syntax error..."
    }
    
    # Mission context
    mission_context = """
    Target: example.com (e-commerce platform)
    Goal: Find critical vulnerabilities in payment system
    Constraints: Read-only testing, no data exfiltration
    Timeline: 2-day assessment
    """
    
    # Apply AI triage
    triaged = await ai.contextual_triage(finding, mission_context)
    
    # Check AI assessment
    if triaged.get('ai_triaged'):
        ai_assessment = triaged['ai_triage']
        print(f"AI Priority: {ai_assessment['priority']}")
        print(f"Risk Score: {ai_assessment['risk_score']}/10")
        print(f"Exploitability: {ai_assessment['exploitability']}")
        print(f"Should Verify: {ai_assessment['should_verify']}")
        print(f"Reasoning: {ai_assessment['reasoning']}")

asyncio.run(triage_finding())
```

### Automatic Integration

When using the conversational agent, AI triage is applied automatically:

```bash
# Run Aegis AI
python main.py

# When vulnerabilities are found, you'll see:
# 📊 Analyzing and prioritizing vulnerabilities...
# 🧠 Applying AI-enhanced triage...
#   Triaging finding 1/5: sql_injection → AI Priority: P0-Critical
#   Triaging finding 2/5: xss → AI Priority: P2-Medium
```

---

## Phase 4: Multimodal Visual Reconnaissance

### Visual Reconnaissance Tool

Capture authenticated screenshots and analyze DOM structures:

```python
import asyncio
from tools.visual_recon import get_visual_recon_tool

async def visual_recon_example():
    tool = get_visual_recon_tool()
    
    # Capture screenshot (with authentication if session.json exists)
    screenshot = await tool.capture_screenshot(
        url="https://example.com/dashboard",
        full_page=True,  # Capture entire page
        wait_for_selector=".dashboard-content"  # Wait for element
    )
    
    if screenshot['status'] == 'success':
        print(f"Screenshot saved: {screenshot['screenshot_path']}")
        print(f"Page title: {screenshot['page_title']}")
    
    # Get DOM snapshot
    dom = await tool.get_dom_snapshot(
        url="https://example.com/profile",
        selectors=[".user-info", "form", ".sensitive-data"]
    )
    
    if dom['status'] == 'success':
        print(f"Found {dom['links_count']} links")
        print(f"Found {dom['forms_count']} forms")
        print(f"Extracted elements: {dom['extracted_elements'].keys()}")
    
    # Clean up
    await tool.close()

asyncio.run(visual_recon_example())
```

### Visual Analysis with AI

Analyze screenshots using the Visual LLM:

```python
async def analyze_screenshot():
    from agents.enhanced_ai_core import EnhancedAegisAI
    
    ai = EnhancedAegisAI()
    await ai.initialize()
    
    # Analyze a screenshot
    analysis = await ai.analyze_visuals(
        image_path="data/screenshots/screenshot_dashboard_12345.png",
        text_prompt="""
        Analyze this screenshot for security issues:
        1. Are there any exposed sensitive data in the UI?
        2. What security indicators are visible (HTTPS, security badges)?
        3. Are there any suspicious UI elements or anomalies?
        4. What user permissions or roles are indicated?
        """
    )
    
    print("Visual Analysis:")
    print(analysis)

asyncio.run(analyze_screenshot())
```

### Context Manager Usage

Use visual recon with automatic cleanup:

```python
async def recon_with_context_manager():
    from tools.visual_recon import VisualReconTool
    
    async with VisualReconTool() as recon:
        # Multiple operations with same browser session
        screenshot1 = await recon.capture_screenshot("https://example.com/page1")
        screenshot2 = await recon.capture_screenshot("https://example.com/page2")
        dom = await recon.get_dom_snapshot("https://example.com/page3")
        
        # Browser automatically closed when exiting context

asyncio.run(recon_with_context_manager())
```

### 4-Model Architecture

The system now has 4 specialized LLMs:

1. **Strategic Planner** (Hermes 3 Llama 70B) - Mission planning, triage, decisions
2. **Reasoning Analyst** (Dolphin 3.0 Mistral 24B) - Vulnerability analysis, exploitation
3. **Code Specialist** (Qwen 2.5 72B) - Code analysis, payload generation
4. **Visual Analyst** (Gemini Pro Vision) - Screenshot analysis, UI reconnaissance

```python
from agents.multi_llm_orchestrator import MultiLLMOrchestrator

async def use_visual_llm():
    orchestrator = MultiLLMOrchestrator()
    await orchestrator.initialize()
    
    # Analyze an image with text prompt
    result = await orchestrator.execute_multimodal_task(
        text_prompt="What vulnerabilities can you identify in this login page?",
        image_path="screenshots/login_page.png"
    )
    
    print(f"Visual Analysis: {result['content']}")

asyncio.run(use_visual_llm())
```

---

## Complete Workflow Example

Here's how all the features work together in a real assessment:

```python
import asyncio
from agents.enhanced_ai_core import EnhancedAegisAI
from utils.business_logic_mapper import get_business_logic_mapper
from tools.logic_tester import get_logic_tester
from tools.visual_recon import get_visual_recon_tool

async def complete_assessment():
    # 1. Initialize AI with environment-configured models
    ai = EnhancedAegisAI()
    await ai.initialize()
    
    # 2. Define business logic
    mapper = get_business_logic_mapper()
    mapper.load_logic_definition({
        "authentication": {
            "flows": ["login", "2fa", "logout"],
            "rules": ["rate_limiting", "session_timeout"]
        }
    })
    
    # 3. Test business logic
    tester = get_logic_tester()
    logic_results = await tester.test_logic_flow(
        flow_name="Login Flow",
        steps=[
            {"method": "POST", "url": "https://example.com/login",
             "data": {"user": "test", "pass": "test"},
             "description": "Submit login"}
        ],
        expected_behavior="Proper authentication required",
        test_type="sequence_bypass"
    )
    
    # 4. Visual reconnaissance
    visual = get_visual_recon_tool()
    screenshot = await visual.capture_screenshot("https://example.com/dashboard")
    
    # 5. Analyze visuals with AI
    visual_analysis = await ai.analyze_visuals(
        screenshot['screenshot_path'],
        "Identify any exposed sensitive information or security issues"
    )
    
    # 6. AI-enhanced triage of findings
    finding = {
        "type": "session_fixation",
        "url": "https://example.com/login",
        "severity": "medium"
    }
    
    triaged = await ai.contextual_triage(finding, "E-commerce assessment")
    
    # Cleanup
    await visual.close()
    
    return {
        "logic_test": logic_results,
        "visual_analysis": visual_analysis,
        "triaged_finding": triaged
    }

# Run complete assessment
results = asyncio.run(complete_assessment())
```

---

## Installation Notes

### Install Dependencies

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium
```

### Set Up Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit .env and add your API key
# OPENROUTER_API_KEY=your_key_here

# Optional: Override models
# CODE_MODEL=cognitivecomputations/dolphin-2.9-deepseek-coder-33b
```

### Session Management

For authenticated testing, create a session file:

```bash
# data/session.json
{
  "cookies": [
    {"name": "session_id", "value": "your_session_id"},
    {"name": "auth_token", "value": "your_token"}
  ]
}
```

All authenticated tools (visual_recon, logic_tester) will automatically use these cookies.

---

## Tips and Best Practices

1. **Model Selection**: Use environment variables to swap models for specific tasks without code changes
2. **Business Logic**: Define comprehensive logic maps before testing to guide the AI
3. **AI Triage**: Provide detailed mission context for more accurate priority assessments
4. **Visual Analysis**: Use full-page screenshots for comprehensive coverage
5. **Session Management**: Keep session.json updated for authenticated testing
6. **Resource Management**: Always close visual recon tools or use context managers

---

## Troubleshooting

### Playwright Issues
```bash
# If browser not found:
playwright install chromium

# Check installation:
playwright --version
```

### Model Override Not Working
```bash
# Ensure .env is in the project root
ls -la .env

# Check environment variables are loaded
python -c "from agents.enhanced_ai_core import CODE_MODEL; print(CODE_MODEL)"
```

### Session Cookies Not Working
```bash
# Verify session.json format
cat data/session.json | python -m json.tool

# Check file permissions
chmod 644 data/session.json
```
