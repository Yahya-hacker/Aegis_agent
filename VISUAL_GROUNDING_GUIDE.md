# Visual Grounding and Blackboard Memory Guide

This guide covers the new advanced features added to Aegis Agent: **Visual Grounding with Set-of-Mark (SoM)** and **Blackboard Memory System**.

## Table of Contents
1. [Visual Grounding (Set-of-Mark)](#visual-grounding-set-of-mark)
2. [Blackboard Memory System](#blackboard-memory-system)
3. [Integration and Workflow](#integration-and-workflow)
4. [API Reference](#api-reference)

---

## Visual Grounding (Set-of-Mark)

### Overview

Set-of-Mark (SoM) is a visual grounding technique that enables the AI agent to "see" and interact with web user interfaces by identifying and tagging interactive elements with numbered badges.

### How It Works

1. **Screenshot Capture with Tagging**
   - The system captures a screenshot of the target web page
   - JavaScript is injected to find all clickable elements (links, buttons, inputs)
   - Numbered red badges are overlaid on each interactive element
   - A mapping is created: `{ID: {xpath, css_selector, text, tag, ...}}`

2. **Visual Analysis**
   - The AI can analyze the tagged screenshot
   - Elements are referenced by their ID numbers
   - The system maintains the mapping for later use

3. **Interaction**
   - The AI decides which element to interact with (by ID)
   - The system looks up the selector from the mapping
   - The real selector is used to perform the click action

### Available Tools

#### `capture_screenshot_som(url, full_page=False)`

Captures a screenshot with Set-of-Mark visual grounding.

**Parameters:**
- `url` (str): Target URL to screenshot
- `full_page` (bool): Whether to capture full page or just viewport

**Returns:**
```json
{
  "status": "success",
  "url": "https://example.com",
  "screenshot_path": "data/screenshots/som_example_com_1234567890.png",
  "screenshot_base64": "base64_encoded_image...",
  "element_mapping": {
    "1": {
      "xpath": "//*[@id='login-button']",
      "css_selector": "#login-button",
      "tag": "button",
      "text": "Login",
      "type": "submit"
    },
    "2": {
      "xpath": "//html/body/nav/a[1]",
      "css_selector": "nav > a.home-link",
      "tag": "a",
      "text": "Home"
    }
  },
  "num_elements": 15
}
```

#### `click_element_by_id(url, element_id)`

Clicks a specific element using its SoM ID.

**Parameters:**
- `url` (str): Target URL (must match the URL used for capture_screenshot_som)
- `element_id` (int): The element ID from the SoM mapping

**Returns:**
```json
{
  "status": "success",
  "element_id": 1,
  "element_info": {...},
  "click_method": "css_selector",
  "old_url": "https://example.com",
  "new_url": "https://example.com/login",
  "url_changed": true
}
```

#### `visual_screenshot(url, full_page=False)`

Captures a regular screenshot without SoM badges.

**Parameters:**
- `url` (str): Target URL to screenshot
- `full_page` (bool): Whether to capture full page or just viewport

### Usage Example

```python
# 1. Capture screenshot with SoM tagging
result = await scanner.execute_action({
    "tool": "capture_screenshot_som",
    "args": {"url": "https://example.com"}
})

# The screenshot now has numbered badges on all clickable elements
# element_mapping shows: {1: login_button, 2: home_link, 3: search_input, ...}

# 2. Analyze and decide which element to click
# (AI analyzes the screenshot and identifies element #1 as the login button)

# 3. Click the identified element
result = await scanner.execute_action({
    "tool": "click_element_by_id",
    "args": {
        "url": "https://example.com",
        "element_id": 1
    }
})

# The system automatically uses the stored selector to click the button
```

### Use Cases

- **Multi-step workflows**: Navigate through complex authentication flows
- **Dynamic UIs**: Interact with JavaScript-generated elements
- **Form testing**: Identify and test all input fields and buttons
- **Visual validation**: Verify that expected UI elements are present
- **Hidden elements**: Find and interact with elements not easily discoverable via HTML

---

## Blackboard Memory System

### Overview

The Blackboard Memory System implements a persistent knowledge base that tracks mission progress across the entire session. It follows the "blackboard architecture" pattern where multiple sources contribute to shared knowledge.

### Components

1. **Verified Facts** - Confirmed ground truths
   - Example: "Port 443 is open on example.com"
   - Example: "WordPress 5.8 detected"
   - Example: "Admin panel found at /wp-admin"

2. **Pending Goals** - Objectives to achieve
   - Example: "Test admin panel for weak credentials"
   - Example: "Enumerate WordPress plugins"
   - Example: "Check for SQL injection in search parameter"

3. **Discarded Vectors** - Failed attack paths
   - Example: "SQL injection in search - WAF blocked"
   - Example: "Port 22 filtered - SSH not accessible"
   - Example: "Directory traversal - input sanitized"

### How It Works

1. **Automatic Fact Extraction**
   - After every tool execution, the Reasoning LLM analyzes the output
   - Facts, goals, and discarded vectors are automatically extracted
   - The blackboard is updated with new knowledge

2. **Persistence**
   - All data is saved to disk: `data/blackboard_<mission_id>.json`
   - Survives across sessions and restarts
   - Can be loaded for mission continuation

3. **Context Integration**
   - The blackboard summary is included in every decision-making context
   - The AI "remembers" what has been discovered and attempted
   - Prevents duplicate work and wasted effort

### API Reference

#### `MissionBlackboard` Class

```python
from agents.enhanced_ai_core import MissionBlackboard

# Create or load a blackboard
blackboard = MissionBlackboard(mission_id="my_mission")

# Add a verified fact
blackboard.add_fact("Port 443 is open on example.com")

# Add a pending goal
blackboard.add_goal("Test admin panel for weak credentials")

# Discard a failed attack vector
blackboard.discard_vector("SQL injection in search - WAF blocked")

# Complete a goal
blackboard.complete_goal("Test admin panel for weak credentials")

# Get summary
summary = blackboard.get_summary()
print(summary)

# Clear all data
blackboard.clear()
```

#### `extract_facts_from_output` Method

Automatically extracts knowledge from tool output.

```python
# Called automatically after every tool execution
await ai_core.extract_facts_from_output(
    tool_name="subdomain_enumeration",
    tool_output={
        "status": "success",
        "data": ["api.example.com", "admin.example.com"]
    },
    mission_context="Target: example.com, Rules: BBP scope"
)
```

### Blackboard Summary Format

```
=== MISSION BLACKBOARD ===

VERIFIED FACTS (3):
  1. Port 443 is open on example.com
  2. WordPress 5.8 detected
  3. Admin panel found at /wp-admin

PENDING GOALS (2):
  1. Test admin panel for weak credentials
  2. Enumerate WordPress plugins

DISCARDED VECTORS (1):
  1. SQL injection in search - WAF blocked

==============================
```

### Benefits

- **No Duplicate Work**: The blackboard prevents re-scanning the same targets
- **Strategic Memory**: The AI learns what works and what doesn't
- **Mission Continuity**: Resume missions across sessions
- **Better Decisions**: Context-aware decision making based on accumulated knowledge
- **Progress Tracking**: Clear view of mission status at any point

---

## Integration and Workflow

### Complete Workflow Example

```python
# 1. Initialize AI with Blackboard
ai_core = EnhancedAegisAI()
await ai_core.initialize()

# 2. Start mission (blackboard is automatically loaded/created)
# Blackboard starts empty or loads from previous session

# 3. Execute reconnaissance
result = await scanner.execute_action({
    "tool": "subdomain_enumeration",
    "args": {"domain": "example.com"}
})

# 4. Facts are automatically extracted
# Blackboard updated with:
#   Facts: ["Found 10 subdomains", "api.example.com discovered"]
#   Goals: ["Test api.example.com for vulnerabilities"]

# 5. Visual reconnaissance with SoM
result = await scanner.execute_action({
    "tool": "capture_screenshot_som",
    "args": {"url": "https://example.com"}
})

# 6. AI analyzes screenshot and decides to click element #3 (login form)
result = await scanner.execute_action({
    "tool": "click_element_by_id",
    "args": {"url": "https://example.com", "element_id": 3}
})

# 7. More facts extracted and blackboard updated
# Facts: ["Login form found", "No CSRF protection on form"]
# Goals: ["Test login for SQL injection", "Test for default credentials"]

# 8. Continue mission with full context
# The AI now knows what has been discovered, what to try next,
# and what has already failed
```

### Best Practices

1. **Use Descriptive Mission IDs**
   - `MissionBlackboard(mission_id="bugcrowd_acme_corp_2024")`
   - Enables easy identification and continuation

2. **Review Blackboard Regularly**
   - Check `blackboard.get_summary()` to see mission progress
   - Identify completed goals and adjust strategy

3. **Leverage SoM for Complex UIs**
   - Use SoM when dealing with JavaScript-heavy applications
   - Essential for testing authentication and multi-step workflows

4. **Trust the Fact Extraction**
   - The Reasoning LLM is conservative and accurate
   - Facts are only added when confirmed
   - Speculative information becomes goals, not facts

5. **Clean Up Between Missions**
   - Use `blackboard.clear()` when starting a completely new target
   - Or use a different mission_id

---

## File Locations

- **Blackboard Data**: `data/blackboard_<mission_id>.json`
- **SoM Screenshots**: `data/screenshots/som_*.png`
- **Regular Screenshots**: `data/screenshots/screenshot_*.png`

---

## Testing

Run the test suite to validate the implementation:

```bash
python test_som_blackboard.py
```

This will test:
- Blackboard memory operations (add, complete, discard, persist)
- SoM method availability and signatures
- Scanner integration
- AI core integration

---

## Conclusion

The combination of Visual Grounding (SoM) and Blackboard Memory creates a powerful foundation for autonomous security testing. The AI can now:

- See and interact with web interfaces like a human
- Maintain strategic memory of mission progress
- Make context-aware decisions based on accumulated knowledge
- Avoid duplicate work and dead ends
- Navigate complex multi-step workflows

These features significantly enhance the agent's capability for comprehensive and efficient security assessments.
