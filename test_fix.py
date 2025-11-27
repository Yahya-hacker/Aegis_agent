
import asyncio
import sys
import os
from unittest.mock import MagicMock, AsyncMock

# Mock dependencies
sys.modules['agents.field_tester'] = MagicMock()
sys.modules['agents.learning_engine'] = MagicMock()
sys.modules['utils.reasoning_display'] = MagicMock()
sys.modules['utils.dynamic_tool_loader'] = MagicMock()
sys.modules['agents.scanner'] = MagicMock()
sys.modules['utils.vulnerability_analyzer'] = MagicMock()

# Mock get_reasoning_display
mock_display = MagicMock()
sys.modules['utils.reasoning_display'].get_reasoning_display.return_value = mock_display

# Mock AegisScanner
mock_scanner = AsyncMock()
sys.modules['agents.scanner'].AegisScanner.return_value = mock_scanner

# Mock AegisFieldTester
mock_field_tester = MagicMock()
mock_field_tester.enter_manual_mode = AsyncMock(return_value=[])
sys.modules['agents.field_tester'].AegisFieldTester.return_value = mock_field_tester

# Mock VulnerabilityAnalyzer
mock_vuln_analyzer = MagicMock()
mock_vuln_analyzer.prioritize_findings.return_value = [] # Return empty list to avoid more mocks
mock_vuln_analyzer.get_statistics.return_value = {
    'total': 0,
    'average_risk_score': 0,
    'by_severity': {}
}
mock_vuln_analyzer.generate_report.return_value = "Test Report"
sys.modules['utils.vulnerability_analyzer'].get_vulnerability_analyzer.return_value = mock_vuln_analyzer

# Import the module to test
from agents.conversational_agent import AegisConversation

async def test_run_autonomous_loop():
    print("Testing run_autonomous_loop_with_triage...")
    
    # Mock AI Core
    mock_ai_core = AsyncMock()
    # First action: run a tool
    # Second action: finish mission
    mock_ai_core.get_next_action_async.side_effect = [
        {
            "tool": "test_tool",
            "args": {"target": "example.com"},
            "reasoning": "Testing tool execution"
        },
        {
            "tool": "finish_mission",
            "args": {"reason": "Test complete"}
        }
    ]
    
    # Mock learning engine on ai_core to be synchronous
    mock_learning_engine = MagicMock()
    mock_learning_engine.should_avoid_action.return_value = (False, "")
    mock_ai_core.learning_engine = mock_learning_engine

    # Mock scanner execution result
    mock_scanner.execute_action.return_value = {
        "status": "success",
        "data": {"result": "success"}
    }
    
    # Mock dynamic tool loader
    mock_tool_loader = MagicMock()
    mock_tool_loader.is_tool_intrusive.return_value = False
    sys.modules['utils.dynamic_tool_loader'].get_tool_loader.return_value = mock_tool_loader
    
    # Initialize conversation
    conversation = AegisConversation(mock_ai_core)
    
    # Run the loop
    try:
        await conversation.run_autonomous_loop_with_triage("example.com", "No rules")
        print("✅ run_autonomous_loop_with_triage completed successfully")
    except Exception as e:
        print(f"❌ run_autonomous_loop_with_triage failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_run_autonomous_loop())
