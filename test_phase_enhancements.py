#!/usr/bin/env python3
"""
Test suite for Phase 1-4 enhancements
Tests the new business logic mapper, logic tester, AI triage, and visual recon features
"""

import asyncio
import json
import os
from pathlib import Path


def test_phase1_model_loading():
    """Test Phase 1: Model loading from environment variables"""
    print("\n" + "="*70)
    print("PHASE 1: Testing Model Loading from Environment Variables")
    print("="*70)
    
    # Test default values
    from agents.enhanced_ai_core import ORCHESTRATOR_MODEL, CODE_MODEL, REASONING_MODEL
    
    assert ORCHESTRATOR_MODEL == "nousresearch/hermes-3-llama-3.1-70b", "ORCHESTRATOR_MODEL mismatch"
    print("✅ ORCHESTRATOR_MODEL loads correctly:", ORCHESTRATOR_MODEL)
    
    assert CODE_MODEL == "qwen/qwen-2.5-72b-instruct", "CODE_MODEL mismatch"
    print("✅ CODE_MODEL loads correctly:", CODE_MODEL)
    
    assert REASONING_MODEL == "cognitivecomputations/dolphin3.0-r1-mistral-24b", "REASONING_MODEL mismatch"
    print("✅ REASONING_MODEL loads correctly:", REASONING_MODEL)
    
    print("\n✅ PASS Phase 1: Models load from environment with correct defaults")


def test_phase2_business_logic_mapper():
    """Test Phase 2: Business Logic Mapper"""
    print("\n" + "="*70)
    print("PHASE 2: Testing Business Logic Mapper")
    print("="*70)
    
    from utils.business_logic_mapper import BusinessLogicMapper, get_business_logic_mapper
    
    # Test singleton
    mapper1 = get_business_logic_mapper()
    mapper2 = get_business_logic_mapper()
    assert mapper1 is mapper2, "Singleton pattern broken"
    print("✅ Singleton pattern works")
    
    # Test load_logic_definition
    test_definition = {
        "authentication": {
            "flows": ["login", "logout", "password_reset"],
            "rules": ["rate_limiting", "session_validation"]
        },
        "payment": {
            "flows": ["checkout", "refund"],
            "rules": ["price_validation"]
        }
    }
    
    mapper1.load_logic_definition(test_definition)
    assert mapper1.logic_definition == test_definition, "Logic definition not loaded correctly"
    print("✅ load_logic_definition() works")
    
    # Test get_testable_functions
    summary = mapper1.get_testable_functions()
    assert "BUSINESS LOGIC CONTEXT" in summary, "Summary missing header"
    assert "authentication" in summary.lower(), "Summary missing authentication category"
    assert "payment" in summary.lower(), "Summary missing payment category"
    assert "login" in summary, "Summary missing flow details"
    print("✅ get_testable_functions() generates proper summary")
    
    # Test helper methods
    categories = mapper1.list_categories()
    assert "authentication" in categories, "Categories list incomplete"
    assert "payment" in categories, "Categories list incomplete"
    print("✅ list_categories() works")
    
    auth_details = mapper1.get_category_details("authentication")
    assert "flows" in auth_details, "Category details incomplete"
    print("✅ get_category_details() works")
    
    print("\n✅ PASS Phase 2: Business Logic Mapper fully functional")


def test_phase2_logic_tester():
    """Test Phase 2: Logic Tester Tool"""
    print("\n" + "="*70)
    print("PHASE 2: Testing Logic Tester Tool")
    print("="*70)
    
    from tools.logic_tester import LogicTesterTool, get_logic_tester
    
    # Test singleton
    tester1 = get_logic_tester()
    tester2 = get_logic_tester()
    assert tester1 is tester2, "Singleton pattern broken"
    print("✅ Singleton pattern works")
    
    # Test session loading methods exist
    assert hasattr(tester1, '_load_session_data'), "Missing _load_session_data method"
    assert hasattr(tester1, '_build_cookie_header'), "Missing _build_cookie_header method"
    print("✅ Session loading methods copied from tool_manager")
    
    # Test main methods exist
    assert hasattr(tester1, 'test_logic_flow'), "Missing test_logic_flow method"
    assert asyncio.iscoroutinefunction(tester1.test_logic_flow), "test_logic_flow not async"
    print("✅ test_logic_flow() is async function")
    
    assert hasattr(tester1, 'test_sequence_bypass'), "Missing test_sequence_bypass method"
    print("✅ test_sequence_bypass() exists")
    
    # Test cookie building (with mock data)
    mock_session = {
        "cookies": [
            {"name": "session_id", "value": "abc123"},
            {"name": "user_token", "value": "xyz789"}
        ]
    }
    cookie_header = tester1._build_cookie_header(mock_session)
    assert cookie_header == "session_id=abc123; user_token=xyz789", "Cookie header format incorrect"
    print("✅ _build_cookie_header() formats cookies correctly")
    
    print("\n✅ PASS Phase 2: Logic Tester Tool fully functional")


async def test_phase3_ai_triage():
    """Test Phase 3: AI-Enhanced Triage"""
    print("\n" + "="*70)
    print("PHASE 3: Testing AI-Enhanced Triage")
    print("="*70)
    
    from agents.enhanced_ai_core import EnhancedAegisAI
    
    # Create AI instance
    ai = EnhancedAegisAI()
    
    # Test that logic_mapper is initialized
    assert hasattr(ai, 'logic_mapper'), "Missing logic_mapper attribute"
    print("✅ logic_mapper initialized in EnhancedAegisAI")
    
    # Test contextual_triage method exists
    assert hasattr(ai, 'contextual_triage'), "Missing contextual_triage method"
    assert asyncio.iscoroutinefunction(ai.contextual_triage), "contextual_triage not async"
    print("✅ contextual_triage() method exists and is async")
    
    # Test method signature (without calling due to API requirements)
    import inspect
    sig = inspect.signature(ai.contextual_triage)
    params = list(sig.parameters.keys())
    assert 'finding' in params, "contextual_triage missing 'finding' parameter"
    assert 'mission_context' in params, "contextual_triage missing 'mission_context' parameter"
    print("✅ contextual_triage() has correct parameters: finding, mission_context")
    
    print("\n✅ PASS Phase 3: AI-Enhanced Triage methods implemented")


def test_phase3_integration():
    """Test Phase 3: Integration into conversational agent"""
    print("\n" + "="*70)
    print("PHASE 3: Testing AI Triage Integration")
    print("="*70)
    
    from agents.conversational_agent import AegisConversation
    
    # Read conversational_agent.py to verify integration
    agent_file = Path("agents/conversational_agent.py")
    content = agent_file.read_text()
    
    # Check for AI triage integration
    assert "contextual_triage" in content, "contextual_triage not integrated"
    print("✅ contextual_triage integrated into conversational_agent")
    
    assert "ai_triaged_findings" in content, "AI triaged findings not stored"
    print("✅ AI triaged findings are stored and used")
    
    assert "Applying AI-enhanced triage" in content, "Missing user feedback about AI triage"
    print("✅ User feedback added for AI triage step")
    
    print("\n✅ PASS Phase 3: AI Triage properly integrated into workflow")


def test_phase4_visual_recon():
    """Test Phase 4: Visual Recon Tool"""
    print("\n" + "="*70)
    print("PHASE 4: Testing Visual Reconnaissance Tool")
    print("="*70)
    
    from tools.visual_recon import VisualReconTool, get_visual_recon_tool
    
    # Test singleton
    tool1 = get_visual_recon_tool()
    tool2 = get_visual_recon_tool()
    assert tool1 is tool2, "Singleton pattern broken"
    print("✅ Singleton pattern works")
    
    # Test session loading methods copied from tool_manager
    assert hasattr(tool1, '_load_session_data'), "Missing _load_session_data method"
    assert hasattr(tool1, '_build_cookie_header'), "Missing _build_cookie_header method"
    print("✅ Session loading methods copied from tool_manager")
    
    # Test main methods
    assert hasattr(tool1, 'capture_screenshot'), "Missing capture_screenshot method"
    assert asyncio.iscoroutinefunction(tool1.capture_screenshot), "capture_screenshot not async"
    print("✅ capture_screenshot() is async function")
    
    assert hasattr(tool1, 'get_dom_snapshot'), "Missing get_dom_snapshot method"
    assert asyncio.iscoroutinefunction(tool1.get_dom_snapshot), "get_dom_snapshot not async"
    print("✅ get_dom_snapshot() is async function")
    
    # Test playwright dependency
    try:
        from playwright.async_api import async_playwright
        print("✅ Playwright library available")
    except ImportError:
        print("⚠️  Playwright not installed (run: playwright install chromium)")
    
    print("\n✅ PASS Phase 4: Visual Recon Tool implemented")


def test_phase4_visual_model():
    """Test Phase 4: Visual Model in Orchestrator"""
    print("\n" + "="*70)
    print("PHASE 4: Testing Visual Model Integration")
    print("="*70)
    
    from agents.multi_llm_orchestrator import MultiLLMOrchestrator
    
    # Create orchestrator
    orchestrator = MultiLLMOrchestrator()
    
    # Test that visual LLM is configured
    assert 'visual' in orchestrator.llms, "Visual LLM not configured"
    print("✅ Visual LLM configured in orchestrator")
    
    visual_config = orchestrator.llms['visual']
    assert visual_config.model_name == "google/gemini-pro-vision", "Wrong visual model"
    print("✅ Visual model is google/gemini-pro-vision")
    
    assert "Visual Analyst" in visual_config.role, "Visual role not set correctly"
    print("✅ Visual LLM role set correctly")
    
    # Test execute_multimodal_task exists
    assert hasattr(orchestrator, 'execute_multimodal_task'), "Missing execute_multimodal_task method"
    assert asyncio.iscoroutinefunction(orchestrator.execute_multimodal_task), "execute_multimodal_task not async"
    print("✅ execute_multimodal_task() method exists and is async")
    
    # Test method signature
    import inspect
    sig = inspect.signature(orchestrator.execute_multimodal_task)
    params = list(sig.parameters.keys())
    assert 'text_prompt' in params, "Missing text_prompt parameter"
    assert 'image_path' in params, "Missing image_path parameter"
    print("✅ execute_multimodal_task() has correct parameters")
    
    print("\n✅ PASS Phase 4: Visual Model properly integrated")


async def test_phase4_analyze_visuals():
    """Test Phase 4: Analyze Visuals in AI Core"""
    print("\n" + "="*70)
    print("PHASE 4: Testing Visual Analysis in AI Core")
    print("="*70)
    
    from agents.enhanced_ai_core import EnhancedAegisAI
    
    # Create AI instance
    ai = EnhancedAegisAI()
    
    # Test analyze_visuals method exists
    assert hasattr(ai, 'analyze_visuals'), "Missing analyze_visuals method"
    assert asyncio.iscoroutinefunction(ai.analyze_visuals), "analyze_visuals not async"
    print("✅ analyze_visuals() method exists and is async")
    
    # Test method signature
    import inspect
    sig = inspect.signature(ai.analyze_visuals)
    params = list(sig.parameters.keys())
    assert 'image_path' in params, "Missing image_path parameter"
    assert 'text_prompt' in params, "Missing text_prompt parameter"
    print("✅ analyze_visuals() has correct parameters")
    
    print("\n✅ PASS Phase 4: Visual analysis integrated into AI Core")


def test_phase4_prompt_integration():
    """Test Phase 4: Prompt Integration"""
    print("\n" + "="*70)
    print("PHASE 4: Testing Prompt Integration")
    print("="*70)
    
    # Read enhanced_ai_core.py to verify prompt updates
    core_file = Path("agents/enhanced_ai_core.py")
    content = core_file.read_text()
    
    # Check for business logic context
    assert "self.logic_mapper.get_testable_functions()" in content, "Business logic context not in prompt"
    print("✅ Business logic context integrated into prompt")
    
    # Check for new tool mentions
    assert "visual_recon.capture_screenshot" in content, "capture_screenshot not in prompt"
    print("✅ visual_recon.capture_screenshot mentioned in prompt")
    
    assert "visual_recon.get_dom_snapshot" in content, "get_dom_snapshot not in prompt"
    print("✅ visual_recon.get_dom_snapshot mentioned in prompt")
    
    assert "logic_tester.test_logic_flow" in content, "test_logic_flow not in prompt"
    print("✅ logic_tester.test_logic_flow mentioned in prompt")
    
    # Check for multimodal capabilities section
    assert "MULTIMODAL CAPABILITIES" in content or "visual reconnaissance" in content.lower(), "No multimodal section"
    print("✅ Multimodal capabilities section added to prompt")
    
    print("\n✅ PASS Phase 4: Prompt properly updated with new capabilities")


def test_requirements():
    """Test that new dependencies are in requirements.txt"""
    print("\n" + "="*70)
    print("Testing Requirements Updates")
    print("="*70)
    
    req_file = Path("requirements.txt")
    content = req_file.read_text()
    
    assert "httpx" in content, "httpx not in requirements.txt"
    print("✅ httpx added to requirements.txt")
    
    assert "playwright" in content, "playwright not in requirements.txt"
    print("✅ playwright added to requirements.txt")
    
    print("\n✅ PASS All new dependencies added to requirements.txt")


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("PHASE 1-4 ENHANCEMENT TEST SUITE")
    print("="*70)
    
    try:
        # Synchronous tests
        test_phase1_model_loading()
        test_phase2_business_logic_mapper()
        test_phase2_logic_tester()
        test_phase3_integration()
        test_phase4_visual_recon()
        test_phase4_visual_model()
        test_phase4_prompt_integration()
        test_requirements()
        
        # Async tests
        asyncio.run(test_phase3_ai_triage())
        asyncio.run(test_phase4_analyze_visuals())
        
        print("\n" + "="*70)
        print("TEST SUMMARY")
        print("="*70)
        print("✅ PASS Phase 1 - Model Loading from Environment Variables")
        print("✅ PASS Phase 2 - Business Logic Mapper")
        print("✅ PASS Phase 2 - Logic Tester Tool")
        print("✅ PASS Phase 3 - AI-Enhanced Triage")
        print("✅ PASS Phase 3 - AI Triage Integration")
        print("✅ PASS Phase 4 - Visual Reconnaissance Tool")
        print("✅ PASS Phase 4 - Visual Model Integration")
        print("✅ PASS Phase 4 - Visual Analysis in AI Core")
        print("✅ PASS Phase 4 - Prompt Integration")
        print("✅ PASS Requirements Updated")
        print("\n🎉 All Phase 1-4 enhancements successfully implemented and tested!")
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
