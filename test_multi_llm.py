#!/usr/bin/env python3
"""
Test script for Multi-LLM orchestrator
Validates that the three LLMs can be initialized and called
"""

import asyncio
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from agents.multi_llm_orchestrator import MultiLLMOrchestrator

async def test_orchestrator():
    """Test the multi-LLM orchestrator"""
    print("=" * 70)
    print("Testing Multi-LLM Orchestrator")
    print("=" * 70)
    
    # Check for API key
    api_key = os.environ.get("TOGETHER_API_KEY")
    if not api_key:
        print("❌ TOGETHER_API_KEY environment variable not set")
        print("Please set it: export TOGETHER_API_KEY='your_key_here'")
        return False
    
    print(f"✅ API Key found: {api_key[:10]}...")
    
    try:
        # Initialize orchestrator
        print("\n📋 Initializing orchestrator...")
        orchestrator = MultiLLMOrchestrator()
        await orchestrator.initialize()
        print("✅ Orchestrator initialized successfully")
        
        # Test LLM selection
        print("\n🎯 Testing LLM selection...")
        test_tasks = [
            ('mission_planning', 'strategic'),
            ('vulnerability_analysis', 'vulnerability'),
            ('payload_generation', 'coder'),
            ('triage', 'strategic'),
            ('next_action', 'vulnerability'),
            ('code_analysis', 'coder'),
        ]
        
        for task, expected_llm in test_tasks:
            selected = orchestrator.select_llm(task)
            status = "✅" if selected == expected_llm else "❌"
            print(f"  {status} {task} → {selected} (expected: {expected_llm})")
        
        # Test calling each LLM (simple test)
        print("\n🧪 Testing LLM calls...")
        
        test_prompts = {
            'strategic': {
                'system': "You are a strategic planner.",
                'user': "What should be the first step in testing example.com? Answer in one sentence."
            },
            'vulnerability': {
                'system': "You are a vulnerability analyst.",
                'user': "What are the most common web vulnerabilities? List 3 briefly."
            },
            'coder': {
                'system': "You are a code analyst.",
                'user': "Write a simple Python function to validate email format. Keep it short."
            }
        }
        
        for llm_type, prompts in test_prompts.items():
            print(f"\n  Testing {orchestrator.llms[llm_type].role}...")
            try:
                response = await orchestrator.call_llm(
                    llm_type=llm_type,
                    messages=[
                        {"role": "system", "content": prompts['system']},
                        {"role": "user", "content": prompts['user']}
                    ],
                    temperature=0.7,
                    max_tokens=256
                )
                
                content_preview = response['content'][:100] + "..." if len(response['content']) > 100 else response['content']
                print(f"  ✅ Response received: {content_preview}")
                print(f"     Model: {response['model']}")
                print(f"     Tokens used: {response.get('usage', {})}")
                
            except Exception as e:
                print(f"  ❌ Error calling {llm_type}: {e}")
                return False
        
        # Test collaborative analysis
        print("\n🤝 Testing collaborative analysis...")
        try:
            results = await orchestrator.collaborative_analysis(
                context="Testing example.com for vulnerabilities",
                strategic_question="What should be our testing strategy?",
                vulnerability_question="What vulnerabilities should we look for?",
                coding_question="What tools should we use?"
            )
            
            print("  ✅ Collaborative analysis completed:")
            for llm_type, response in results.items():
                preview = response['content'][:80] + "..." if len(response['content']) > 80 else response['content']
                print(f"    • {llm_type}: {preview}")
        
        except Exception as e:
            print(f"  ❌ Error in collaborative analysis: {e}")
            return False
        
        print("\n" + "=" * 70)
        print("✅ All tests passed successfully!")
        print("=" * 70)
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    """Main entry point"""
    success = await test_orchestrator()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    asyncio.run(main())
