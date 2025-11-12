#!/usr/bin/env python3
"""
Example usage of Multi-LLM Enhanced Aegis AI
Demonstrates how to use the three specialized LLMs
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.enhanced_ai_core import EnhancedAegisAI
from agents.learning_engine import AegisLearningEngine

async def example_triage():
    """Example: Using Llama 70B for mission triage"""
    print("\n" + "="*70)
    print("EXAMPLE 1: Mission Triage (Llama 70B)")
    print("="*70)
    
    ai = EnhancedAegisAI()
    await ai.initialize()
    
    # Simulate a conversation
    conversation = [
        {"role": "user", "content": "I want to test example.com"},
        {"role": "assistant", "content": "What are the bug bounty program rules?"},
        {"role": "user", "content": "In scope: *.example.com, example.org. Out of scope: admin.example.com. No DDoS, no social engineering."}
    ]
    
    result = await ai.triage_mission(conversation)
    print(f"Triage result: {result}")

async def example_vulnerability_analysis():
    """Example: Using Mixtral 8x7B for vulnerability analysis"""
    print("\n" + "="*70)
    print("EXAMPLE 2: Next Action Decision (Mixtral 8x7B)")
    print("="*70)
    
    ai = EnhancedAegisAI()
    await ai.initialize()
    
    # Simulate agent memory
    bbp_rules = """
    TARGET: example.com
    RULES: 
    - In scope: *.example.com
    - No DDoS attacks
    - Report responsibly
    """
    
    agent_memory = [
        {"type": "mission", "content": "Starting reconnaissance on example.com"},
        {"type": "observation", "content": "Found 5 subdomains: www, api, blog, staging, dev"},
        {"type": "observation", "content": "Port scan on www.example.com found: 80, 443 open"},
    ]
    
    action = ai.get_next_action(bbp_rules, agent_memory)
    print(f"Next action: {action}")

async def example_code_analysis():
    """Example: Using Qwen-coder for code analysis"""
    print("\n" + "="*70)
    print("EXAMPLE 3: Code Analysis (Qwen-coder)")
    print("="*70)
    
    ai = EnhancedAegisAI()
    await ai.initialize()
    
    vulnerable_code = """
    def login(username, password):
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        cursor.execute(query)
        return cursor.fetchone()
    """
    
    result = await ai.analyze_code(
        code=vulnerable_code,
        context="Python login function found in web application"
    )
    
    print(f"Analysis from {result['model_used']}:")
    print(result['analysis'])

async def example_payload_generation():
    """Example: Using Qwen-coder for payload generation"""
    print("\n" + "="*70)
    print("EXAMPLE 4: Payload Generation (Qwen-coder)")
    print("="*70)
    
    ai = EnhancedAegisAI()
    await ai.initialize()
    
    result = await ai.generate_payload(
        vulnerability_type="SQL Injection",
        target_info={
            "url": "https://example.com/login",
            "parameter": "username",
            "method": "POST",
            "database": "MySQL"
        },
        constraints=["Must bypass basic WAF", "Time-based blind"]
    )
    
    print(f"Payloads from {result['model_used']}:")
    print(result['payloads'])

async def example_collaborative_analysis():
    """Example: Using all three LLMs for collaborative analysis"""
    print("\n" + "="*70)
    print("EXAMPLE 5: Collaborative Analysis (All 3 LLMs)")
    print("="*70)
    
    ai = EnhancedAegisAI()
    await ai.initialize()
    
    findings = [
        {
            "type": "SQL Injection",
            "severity": "critical",
            "location": "https://example.com/login?username=test",
            "description": "Parameter 'username' is vulnerable to SQL injection"
        },
        {
            "type": "XSS",
            "severity": "high",
            "location": "https://example.com/search?q=test",
            "description": "Search parameter reflects user input without sanitization"
        },
        {
            "type": "Information Disclosure",
            "severity": "medium",
            "location": "https://example.com/.git/config",
            "description": "Git configuration file exposed"
        }
    ]
    
    result = await ai.collaborative_vulnerability_assessment(
        target="example.com",
        findings=findings
    )
    
    print("\n📊 Strategic Assessment (Llama 70B):")
    print(result['strategic_assessment'][:200] + "...")
    
    print("\n🎯 Vulnerability Analysis (Mixtral 8x7B):")
    print(result['vulnerability_analysis'][:200] + "...")
    
    print("\n💻 Technical Recommendations (Qwen-coder):")
    print(result['technical_recommendations'][:200] + "...")

async def main():
    """Run all examples"""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║          Multi-LLM Aegis AI - Usage Examples                     ║
║                                                                  ║
║  Demonstrating the three specialized LLMs:                      ║
║  • Llama 70B: Strategic planning                                ║
║  • Mixtral 8x7B: Vulnerability analysis                         ║
║  • Qwen-coder: Code analysis & payload generation               ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    
    examples = [
        ("Mission Triage", example_triage),
        ("Vulnerability Analysis", example_vulnerability_analysis),
        ("Code Analysis", example_code_analysis),
        ("Payload Generation", example_payload_generation),
        ("Collaborative Analysis", example_collaborative_analysis),
    ]
    
    for name, example_func in examples:
        try:
            await example_func()
        except Exception as e:
            print(f"\n❌ Error in {name}: {e}")
            import traceback
            traceback.print_exc()
        
        # Wait a bit between examples to avoid rate limiting
        await asyncio.sleep(2)
    
    print("\n" + "="*70)
    print("✅ All examples completed!")
    print("="*70)

if __name__ == "__main__":
    asyncio.run(main())
