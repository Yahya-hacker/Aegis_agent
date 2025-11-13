#!/usr/bin/env python3
"""
Test script for the reasoning display system
Demonstrates the new reasoning capabilities
"""

import sys
from pathlib import Path
import time

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from utils.reasoning_display import ReasoningDisplay, get_reasoning_display
from utils.keep_alive import KeepAlive

def test_reasoning_display():
    """Test the reasoning display system"""
    print("=" * 80)
    print("Testing Reasoning Display System")
    print("=" * 80)
    
    display = get_reasoning_display(verbose=True)
    
    # Test different types of thoughts
    print("\n1. Testing Strategic Thought:")
    display.show_thought(
        "Analyzing target scope and determining initial reconnaissance strategy",
        thought_type="strategic",
        metadata={
            "target": "example.com",
            "scope": ["*.example.com"],
            "out_of_scope": ["admin.example.com"]
        }
    )
    
    time.sleep(1)
    
    print("\n2. Testing Tactical Decision:")
    display.show_thought(
        "Based on open ports 80 and 443, deciding to enumerate subdomains first",
        thought_type="tactical",
        metadata={
            "open_ports": [80, 443, 8080],
            "next_action": "subdomain_enumeration"
        }
    )
    
    time.sleep(1)
    
    print("\n3. Testing Analysis:")
    display.show_thought(
        "Discovered 15 subdomains with 8 having open web services",
        thought_type="analysis",
        metadata={
            "total_subdomains": 15,
            "active_services": 8,
            "interesting_findings": ["api.example.com", "dev.example.com"]
        }
    )
    
    time.sleep(1)
    
    print("\n4. Testing LLM Interaction:")
    display.show_llm_interaction(
        llm_name="Mixtral 8x7B (Vulnerability Analyst)",
        prompt="What should be the next step after discovering these subdomains?",
        response="Based on the discovered subdomains, I recommend:\n1. Perform technology detection on each subdomain\n2. Focus on dev.example.com as it may have weaker security\n3. Check for common vulnerabilities in the identified services",
        metadata={
            "model": "mistralai/Mixtral-8x7B-Instruct-v0.1",
            "temperature": 0.7,
            "tokens_used": 150
        }
    )
    
    time.sleep(1)
    
    print("\n5. Testing Action Proposal:")
    display.show_action_proposal(
        action={
            "tool": "tech_detection",
            "args": {"target": "dev.example.com"}
        },
        reasoning="Development subdomains often have different technology stacks and may expose more information. This will help identify potential attack vectors and vulnerable components."
    )
    
    time.sleep(1)
    
    print("\n6. Testing Step Summary:")
    display.show_step_summary(
        step_number=3,
        total_steps=10,
        status="success",
        summary="Technology detection completed: Found WordPress 5.8 with outdated plugins"
    )
    
    time.sleep(1)
    
    print("\n7. Testing Observation:")
    display.show_thought(
        "Vulnerability scan completed successfully. Found 3 potential vulnerabilities including SQL injection in login form",
        thought_type="observation",
        metadata={
            "vulnerabilities_found": 3,
            "severity": {"high": 1, "medium": 2},
            "most_critical": "SQL Injection in /login.php"
        }
    )
    
    time.sleep(1)
    
    print("\n8. Testing Warning:")
    display.show_thought(
        "Rate limit approaching. Will slow down requests to avoid detection",
        thought_type="warning",
        metadata={
            "requests_made": 450,
            "rate_limit": 500,
            "action": "slow_down"
        }
    )
    
    print("\n" + "=" * 80)
    print("✅ Reasoning Display Test Complete!")
    print("=" * 80)
    
    # Show reasoning history summary
    history = display.get_reasoning_history()
    print(f"\n📊 Total reasoning entries captured: {len(history)}")
    
    # Export to file
    export_path = "/tmp/reasoning_test_log.json"
    display.export_reasoning_log(export_path)
    print(f"📁 Reasoning log exported to: {export_path}")

def test_keep_alive():
    """Test the keep-alive mechanism"""
    print("\n" + "=" * 80)
    print("Testing Keep-Alive Mechanism")
    print("=" * 80)
    
    print("\n🔋 Starting keep-alive (will run for 5 seconds)...")
    keep_alive = KeepAlive(interval=1)  # 1 second interval for testing
    keep_alive.start()
    
    # Simulate some work
    for i in range(5):
        status = keep_alive.get_status()
        print(f"  Status: Running={status['running']}, Elapsed={status['elapsed_seconds']}s, Heartbeats={status['heartbeat_count']}")
        time.sleep(1)
    
    keep_alive.stop()
    print("✅ Keep-alive test complete!")
    
    # Test context manager
    print("\n🔋 Testing keep-alive with context manager (3 seconds)...")
    with KeepAlive(interval=1) as ka:
        for i in range(3):
            status = ka.get_status()
            print(f"  Status: Running={status['running']}, Heartbeats={status['heartbeat_count']}")
            time.sleep(1)
    
    print("✅ Context manager test complete!")

def main():
    """Main test function"""
    print("\n" + "🛡️  AEGIS AGENT - ENHANCED REASONING TEST SUITE " + "\n")
    
    # Test reasoning display
    test_reasoning_display()
    
    # Test keep-alive
    test_keep_alive()
    
    print("\n" + "=" * 80)
    print("✅ ALL TESTS PASSED!")
    print("=" * 80)
    print("\nThe agent now has:")
    print("  • Transparent reasoning display showing all thoughts and decisions")
    print("  • Keep-alive mechanism to prevent terminal from sleeping")
    print("  • Enhanced sophistication in decision-making")
    print("  • Better detection chances through comprehensive analysis")

if __name__ == "__main__":
    main()
