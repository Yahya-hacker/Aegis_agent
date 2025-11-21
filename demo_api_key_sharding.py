#!/usr/bin/env python3
"""
Quick demonstration of API Key Sharding feature
Shows how the system works with different configurations
"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from agents.multi_llm_orchestrator import MultiLLMOrchestrator

def print_section(title):
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")

async def demo_configuration_1():
    """Demo 1: Master key only (backward compatible)"""
    print_section("DEMO 1: Classic Configuration (Master Key Only)")
    
    os.environ["OPENROUTER_API_KEY"] = "sk-master-key-abc123"
    for key in ["STRATEGIC_API_KEY", "REASONING_API_KEY", "CODE_API_KEY", "VISUAL_API_KEY"]:
        if key in os.environ:
            del os.environ[key]
    
    orchestrator = MultiLLMOrchestrator()
    await orchestrator.initialize()
    
    print("\n✅ Configuration successful!")
    print("   All 4 roles using master key - perfect for getting started!")
    print(f"   Legacy self.api_key: {orchestrator.api_key[:20]}...")

async def demo_configuration_2():
    """Demo 2: Full sharding"""
    print_section("DEMO 2: Full API Key Sharding (Maximum Control)")
    
    os.environ["OPENROUTER_API_KEY"] = "sk-master-fallback"
    os.environ["STRATEGIC_API_KEY"] = "sk-strategic-team-alpha"
    os.environ["REASONING_API_KEY"] = "sk-reasoning-team-beta"
    os.environ["CODE_API_KEY"] = "sk-code-team-gamma"
    os.environ["VISUAL_API_KEY"] = "sk-visual-shared-pool"
    
    orchestrator = MultiLLMOrchestrator()
    await orchestrator.initialize()
    
    print("\n✅ Configuration successful!")
    print("   Each role has dedicated key - perfect for cost tracking!")
    print("\n   Key Assignment:")
    for role, key in orchestrator.api_keys.items():
        print(f"      • {role:15} → {key[:25]}...")

async def demo_configuration_3():
    """Demo 3: Partial sharding"""
    print_section("DEMO 3: Partial Sharding (Hybrid Approach)")
    
    os.environ["OPENROUTER_API_KEY"] = "sk-standard-key-xyz789"
    os.environ["REASONING_API_KEY"] = "sk-premium-limited-quota"
    os.environ["CODE_API_KEY"] = "sk-code-generation-budget"
    for key in ["STRATEGIC_API_KEY", "VISUAL_API_KEY"]:
        if key in os.environ:
            del os.environ[key]
    
    orchestrator = MultiLLMOrchestrator()
    await orchestrator.initialize()
    
    print("\n✅ Configuration successful!")
    print("   Some roles isolated, others use master - flexible budgeting!")
    print("\n   Key Assignment:")
    for role, key in orchestrator.api_keys.items():
        key_type = "Specific" if "premium" in key or "budget" in key else "Master"
        print(f"      • {role:15} → {key[:30]}... ({key_type})")

async def main():
    """Run all demonstrations"""
    print("\n" + "╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "API KEY SHARDING DEMONSTRATIONS" + " " * 27 + "║")
    print("╚" + "=" * 78 + "╝")
    
    try:
        await demo_configuration_1()
        await demo_configuration_2()
        await demo_configuration_3()
        
        print("\n" + "=" * 80)
        print("  🎉 ALL DEMONSTRATIONS COMPLETED SUCCESSFULLY!")
        print("=" * 80)
        print("\n  The API Key Sharding system supports:")
        print("    ✓ Master key only (backward compatible)")
        print("    ✓ Full sharding (maximum control)")
        print("    ✓ Partial sharding (flexible approach)")
        print("\n  See API_KEY_SHARDING_GUIDE.md for detailed documentation!")
        print("=" * 80 + "\n")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        for key in ["OPENROUTER_API_KEY", "STRATEGIC_API_KEY", "REASONING_API_KEY", "CODE_API_KEY", "VISUAL_API_KEY"]:
            if key in os.environ:
                del os.environ[key]

if __name__ == "__main__":
    asyncio.run(main())
