#!/usr/bin/env python3
"""
AEGIS AI SECURITY AGENT
Advanced AI-powered penetration testing assistant
"""

import asyncio
import sys
import os

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from agents.main_agent import AdvancedAegisAI

async def main():
    """Main entry point for Aegis AI"""
    print("🚀 Starting Aegis AI Security Agent...")
    
    try:
        # Initialize the AI agent
        agent = AdvancedAegisAI()
        
        # Start interactive conversation
        await agent.conversation.chat_interface()
        
    except KeyboardInterrupt:
        print("\n\n🛡️  Aegis AI session terminated by user.")
    except Exception as e:
        print(f"❌ Error starting Aegis AI: {e}")
        print("💡 Make sure all dependencies are installed and files are in place.")

if __name__ == "__main__":
    asyncio.run(main())