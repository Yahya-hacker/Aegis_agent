#!/usr/bin/env python3
"""
AEGIS AI - AUTONOMOUS PENTEST AGENT (V8)
Main entry point with robust logging and improved error handling
"""

import asyncio
import sys
import os
import logging
from pathlib import Path

# For env
from dotenv import load_dotenv
load_dotenv()  # Loads variables from .env file

# Get script directory for robust paths
SCRIPT_DIR = Path(__file__).parent.resolve()

# Ensure logs directory exists
LOGS_DIR = SCRIPT_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

# Logging configuration (critical for debugging)
# Use path relative to script, not CWD
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOGS_DIR / 'aegis_agent.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

print(f"📝 Logging initialized at: {LOGS_DIR / 'aegis_agent.log'}")
                                             
logger = logging.getLogger(__name__)

# Adds project root to PYTHONPATH
sys.path.insert(0, str(SCRIPT_DIR))

async def main():
    """Main entry point for the new autonomous architecture."""
    
    # Import NEW components
    try:
        from agents.enhanced_ai_core import EnhancedAegisAI
        from agents.conversational_agent import AegisConversation
        from agents.learning_engine import AegisLearningEngine
        from utils.keep_alive import start_keep_alive, stop_keep_alive
        from utils.dynamic_tool_loader import get_tool_loader_async
    except ImportError as e:
        logger.error(f"Critical import error : {e}")
        print(f"❌ Error: Ensure your files are in the 'agents' folder.")
        sys.exit(1)

    print("🚀 Starting Aegis AI Autonomous Agent with Unified LLM Architecture...")
    print("📋 LLM Configuration (v9.0 - Single LLM Mode):")
    print("   • Main LLM (DeepSeek R1): Strategic planning, vulnerability analysis, code analysis, reasoning")
    print("   • Visual LLM: Screenshot and image analysis only")
    print("   ℹ️  Configure via MAIN_MODEL or DEEPSEEK_MODEL environment variable")

    # Run dependency checks
    from utils.dependency_check import check_dependencies
    if not check_dependencies():
        print("❌ Startup cancelled due to missing dependencies.")
        sys.exit(1)
    
    # Initialize dynamic tool loader
    print("\n🔧 Initializing dynamic tool arsenal...")
    tool_loader = await get_tool_loader_async()
    stats = tool_loader.get_statistics()
    print(f"   • {stats['available_tools']}/{stats['total_tools']} tools available")
    print(f"   • {stats['intrusive_tools']} intrusive tools")
    print(f"   • {stats['non_intrusive_tools']} non-intrusive tools")
    print(f"   • Categories: {', '.join(stats['categories'])}")
    
    # Start keep-alive mechanism to prevent terminal sleep
    keep_alive = start_keep_alive(interval=60)
    print("\n🔋 Keep-alive mechanism activated (prevents terminal sleep)")
    
    # Initialize components
    learning_engine = None
    ai_core = None
    conversation = None
    
    try:
        # 1. Initialize learning engine
        learning_engine = AegisLearningEngine()
        
        # 2. Initialize Multi-LLM Brain (EnhancedAegisAI)
        ai_core = EnhancedAegisAI(learning_engine)
        await ai_core.initialize()
        
        # 3. Initialize Orchestrator (AegisConversation)
        # Injecting the brain into the orchestrator
        conversation = AegisConversation(ai_core)
        
        # 4. Start conversation loop
        # The orchestrator takes control
        await conversation.start()
        
    except KeyboardInterrupt:
        print("\n\n🛡️  Aegis AI session terminated by user.")
    except Exception as e:
        logger.error(f"❌ Critical startup error: {e}", exc_info=True)
        print(f"❌ A fatal error occurred: {e}")
        print(f"💡 Check '{LOGS_DIR / 'aegis_agent.log'}' for details.")
        return 1  # Return error code
    finally:
        # Cleanup: Stop keep-alive mechanism
        try:
            stop_keep_alive()
            print("🔋 Keep-alive mechanism stopped")
        except Exception as e:
            logger.error(f"Error stopping keep-alive: {e}")
        
        # Cleanup: Close database connections
        try:
            from utils.database_manager import get_database
            db = get_database()
            db.close()
            logger.info("Database connection closed")
        except Exception as e:
            logger.error(f"Error closing database: {e}")
        
        # Cleanup: Save pending patterns
        try:
            if learning_engine:
                learning_engine.analyze_patterns()
                logger.info("Learning patterns saved")
        except Exception as e:
            logger.error(f"Error saving patterns: {e}")
        
        print("\n🛡️  Cleanup complete. Aegis AI stopping cleanly.")
    
    return 0  # Success

if __name__ == "__main__":
    # Ensure webdriver-manager has permissions (if needed)
    # os.environ['WDM_SSL_VERIFY'] = '0' # Uncomment if you have SSL errors
    
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n🛡️  Aegis AI interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Unhandled fatal error: {e}", exc_info=True)
        print(f"\n❌ Unhandled fatal error: {e}")
        print(f"💡 Check '{LOGS_DIR / 'aegis_agent.log'}' for details.")
        sys.exit(1)
