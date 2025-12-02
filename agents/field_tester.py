# agents/field_tester.py
# --- VERSION 8.0 - Secure headless mode with timeout ---
"""
Aegis AI Field Tester
Handles manual verification of findings with headless support
"""

import json
import sys
from typing import Dict, List, Any, Optional
import asyncio
# Import AegisLearningEngine for type hinting
from agents.learning_engine import AegisLearningEngine 

# Default timeout for user input (in seconds)
# 60 seconds is a good balance between giving time to think and avoiding blocks
DEFAULT_INPUT_TIMEOUT = 60


class AegisFieldTester:
    """
    Field tester for manual verification of findings
    Supports headless environments (Docker/CI) with automatic detection
    """
    
    def __init__(self, learning_engine: AegisLearningEngine, input_timeout: int = DEFAULT_INPUT_TIMEOUT):
        """
        Initialize the field tester
        
        Args:
            learning_engine: Learning engine instance
            input_timeout: Timeout for user input in seconds
        """
        self.learning_engine = learning_engine
        self.verification_queue: List[Dict] = []
        self.input_timeout = input_timeout
    
    def _is_interactive(self) -> bool:
        """Check if we are in an interactive environment"""
        return sys.stdin.isatty()
        
    async def enter_manual_mode(self, findings: List[Dict]) -> List[Dict]:
        """
        Enters manual test mode for verification.
        In headless mode, automatically switches to auto-verification mode.
        """
        # Check if we are in headless mode
        if not self._is_interactive():
            print("\n⚠️  Headless mode detected (no interactive terminal)")
            print("   Switching to auto-verification mode...")
            return await self._auto_verify_findings(findings)
        
        print("\n🔍 ENTERING MANUAL VERIFICATION MODE")
        print("   Help me learn by validating findings.\n")
        
        verified_findings: List[Dict] = []
        
        for finding in findings:
            print(f"\n🎯 Finding : {finding.get('type', 'Unknown')}")
            print(f"📍 Target : {finding.get('target', 'Unknown')}")
            print(f"📝 Details : {finding.get('description', 'No description')}")
            
            response = await self._get_user_input_with_timeout(
                "❓ Is this a REAL vulnerability? (y/n/skip/info): "
            )
            
            if response is None:
                # Timeout reached - skip automatically
                print("⏰ Timeout reached. Finding ignored.")
                continue
            
            result = await self._process_user_response(response, finding, verified_findings)
            if result == 'continue':
                continue
            elif result == 'break':
                break
        
        return verified_findings
    
    async def _get_user_input_with_timeout(self, prompt: str) -> Optional[str]:
        """
        Get user input with a timeout
        
        Args:
            prompt: The prompt to display
            
        Returns:
            The user response or None in case of timeout/error
        """
        try:
            # Use asyncio.wait_for with timeout
            response = await asyncio.wait_for(
                asyncio.to_thread(input, prompt),
                timeout=self.input_timeout
            )
            return response.lower().strip()
        except asyncio.TimeoutError:
            return None
        except EOFError:
            # This happens in headless environments
            print("\n⚠️  EOFError detected - non-interactive environment")
            return None
        except Exception as e:
            print(f"\n⚠️  Error reading input: {e}")
            return None
    
    async def _process_user_response(
        self, 
        response: str, 
        finding: Dict, 
        verified_findings: List[Dict]
    ) -> str:
        """
        Process user response
        
        Returns:
            'continue' to move to the next finding
            'break' to stop the loop
            'retry' to ask for new input
        """
        while True:
            if response in ['y', 'yes', 'o', 'oui']:
                finding['verified'] = True
                finding['false_positive'] = False
                verified_findings.append(finding)
                # Learning
                self.learning_engine.save_finding(finding, is_false_positive=False)
                print("✅ Marked as TRUE VULNERABILITY. Lesson learned.")
                return 'continue'
                
            elif response in ['n', 'no', 'non']:
                finding['verified'] = False
                finding['false_positive'] = True
                # Learning
                self.learning_engine.save_finding(finding, is_false_positive=True)
                print("❌ Marked as FALSE POSITIVE. Lesson learned.")
                return 'continue'
                
            elif response == 'skip':
                print("⏭️  Finding ignored.")
                return 'continue'
                
            elif response == 'info':
                self._show_verification_help(finding)
                # Ask for new input
                new_response = await self._get_user_input_with_timeout(
                    "❓ Is this a REAL vulnerability? (y/n/skip/info): "
                )
                if new_response is None:
                    return 'continue'
                response = new_response
                continue
                
            elif response in ['q', 'quit', 'exit']:
                print("🚪 Exiting verification mode.")
                return 'break'
                
            else:
                print("⚠️  Please enter y, n, skip, info or q to quit")
                new_response = await self._get_user_input_with_timeout(
                    "❓ Is this a REAL vulnerability? (y/n/skip/info): "
                )
                if new_response is None:
                    return 'continue'
                response = new_response
    
    async def _auto_verify_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Automatic verification mode for headless environments
        Marks all findings as requiring later verification
        """
        print(f"\n📋 Processing {len(findings)} findings in automatic mode...")
        
        results: List[Dict] = []
        for finding in findings:
            # In automatic mode, mark as "pending verification"
            finding['verified'] = False
            finding['auto_processed'] = True
            finding['needs_manual_review'] = True
            results.append(finding)
            
            print(f"   📝 {finding.get('type', 'Unknown')}: marked for later review")
        
        print(f"\n✅ {len(results)} findings marked for later manual review")
        return results
    
    def _show_verification_help(self, finding: Dict):
        """Displays verification help."""
        print(f"""
🔍 VERIFICATION HELP for {finding.get('type', 'Unknown')}:
   
   Check the following points:
   - Can you reproduce the problem?
   - Does it have a real security impact?
   - Is it in scope?
   - Is there a clear exploitation path?
   
   Common false positives:
   - Static content triggering scanners.
   - Default pages with no real impact.
   - Theoretical vulnerabilities without practical exploit.
   
   Available commands:
   - y/yes : Mark as true vulnerability
   - n/no  : Mark as false positive
   - skip  : Ignore this finding
   - info  : Show this help
   - q     : Quit verification mode
        """)

