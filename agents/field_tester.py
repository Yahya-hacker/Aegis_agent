import json
from typing import Dict, List, Any

class AegisFieldTester:
    def __init__(self):
        self.false_positive_patterns = []
        self.verification_queue = []
        
    async def enter_manual_mode(self, findings: List[Dict]) -> List[Dict]:
        """Enter manual testing mode for verification"""
        print("\n🔍 ENTERING MANUAL TESTING MODE")
        print("   I'll help you verify findings and eliminate false positives\n")
        
        verified_findings = []
        
        for finding in findings:
            print(f"\n🎯 Finding: {finding.get('type', 'Unknown')}")
            print(f"📍 Target: {finding.get('target', 'Unknown')}")
            print(f"📝 Details: {finding.get('description', 'No description')}")
            
            # Ask user for verification
            while True:
                response = input("❓ Is this a true vulnerability? (y/n/skip/info): ").lower().strip()
                
                if response in ['y', 'yes']:
                    finding['verified'] = True
                    finding['false_positive'] = False
                    verified_findings.append(finding)
                    print("✅ Marked as CONFIRMED vulnerability")
                    break
                    
                elif response in ['n', 'no']:
                    finding['verified'] = False
                    finding['false_positive'] = True
                    print("❌ Marked as FALSE POSITIVE")
                    self._learn_false_positive_pattern(finding)
                    break
                    
                elif response == 'skip':
                    print("⏭️  Skipping this finding")
                    break
                    
                elif response == 'info':
                    self._show_verification_help(finding)
                    
                else:
                    print("⚠️  Please enter y, n, skip, or info")
        
        return verified_findings
    
    def _learn_false_positive_pattern(self, false_positive: Dict):
        """Learn from false positives to improve future detection"""
        pattern = {
            "type": false_positive.get('type'),
            "target_pattern": false_positive.get('target', ''),
            "detection_method": false_positive.get('detection_method', ''),
            "reason": "User verified false positive",
            "timestamp": false_positive.get('timestamp', '')
        }
        
        self.false_positive_patterns.append(pattern)
        
        # Save to knowledge base
        with open("data/false_positives.json", 'w') as f:
            json.dump(self.false_positive_patterns, f, indent=2)
    
    def _show_verification_help(self, finding: Dict):
        """Show help for verifying a finding"""
        print(f"""
🔍 VERIFICATION HELP for {finding.get('type', 'Unknown')}:
   
   Check the following:
   - Can you reproduce the issue?
   - Does it impact security?
   - Is it within scope?
   - Is there a clear exploitation path?
   
   Common false positives:
   - Static content triggering scanners
   - Default pages without real impact
   - Theoretical vulnerabilities without practical exploit
        """)