import json
from datetime import datetime
from typing import Dict, List, Any, Tuple
from collections import Counter
import logging

logger = logging.getLogger(__name__)

class AegisLearningEngine:
    """
    Enhanced Learning Engine with adaptive learning and pattern recognition
    """
    def __init__(self):
        self.knowledge_base = "data/knowledge_base.json"
        self.false_positive_db = "data/false_positives.json"
        self.pattern_recognition = {}
        self.failed_attempts_db = "data/failed_attempts.json"  # Track what didn't work
        self.success_patterns_db = "data/success_patterns.json"  # Track what worked
        
    def load_historical_data(self) -> Dict[str, Any]:
        """Load past testing data and results"""
        try:
            with open(self.knowledge_base, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {"vulnerabilities": {}, "techniques": {}, "target_patterns": {}}
    
    def save_finding(self, finding: Dict, is_false_positive: bool = False):
        """Save findings and learn from results with enhanced tracking"""
        try:
            historical_data = self.load_historical_data()
            
            vuln_type = finding.get('type', 'unknown')
            if vuln_type not in historical_data['vulnerabilities']:
                historical_data['vulnerabilities'][vuln_type] = []
            
            finding['timestamp'] = datetime.now().isoformat()
            finding['false_positive'] = is_false_positive
            
            historical_data['vulnerabilities'][vuln_type].append(finding)
            
            # Save back to knowledge base
            with open(self.knowledge_base, 'w') as f:
                json.dump(historical_data, f, indent=2)
            
            # Update pattern recognition immediately
            self.analyze_patterns()
            
            logger.info(f"✅ Saved finding: {vuln_type} (false_positive={is_false_positive})")
        
        except Exception as e:
            logger.error(f"Error saving finding: {e}", exc_info=True)
    
    def record_failed_attempt(self, action: str, target: str, reason: str):
        """
        Record failed attempts to avoid repeating ineffective actions
        
        Args:
            action: The action that failed (e.g., 'subdomain_enumeration')
            target: The target of the action
            reason: Why it failed
        """
        try:
            failed_attempts = self._load_json_safe(self.failed_attempts_db, default=[])
            
            failed_attempts.append({
                'action': action,
                'target': target,
                'reason': reason,
                'timestamp': datetime.now().isoformat()
            })
            
            # Keep only recent failures (last 100)
            failed_attempts = failed_attempts[-100:]
            
            with open(self.failed_attempts_db, 'w') as f:
                json.dump(failed_attempts, f, indent=2)
            
            logger.info(f"Recorded failed attempt: {action} on {target}")
        
        except Exception as e:
            logger.error(f"Error recording failed attempt: {e}")
    
    def record_successful_action(self, action: str, target: str, result_summary: str):
        """
        Record successful actions to identify patterns
        
        Args:
            action: The action that succeeded
            target: The target of the action
            result_summary: Summary of results
        """
        try:
            successes = self._load_json_safe(self.success_patterns_db, default=[])
            
            successes.append({
                'action': action,
                'target': target,
                'result_summary': result_summary,
                'timestamp': datetime.now().isoformat()
            })
            
            # Keep only recent successes (last 100)
            successes = successes[-100:]
            
            with open(self.success_patterns_db, 'w') as f:
                json.dump(successes, f, indent=2)
            
            logger.info(f"Recorded successful action: {action} on {target}")
        
        except Exception as e:
            logger.error(f"Error recording successful action: {e}")
    
    def should_avoid_action(self, action: str, target: str) -> Tuple[bool, str]:
        """
        Check if an action should be avoided based on past failures
        
        Returns:
            Tuple of (should_avoid: bool, reason: str)
        """
        try:
            failed_attempts = self._load_json_safe(self.failed_attempts_db, default=[])
            
            # Count recent failures for this action-target combination
            recent_failures = [
                f for f in failed_attempts[-50:]  # Last 50 attempts
                if f['action'] == action and f['target'] == target
            ]
            
            if len(recent_failures) >= 3:
                return True, f"Action {action} failed {len(recent_failures)} times on {target}"
            
            return False, ""
        
        except Exception as e:
            logger.error(f"Error checking failed attempts: {e}")
            return False, ""
    
    def _load_json_safe(self, filepath: str, default: Any = None) -> Any:
        """Safely load JSON file with error handling"""
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.debug(f"Could not load {filepath}: {e}")
            return default if default is not None else {}
            
    def analyze_patterns(self):
        """Analyze patterns in successful findings with enhanced intelligence"""
        try:
            data = self.load_historical_data()
            
            for vuln_type, findings in data['vulnerabilities'].items():
                # Only analyze true positives
                true_positives = [f for f in findings if not f.get('false_positive', True)]
                
                if true_positives:
                    # Extract common patterns
                    common_techniques = Counter()
                    common_payloads = Counter()
                    common_targets = Counter()
                    
                    for finding in true_positives:
                        common_techniques[finding.get('technique', 'unknown')] += 1
                        common_payloads[finding.get('payload', 'unknown')] += 1
                        
                        # Extract target characteristics
                        target = finding.get('target', '')
                        if target:
                            # Extract domain/path patterns
                            if '/' in target:
                                path = target.split('/', 3)[-1] if target.count('/') >= 3 else ''
                                if path:
                                    common_targets[path.split('/')[0]] += 1
                    
                    self.pattern_recognition[vuln_type] = {
                        'most_effective_techniques': common_techniques.most_common(5),
                        'successful_payloads': common_payloads.most_common(10),
                        'common_vulnerable_paths': common_targets.most_common(5),
                        'total_findings': len(true_positives),
                        'false_positive_rate': len([f for f in findings if f.get('false_positive', False)]) / len(findings) if findings else 0
                    }
            
            # Save patterns
            with open('data/patterns.json', 'w') as f:
                json.dump(self.pattern_recognition, f, indent=2)
            
            logger.info(f"✅ Analyzed patterns for {len(self.pattern_recognition)} vulnerability types")
        
        except Exception as e:
            logger.error(f"Error analyzing patterns: {e}", exc_info=True)
    
    def load_learned_patterns(self) -> str:
        """Load learned patterns and return as formatted string for AI context"""
        try:
            with open('data/patterns.json', 'r') as f:
                patterns = json.load(f)
            
            if not patterns:
                return "No learned patterns available yet."
            
            # Format patterns for AI consumption with enhanced detail
            formatted = ["LEARNED PATTERNS FROM PREVIOUS MISSIONS:"]
            
            for vuln_type, data in patterns.items():
                formatted.append(f"\n{vuln_type}:")
                formatted.append(f"  Total successful findings: {data.get('total_findings', 0)}")
                formatted.append(f"  False positive rate: {data.get('false_positive_rate', 0):.1%}")
                
                if 'most_effective_techniques' in data:
                    formatted.append("  Most effective techniques:")
                    for technique, count in data['most_effective_techniques']:
                        if technique != 'unknown':
                            formatted.append(f"    - {technique} (success count: {count})")
                
                if 'successful_payloads' in data:
                    formatted.append("  Successful payloads:")
                    for payload, count in data['successful_payloads'][:5]:  # Top 5 only
                        if payload != 'unknown':
                            formatted.append(f"    - {payload}")
                
                if 'common_vulnerable_paths' in data:
                    formatted.append("  Common vulnerable paths:")
                    for path, count in data['common_vulnerable_paths']:
                        if path:
                            formatted.append(f"    - /{path} (found {count} times)")
            
            # Add insights from successful actions
            try:
                successes = self._load_json_safe(self.success_patterns_db, default=[])
                if successes:
                    formatted.append("\nRECENT SUCCESSFUL ACTIONS:")
                    action_counts = Counter(s['action'] for s in successes[-20:])
                    for action, count in action_counts.most_common(5):
                        formatted.append(f"  - {action}: {count} successful uses")
            except:
                pass
            
            # Add warnings about failed attempts
            try:
                failed = self._load_json_safe(self.failed_attempts_db, default=[])
                if failed:
                    formatted.append("\nWARNINGS - AVOID THESE PATTERNS:")
                    action_failures = Counter(f['action'] for f in failed[-20:])
                    for action, count in action_failures.most_common(3):
                        formatted.append(f"  - {action} has failed {count} times recently")
            except:
                pass
            
            return "\n".join(formatted)
            
        except FileNotFoundError:
            return "No learned patterns available yet."
        except Exception as e:
            logger.error(f"Error loading patterns: {e}", exc_info=True)
            return f"Error loading patterns: {str(e)}"