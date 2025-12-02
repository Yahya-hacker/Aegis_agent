"""
Aegis AI Learning Engine
Version V8 - Async I/O with concurrency control and caching
"""

import asyncio
import json
import aiofiles
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from collections import Counter
import logging

logger = logging.getLogger(__name__)

# Configuration constants
MAX_RECENT_RECORDS = 100  # Maximum number of recent records to keep
MAX_RECENT_CHECK = 50  # Number of records to check to avoid actions


class AegisLearningEngine:
    """
    Enhanced learning engine with adaptive learning and pattern recognition
    Includes concurrency control and non-blocking I/O
    """
    def __init__(self):
        self.knowledge_base = "data/knowledge_base.json"
        self.false_positive_db = "data/false_positives.json"
        self.pattern_recognition: Dict[str, Any] = {}
        self.failed_attempts_db = "data/failed_attempts.json"  # Failure tracking
        self.success_patterns_db = "data/success_patterns.json"  # Success tracking
        self.patterns_file = "data/patterns.json"
        
        # Locks to avoid race conditions
        self._write_lock = asyncio.Lock()
        
        # In-memory cache to avoid repeated reads
        self._cache: Dict[str, Any] = {}
        self._cache_loaded = False
    
    async def _ensure_cache_loaded(self) -> None:
        """Ensure cache is loaded from disk"""
        if self._cache_loaded:
            return
        
        async with self._write_lock:
            if self._cache_loaded:
                return
            
            # Load all data into memory
            self._cache['historical'] = await self._load_json_async(
                self.knowledge_base, 
                {"vulnerabilities": {}, "techniques": {}, "target_patterns": {}}
            )
            self._cache['failed_attempts'] = await self._load_json_async(
                self.failed_attempts_db, []
            )
            self._cache['success_patterns'] = await self._load_json_async(
                self.success_patterns_db, []
            )
            self._cache['patterns'] = await self._load_json_async(
                self.patterns_file, {}
            )
            self._cache_loaded = True
            logger.info("✅ Learning engine cache loaded")
    
    async def _load_json_async(self, filepath: str, default: Any = None) -> Any:
        """Load JSON file asynchronously"""
        try:
            path = Path(filepath)
            if not path.exists():
                return default if default is not None else {}
            
            async with aiofiles.open(filepath, 'r') as f:
                content = await f.read()
                return json.loads(content)
        except (json.JSONDecodeError, Exception) as e:
            logger.debug(f"Unable to load {filepath}: {e}")
            return default if default is not None else {}
    
    async def _save_json_async(self, filepath: str, data: Any) -> None:
        """Save JSON file asynchronously"""
        try:
            # Ensure directory exists
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            async with aiofiles.open(filepath, 'w') as f:
                await f.write(json.dumps(data, indent=2))
        except Exception as e:
            logger.error(f"Error saving {filepath}: {e}")
    
    def load_historical_data(self) -> Dict[str, Any]:
        """
        Load historical test data (synchronous version for compatibility)
        Note: Use load_historical_data_async for new implementations
        """
        try:
            with open(self.knowledge_base, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {"vulnerabilities": {}, "techniques": {}, "target_patterns": {}}
    
    async def load_historical_data_async(self) -> Dict[str, Any]:
        """Load historical test data asynchronously"""
        await self._ensure_cache_loaded()
        return self._cache.get('historical', {"vulnerabilities": {}, "techniques": {}, "target_patterns": {}})
    
    async def save_finding_async(self, finding: Dict, is_false_positive: bool = False) -> None:
        """Save findings and learn from results with improved tracking"""
        await self._ensure_cache_loaded()
        
        async with self._write_lock:
            try:
                historical_data = self._cache.get('historical', {"vulnerabilities": {}, "techniques": {}, "target_patterns": {}})
                
                vuln_type = finding.get('type', 'unknown')
                if vuln_type not in historical_data['vulnerabilities']:
                    historical_data['vulnerabilities'][vuln_type] = []
                
                finding['timestamp'] = datetime.now().isoformat()
                finding['false_positive'] = is_false_positive
                
                historical_data['vulnerabilities'][vuln_type].append(finding)
                
                # Update cache
                self._cache['historical'] = historical_data
                
                # Save to disk asynchronously
                await self._save_json_async(self.knowledge_base, historical_data)
                
                # Update pattern recognition immediately
                await self.analyze_patterns_async()
                
                logger.info(f"✅ Finding saved: {vuln_type} (false_positive={is_false_positive})")
            
            except Exception as e:
                logger.error(f"Error saving finding: {e}", exc_info=True)
    
    def save_finding(self, finding: Dict, is_false_positive: bool = False):
        """
        Save findings (synchronous version for compatibility)
        Note: Use save_finding_async for new implementations
        """
        try:
            historical_data = self.load_historical_data()
            
            vuln_type = finding.get('type', 'unknown')
            if vuln_type not in historical_data['vulnerabilities']:
                historical_data['vulnerabilities'][vuln_type] = []
            
            finding['timestamp'] = datetime.now().isoformat()
            finding['false_positive'] = is_false_positive
            
            historical_data['vulnerabilities'][vuln_type].append(finding)
            
            # Save to knowledge base
            with open(self.knowledge_base, 'w') as f:
                json.dump(historical_data, f, indent=2)
            
            # Update pattern recognition immediately
            self.analyze_patterns()
            
            logger.info(f"✅ Finding saved: {vuln_type} (false_positive={is_false_positive})")
        
        except Exception as e:
            logger.error(f"Error saving finding: {e}", exc_info=True)
    
    async def record_failed_attempt_async(self, action: str, target: str, reason: str) -> None:
        """
        Record failed attempts to avoid repeating ineffective actions
        
        Args:
            action: The action that failed (e.g., 'subdomain_enumeration')
            target: The target of the action
            reason: Why it failed
        """
        await self._ensure_cache_loaded()
        
        async with self._write_lock:
            try:
                failed_attempts = self._cache.get('failed_attempts', [])
                
                failed_attempts.append({
                    'action': action,
                    'target': target,
                    'reason': reason,
                    'timestamp': datetime.now().isoformat()
                })
                
                # Keep only recent failures
                failed_attempts = failed_attempts[-MAX_RECENT_RECORDS:]
                
                # Update cache
                self._cache['failed_attempts'] = failed_attempts
                
                # Save to disk
                await self._save_json_async(self.failed_attempts_db, failed_attempts)
                
                logger.info(f"Failed attempt recorded: {action} on {target}")
            
            except Exception as e:
                logger.error(f"Error recording failed attempt: {e}")
    
    def record_failed_attempt(self, action: str, target: str, reason: str):
        """
        Record failed attempts (synchronous version for compatibility)
        """
        try:
            failed_attempts = self._load_json_safe(self.failed_attempts_db, default=[])
            
            failed_attempts.append({
                'action': action,
                'target': target,
                'reason': reason,
                'timestamp': datetime.now().isoformat()
            })
            
            # Keep only recent failures
            failed_attempts = failed_attempts[-MAX_RECENT_RECORDS:]
            
            with open(self.failed_attempts_db, 'w') as f:
                json.dump(failed_attempts, f, indent=2)
            
            logger.info(f"Failed attempt recorded: {action} on {target}")
        
        except Exception as e:
            logger.error(f"Error recording failed attempt: {e}")
    
    async def record_successful_action_async(self, action: str, target: str, result_summary: str) -> None:
        """
        Record successful actions to identify patterns
        
        Args:
            action: The action that succeeded
            target: The target of the action
            result_summary: Summary of results
        """
        await self._ensure_cache_loaded()
        
        async with self._write_lock:
            try:
                successes = self._cache.get('success_patterns', [])
                
                successes.append({
                    'action': action,
                    'target': target,
                    'result_summary': result_summary,
                    'timestamp': datetime.now().isoformat()
                })
                
                # Keep only recent successes
                successes = successes[-MAX_RECENT_RECORDS:]
                
                # Update cache
                self._cache['success_patterns'] = successes
                
                # Save to disk
                await self._save_json_async(self.success_patterns_db, successes)
                
                logger.info(f"Successful action recorded: {action} on {target}")
            
            except Exception as e:
                logger.error(f"Error recording successful action: {e}")
    
    def record_successful_action(self, action: str, target: str, result_summary: str):
        """
        Record successful actions (synchronous version for compatibility)
        """
        try:
            successes = self._load_json_safe(self.success_patterns_db, default=[])
            
            successes.append({
                'action': action,
                'target': target,
                'result_summary': result_summary,
                'timestamp': datetime.now().isoformat()
            })
            
            # Keep only recent successes
            successes = successes[-MAX_RECENT_RECORDS:]
            
            with open(self.success_patterns_db, 'w') as f:
                json.dump(successes, f, indent=2)
            
            logger.info(f"Successful action recorded: {action} on {target}")
        
        except Exception as e:
            logger.error(f"Error recording successful action: {e}")
    
    async def should_avoid_action_async(self, action: str, target: str) -> Tuple[bool, str]:
        """
        Check if an action should be avoided based on past failures
        
        Returns:
            Tuple of (should_avoid: bool, reason: str)
        """
        await self._ensure_cache_loaded()
        
        try:
            failed_attempts = self._cache.get('failed_attempts', [])
            
            # Count recent failures for this action-target combination
            recent_failures = [
                f for f in failed_attempts[-MAX_RECENT_CHECK:]
                if f['action'] == action and f['target'] == target
            ]
            
            if len(recent_failures) >= 3:
                return True, f"Action {action} failed {len(recent_failures)} times on {target}"
            
            return False, ""
        
        except Exception as e:
            logger.error(f"Error checking failed attempts: {e}")
            return False, ""
    
    def should_avoid_action(self, action: str, target: str) -> Tuple[bool, str]:
        """
        Check if an action should be avoided (synchronous version for compatibility)
        """
        try:
            failed_attempts = self._load_json_safe(self.failed_attempts_db, default=[])
            
            # Count recent failures for this action-target combination
            recent_failures = [
                f for f in failed_attempts[-MAX_RECENT_CHECK:]
                if f['action'] == action and f['target'] == target
            ]
            
            if len(recent_failures) >= 3:
                return True, f"Action {action} failed {len(recent_failures)} times on {target}"
            
            return False, ""
        
        except Exception as e:
            logger.error(f"Error checking failed attempts: {e}")
            return False, ""
    
    def _load_json_safe(self, filepath: str, default: Any = None) -> Any:
        """Load JSON file safely with error handling"""
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.debug(f"Unable to load {filepath}: {e}")
            return default if default is not None else {}
    
    async def analyze_patterns_async(self) -> None:
        """Analyze patterns in successful findings with improved intelligence"""
        await self._ensure_cache_loaded()
        
        try:
            data = self._cache.get('historical', {"vulnerabilities": {}})
            
            for vuln_type, findings in data.get('vulnerabilities', {}).items():
                # Analyze only true positives
                true_positives = [f for f in findings if not f.get('false_positive', True)]
                
                if true_positives:
                    # Extract common patterns
                    common_techniques: Counter = Counter()
                    common_payloads: Counter = Counter()
                    common_targets: Counter = Counter()
                    
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
            
            # Update cache
            self._cache['patterns'] = self.pattern_recognition
            
            # Save patterns
            await self._save_json_async(self.patterns_file, self.pattern_recognition)
            
            logger.info(f"✅ Patterns analyzed for {len(self.pattern_recognition)} vulnerability types")
        
        except Exception as e:
            logger.error(f"Error analyzing patterns: {e}", exc_info=True)
    
    def analyze_patterns(self):
        """Analyze patterns (synchronous version for compatibility)"""
        try:
            data = self.load_historical_data()
            
            for vuln_type, findings in data['vulnerabilities'].items():
                # Analyze only true positives
                true_positives = [f for f in findings if not f.get('false_positive', True)]
                
                if true_positives:
                    # Extract common patterns
                    common_techniques: Counter = Counter()
                    common_payloads: Counter = Counter()
                    common_targets: Counter = Counter()
                    
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
            with open(self.patterns_file, 'w') as f:
                json.dump(self.pattern_recognition, f, indent=2)
            
            logger.info(f"✅ Patterns analyzed for {len(self.pattern_recognition)} vulnerability types")
        
        except Exception as e:
            logger.error(f"Error analyzing patterns: {e}", exc_info=True)
    
    async def load_learned_patterns_async(self) -> str:
        """Load learned patterns and return a formatted string for AI context"""
        await self._ensure_cache_loaded()
        
        try:
            patterns = self._cache.get('patterns', {})
            
            if not patterns:
                return "No learned patterns available at the moment."
            
            # Format patterns for AI consumption with improved details
            formatted = ["PATTERNS LEARNED FROM PREVIOUS MISSIONS:"]
            
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
                successes = self._cache.get('success_patterns', [])
                if successes:
                    formatted.append("\nRECENT SUCCESSFUL ACTIONS:")
                    action_counts = Counter(s['action'] for s in successes[-20:])
                    for action, count in action_counts.most_common(5):
                        formatted.append(f"  - {action}: {count} successful uses")
            except Exception:
                pass
            
            # Add warnings about failed attempts
            try:
                failed = self._cache.get('failed_attempts', [])
                if failed:
                    formatted.append("\nWARNINGS - AVOID THESE PATTERNS:")
                    action_failures = Counter(f['action'] for f in failed[-20:])
                    for action, count in action_failures.most_common(3):
                        formatted.append(f"  - {action} failed {count} times recently")
            except Exception:
                pass
            
            return "\n".join(formatted)
            
        except Exception as e:
            logger.error(f"Error loading patterns: {e}", exc_info=True)
            return f"Error loading patterns: {str(e)}"
    
    def load_learned_patterns(self) -> str:
        """Load learned patterns (synchronous version for compatibility)"""
        try:
            with open(self.patterns_file, 'r') as f:
                patterns = json.load(f)
            
            if not patterns:
                return "No learned patterns available at the moment."
            
            # Format patterns for AI consumption with improved details
            formatted = ["PATTERNS LEARNED FROM PREVIOUS MISSIONS:"]
            
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
            except Exception:
                pass
            
            # Add warnings about failed attempts
            try:
                failed = self._load_json_safe(self.failed_attempts_db, default=[])
                if failed:
                    formatted.append("\nWARNINGS - AVOID THESE PATTERNS:")
                    action_failures = Counter(f['action'] for f in failed[-20:])
                    for action, count in action_failures.most_common(3):
                        formatted.append(f"  - {action} failed {count} times recently")
            except Exception:
                pass
            
            return "\n".join(formatted)
            
        except FileNotFoundError:
            return "No learned patterns available at the moment."
        except Exception as e:
            logger.error(f"Error loading patterns: {e}", exc_info=True)
            return f"Error loading patterns: {str(e)}"