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


class QLearningRewardEngine:
    """
    Q-Learning based Reward Engine for tool selection optimization.
    
    This implements reinforcement learning to help the agent learn which tools
    work best against specific environments (e.g., "Don't use SQLMap if WAF detected").
    
    State: Current tech stack / environment fingerprint
    Action: Tool selected
    Reward: +10 for finding, -5 for WAF block/timeout, +1 for new endpoints
    """
    
    # Reward constants
    REWARD_FINDING = 10.0          # Major vulnerability discovery
    REWARD_NEW_ENDPOINT = 1.0      # New endpoint discovered
    REWARD_PARTIAL_SUCCESS = 0.5   # Partial progress made
    REWARD_NEUTRAL = 0.0           # No significant outcome
    REWARD_WAF_BLOCK = -5.0        # Blocked by WAF/security control
    REWARD_TIMEOUT = -3.0          # Request timeout
    REWARD_ERROR = -1.0            # Tool error/failure
    
    # Learning parameters
    DEFAULT_LEARNING_RATE = 0.1     # Alpha - how fast to learn
    DEFAULT_DISCOUNT_FACTOR = 0.9   # Gamma - future reward importance
    DEFAULT_EXPLORATION_RATE = 0.2  # Epsilon - exploration vs exploitation
    
    def __init__(
        self,
        learning_rate: float = DEFAULT_LEARNING_RATE,
        discount_factor: float = DEFAULT_DISCOUNT_FACTOR,
        exploration_rate: float = DEFAULT_EXPLORATION_RATE
    ):
        """
        Initialize the Q-Learning Reward Engine.
        
        Args:
            learning_rate: Alpha - how quickly to update Q-values (0.0-1.0)
            discount_factor: Gamma - importance of future rewards (0.0-1.0)
            exploration_rate: Epsilon - probability of exploring vs exploiting (0.0-1.0)
        """
        self.learning_rate = learning_rate
        self.discount_factor = discount_factor
        self.exploration_rate = exploration_rate
        
        # Q-table: {state_key: {action: q_value}}
        self.q_table: Dict[str, Dict[str, float]] = {}
        
        # State-action history for learning
        self.episode_history: List[Tuple[str, str, float]] = []
        
        # Tool effectiveness tracking
        self.tool_stats: Dict[str, Dict[str, int]] = {}
        
        # Persistence
        self.q_table_file = "data/q_learning_table.json"
        self._load_q_table()
        
        logger.info("🧠 Q-Learning Reward Engine initialized "
                   f"(α={learning_rate}, γ={discount_factor}, ε={exploration_rate})")
    
    def _load_q_table(self) -> None:
        """Load Q-table from persistent storage"""
        try:
            path = Path(self.q_table_file)
            if path.exists():
                with open(path, 'r') as f:
                    data = json.load(f)
                    self.q_table = data.get('q_table', {})
                    self.tool_stats = data.get('tool_stats', {})
                logger.info(f"✅ Loaded Q-table with {len(self.q_table)} states")
        except Exception as e:
            logger.debug(f"Could not load Q-table: {e}")
            self.q_table = {}
            self.tool_stats = {}
    
    def _save_q_table(self) -> None:
        """Save Q-table to persistent storage"""
        try:
            path = Path(self.q_table_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, 'w') as f:
                json.dump({
                    'q_table': self.q_table,
                    'tool_stats': self.tool_stats
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save Q-table: {e}")
    
    def _state_to_key(self, tech_stack: List[str], has_waf: bool = False, 
                      auth_type: Optional[str] = None) -> str:
        """
        Convert environment state to a hashable key for the Q-table.
        
        Args:
            tech_stack: List of detected technologies (e.g., ['django', 'nginx', 'postgres'])
            has_waf: Whether a WAF is detected
            auth_type: Type of authentication if any (e.g., 'jwt', 'session', 'basic')
        
        Returns:
            State key string
        """
        # Normalize and sort tech stack for consistent keys
        normalized_tech = sorted([t.lower().strip() for t in tech_stack if t])
        
        state_components = [
            f"tech:{','.join(normalized_tech) or 'unknown'}",
            f"waf:{has_waf}",
            f"auth:{auth_type or 'none'}"
        ]
        
        return "|".join(state_components)
    
    def get_q_value(self, state: str, action: str) -> float:
        """
        Get Q-value for a state-action pair.
        
        Args:
            state: State key
            action: Tool/action name
        
        Returns:
            Q-value (0.0 if not yet learned)
        """
        if state not in self.q_table:
            return 0.0
        return self.q_table[state].get(action, 0.0)
    
    def get_best_action(self, state: str, available_actions: List[str]) -> Tuple[str, float]:
        """
        Get the best action for a given state using epsilon-greedy policy.
        
        Args:
            state: Current state key
            available_actions: List of available tool/action names
        
        Returns:
            Tuple of (best_action, q_value)
        """
        import random
        
        if not available_actions:
            return ("", 0.0)
        
        # Epsilon-greedy: explore with probability epsilon
        if random.random() < self.exploration_rate:
            # Exploration: random action
            action = random.choice(available_actions)
            q_value = self.get_q_value(state, action)
            logger.debug(f"[RL] Exploring: chose '{action}' randomly")
            return (action, q_value)
        
        # Exploitation: choose best action
        best_action = available_actions[0]
        best_q_value = self.get_q_value(state, best_action)
        
        for action in available_actions[1:]:
            q_value = self.get_q_value(state, action)
            if q_value > best_q_value:
                best_action = action
                best_q_value = q_value
        
        logger.debug(f"[RL] Exploiting: chose '{best_action}' (Q={best_q_value:.2f})")
        return (best_action, best_q_value)
    
    def update_q_value(
        self,
        state: str,
        action: str,
        reward: float,
        next_state: Optional[str] = None,
        next_actions: Optional[List[str]] = None
    ) -> float:
        """
        Update Q-value using the Q-learning update rule:
        Q(s,a) = Q(s,a) + α * [r + γ * max(Q(s',a')) - Q(s,a)]
        
        Args:
            state: Current state key
            action: Action taken
            reward: Reward received
            next_state: Next state key (optional, for future reward estimation)
            next_actions: Available actions in next state (optional)
        
        Returns:
            New Q-value
        """
        # Initialize state in Q-table if needed
        if state not in self.q_table:
            self.q_table[state] = {}
        
        # Get current Q-value
        current_q = self.get_q_value(state, action)
        
        # Calculate maximum future Q-value
        max_future_q = 0.0
        if next_state and next_actions:
            max_future_q = max(
                [self.get_q_value(next_state, a) for a in next_actions],
                default=0.0
            )
        
        # Q-learning update rule
        new_q = current_q + self.learning_rate * (
            reward + self.discount_factor * max_future_q - current_q
        )
        
        # Store updated Q-value
        self.q_table[state][action] = new_q
        
        # Update tool statistics
        if action not in self.tool_stats:
            self.tool_stats[action] = {'success': 0, 'failure': 0, 'waf_block': 0}
        
        if reward >= self.REWARD_FINDING:
            self.tool_stats[action]['success'] += 1
        elif reward <= self.REWARD_WAF_BLOCK:
            self.tool_stats[action]['waf_block'] += 1
        elif reward < 0:
            self.tool_stats[action]['failure'] += 1
        
        # Save Q-table periodically
        self._save_q_table()
        
        logger.info(f"[RL] Updated Q({state[:50]}..., {action}): "
                   f"{current_q:.2f} -> {new_q:.2f} (reward: {reward})")
        
        return new_q
    
    def calculate_reward(
        self,
        result: Dict[str, Any],
        tool_name: str
    ) -> float:
        """
        Calculate reward based on tool execution result.
        
        Args:
            result: Tool execution result dictionary
            tool_name: Name of the tool that was executed
        
        Returns:
            Reward value
        """
        status = result.get('status', '')
        
        # Check for findings/vulnerabilities
        findings = result.get('findings', [])
        vulnerabilities = result.get('vulnerabilities', [])
        
        if findings or vulnerabilities:
            num_findings = len(findings) + len(vulnerabilities)
            reward = self.REWARD_FINDING * min(num_findings, 3)  # Cap at 3x
            logger.info(f"[RL] 🎯 Finding reward: +{reward} for {num_findings} findings")
            return reward
        
        # Check for new endpoints discovered
        endpoints = result.get('endpoints', []) or result.get('new_endpoints', [])
        if endpoints:
            reward = self.REWARD_NEW_ENDPOINT * min(len(endpoints), 10)
            logger.info(f"[RL] 🔍 Discovery reward: +{reward} for {len(endpoints)} endpoints")
            return reward
        
        # Check for WAF/security blocks
        error_msg = str(result.get('error', '')).lower()
        status_code = result.get('status_code', 0)
        
        waf_indicators = ['forbidden', '403', 'blocked', 'waf', 'firewall', 
                         'access denied', 'rate limit', '429']
        if any(ind in error_msg for ind in waf_indicators) or status_code in [403, 429]:
            logger.info(f"[RL] 🛡️ WAF block penalty: {self.REWARD_WAF_BLOCK}")
            return self.REWARD_WAF_BLOCK
        
        # Check for timeouts
        if 'timeout' in error_msg or status == 'timeout':
            logger.info(f"[RL] ⏱️ Timeout penalty: {self.REWARD_TIMEOUT}")
            return self.REWARD_TIMEOUT
        
        # Check for errors
        if status == 'error' or 'error' in error_msg:
            logger.info(f"[RL] ❌ Error penalty: {self.REWARD_ERROR}")
            return self.REWARD_ERROR
        
        # Neutral outcome
        return self.REWARD_NEUTRAL
    
    def get_tool_recommendations(
        self,
        tech_stack: List[str],
        has_waf: bool = False,
        available_tools: Optional[List[str]] = None
    ) -> List[Tuple[str, float]]:
        """
        Get ranked tool recommendations for the current environment.
        
        Args:
            tech_stack: Detected technology stack
            has_waf: Whether WAF is detected
            available_tools: List of available tools (optional)
        
        Returns:
            List of (tool_name, confidence_score) tuples, sorted by confidence
        """
        state = self._state_to_key(tech_stack, has_waf)
        
        if state not in self.q_table:
            logger.info(f"[RL] No learned preferences for state: {state[:50]}...")
            return []
        
        state_q_values = self.q_table[state]
        
        # Filter to available tools if specified
        if available_tools:
            state_q_values = {k: v for k, v in state_q_values.items() 
                            if k in available_tools}
        
        # Sort by Q-value (descending)
        recommendations = sorted(
            state_q_values.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        if recommendations:
            logger.info(f"[RL] Top recommendation: {recommendations[0][0]} "
                       f"(confidence: {recommendations[0][1]:.2f})")
        
        return recommendations
    
    def get_learning_summary(self) -> str:
        """
        Get a human-readable summary of learned preferences.
        
        Returns:
            Formatted string with learning insights
        """
        summary = ["[Q-LEARNING INSIGHTS]"]
        summary.append(f"States learned: {len(self.q_table)}")
        
        # Tool effectiveness summary
        if self.tool_stats:
            summary.append("\nTool Effectiveness:")
            for tool, stats in sorted(self.tool_stats.items()):
                success = stats.get('success', 0)
                failure = stats.get('failure', 0)
                waf = stats.get('waf_block', 0)
                total = success + failure + waf
                if total > 0:
                    success_rate = success / total * 100
                    summary.append(f"  {tool}: {success_rate:.1f}% success "
                                 f"({success}/{total}, {waf} WAF blocks)")
        
        # Top state-action pairs
        if self.q_table:
            summary.append("\nTop Learned Preferences:")
            all_pairs = []
            for state, actions in self.q_table.items():
                for action, q_value in actions.items():
                    all_pairs.append((state, action, q_value))
            
            top_pairs = sorted(all_pairs, key=lambda x: x[2], reverse=True)[:5]
            for state, action, q_value in top_pairs:
                summary.append(f"  • {action} in {state[:40]}... (Q={q_value:.2f})")
        
        return "\n".join(summary)