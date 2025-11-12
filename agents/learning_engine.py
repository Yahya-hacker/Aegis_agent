import json
from datetime import datetime
from typing import Dict, List, Any
from collections import Counter

class AegisLearningEngine:
    def __init__(self):
        self.knowledge_base = "data/knowledge_base.json"
        self.false_positive_db = "data/false_positives.json"
        self.pattern_recognition = {}
        
    def load_historical_data(self) -> Dict[str, Any]:
        """Load past testing data and results"""
        try:
            with open(self.knowledge_base, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {"vulnerabilities": {}, "techniques": {}, "target_patterns": {}}
    
    def save_finding(self, finding: Dict, is_false_positive: bool = False):
        """Save findings and learn from results"""
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
            
    def analyze_patterns(self):
        """Analyze patterns in successful findings"""
        data = self.load_historical_data()
        
        for vuln_type, findings in data['vulnerabilities'].items():
            true_positives = [f for f in findings if not f.get('false_positive', True)]
            
            if true_positives:
                # Extract common patterns
                common_techniques = Counter()
                common_payloads = Counter()
                
                for finding in true_positives:
                    common_techniques[finding.get('technique', 'unknown')] += 1
                    common_payloads[finding.get('payload', 'unknown')] += 1
                
                self.pattern_recognition[vuln_type] = {
                    'most_effective_techniques': common_techniques.most_common(5),
                    'successful_payloads': common_payloads.most_common(10)
                }
        
        # Save patterns
        with open('data/patterns.json', 'w') as f:
            json.dump(self.pattern_recognition, f, indent=2)
    
    def load_learned_patterns(self) -> str:
        """Load learned patterns and return as formatted string for AI context"""
        try:
            with open('data/patterns.json', 'r') as f:
                patterns = json.load(f)
            
            if not patterns:
                return "No learned patterns available yet."
            
            # Format patterns for AI consumption
            formatted = ["LEARNED PATTERNS FROM PREVIOUS MISSIONS:"]
            
            for vuln_type, data in patterns.items():
                formatted.append(f"\n{vuln_type}:")
                
                if 'most_effective_techniques' in data:
                    formatted.append("  Effective techniques:")
                    for technique, count in data['most_effective_techniques']:
                        formatted.append(f"    - {technique} (success rate: {count})")
                
                if 'successful_payloads' in data:
                    formatted.append("  Successful payloads:")
                    for payload, count in data['successful_payloads'][:5]:  # Top 5 only
                        if payload != 'unknown':
                            formatted.append(f"    - {payload}")
            
            return "\n".join(formatted)
            
        except FileNotFoundError:
            return "No learned patterns available yet."
        except Exception as e:
            return f"Error loading patterns: {str(e)}"