"""
Utility helper functions for Aegis AI
"""

import re
import json
import asyncio
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin

class AegisHelpers:
    @staticmethod
    def sanitize_target_url(url: str) -> str:
        """Sanitize and validate target URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    @staticmethod
    def extract_domain(url: str) -> str:
        """Extract domain from URL"""
        return urlparse(url).netloc

    @staticmethod
    def is_same_domain(url1: str, url2: str) -> bool:
        """Check if two URLs belong to the same domain"""
        return urlparse(url1).netloc == urlparse(url2).netloc

    @staticmethod
    def generate_session_id() -> str:
        """Generate unique session ID"""
        import uuid
        return str(uuid.uuid4())[:8]

    @staticmethod
    def format_finding(finding: Dict) -> str:
        """Format finding for display"""
        return f"""
🔍 Finding: {finding.get('type', 'Unknown')}
📍 URL: {finding.get('url', 'Unknown')}
📊 Confidence: {finding.get('confidence', 'Unknown')}
📝 Description: {finding.get('description', 'No description')}
⚡ Impact: {finding.get('impact', 'Unknown')}
🔧 Remediation: {finding.get('remediation', 'No remediation provided')}
        """

    @staticmethod
    async def rate_limit(delay: float = 1.0):
        """Rate limiting between requests"""
        await asyncio.sleep(delay)

    @staticmethod
    def load_json_file(filepath: str, default: Any = None) -> Any:
        """Safely load JSON file"""
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return default if default is not None else {}

    @staticmethod
    def save_json_file(filepath: str, data: Any):
        """Safely save JSON file"""
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            print(f"❌ Error saving {filepath}: {e}")
            return False