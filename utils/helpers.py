"""
Utility helper functions for Aegis AI - Enhanced with Stealth Module
"""

import re
import json
import asyncio
import random
import os
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin

# TASK 4: User-Agent rotation list (20 recent, realistic User-Agents)
STEALTH_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
]

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
    
    # --- TASK 4: STEALTH MODULE (GHOST) ---
    
    @staticmethod
    def get_random_user_agent() -> str:
        """
        TASK 4: Get a random User-Agent from the stealth list
        
        Returns:
            Random User-Agent string
        """
        return random.choice(STEALTH_USER_AGENTS)
    
    @staticmethod
    def get_random_proxy() -> Optional[str]:
        """
        TASK 4: Get a random proxy from PROXY_LIST environment variable
        
        Returns:
            Random proxy URL or None if no proxies configured
        """
        proxy_list = os.environ.get("PROXY_LIST", "")
        if not proxy_list:
            return None
        
        proxies = [p.strip() for p in proxy_list.split(",") if p.strip()]
        if not proxies:
            return None
        
        return random.choice(proxies)
    
    @staticmethod
    async def apply_jitter(min_delay: float = 1.0, max_delay: float = 3.0):
        """
        TASK 4: Apply random jitter delay to avoid detection
        
        Args:
            min_delay: Minimum delay in seconds (default 1.0)
            max_delay: Maximum delay in seconds (default 3.0)
        """
        delay = random.uniform(min_delay, max_delay)
        await asyncio.sleep(delay)
    
    @staticmethod
    def get_stealth_headers() -> Dict[str, str]:
        """
        TASK 4: Get stealth headers with random User-Agent and realistic browser headers
        
        Returns:
            Dictionary of HTTP headers for stealth requests
        """
        return {
            "User-Agent": AegisHelpers.get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0"
        }