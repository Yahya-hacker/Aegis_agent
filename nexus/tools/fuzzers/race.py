"""
Nexus v2.0 - Race Condition Tester
==================================

Time-of-check to time-of-use (TOCTOU) vulnerabilities.
This is a high-value bug bounty category.
"""

import asyncio
import aiohttp
import logging
import time
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

from nexus.execution.proxy import get_proxy_client

logger = logging.getLogger(__name__)


@dataclass
class RaceFinding:
    """A race condition vulnerability finding."""
    endpoint: str
    vulnerability: str
    severity: str
    description: str
    successful_races: int
    total_attempts: int
    evidence: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "vulnerability": self.vulnerability,
            "severity": self.severity,
            "description": self.description,
            "successful_races": self.successful_races,
            "total_attempts": self.total_attempts,
            "evidence": self.evidence,
        }


class RaceConditionTester:
    """
    Race condition vulnerability tester.
    
    Attack types:
    1. Limit bypass (coupons, votes, etc.)
    2. Double spending
    3. Privilege escalation
    4. State manipulation
    """
    
    def __init__(self):
        self.client = get_proxy_client()
    
    async def send_concurrent_requests(
        self,
        url: str,
        method: str = "POST",
        body: Dict[str, Any] = None,
        headers: Dict[str, str] = None,
        count: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Send multiple concurrent requests.
        
        Args:
            url: Target URL
            method: HTTP method
            body: Request body
            headers: Request headers
            count: Number of concurrent requests
        
        Returns:
            List of response data
        """
        results = []
        
        async with aiohttp.ClientSession() as session:
            # Create all requests
            tasks = []
            
            for i in range(count):
                if method.upper() == "GET":
                    task = session.get(url, headers=headers, ssl=False)
                else:
                    task = session.post(url, json=body, headers=headers, ssl=False)
                tasks.append(task)
            
            # Barrier to ensure simultaneous start
            start_time = time.time()
            
            # Execute all simultaneously
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            end_time = time.time()
            
            for i, response in enumerate(responses):
                if isinstance(response, Exception):
                    results.append({
                        "index": i,
                        "error": str(response),
                        "success": False,
                    })
                else:
                    async with response as resp:
                        body_text = await resp.text()
                        results.append({
                            "index": i,
                            "status": resp.status,
                            "body_preview": body_text[:500],
                            "headers": dict(resp.headers),
                            "success": resp.status == 200,
                        })
        
        logger.debug(f"Sent {count} requests in {end_time - start_time:.3f}s")
        
        return results
    
    async def test_limit_bypass(
        self,
        url: str,
        method: str = "POST",
        body: Dict[str, Any] = None,
        expected_limit: int = 1,
        attempts: int = 20
    ) -> Optional[RaceFinding]:
        """
        Test for limit bypass via race condition.
        
        Common targets:
        - Coupon redemption (use coupon 100x)
        - Vote manipulation
        - Free tier abuse
        - Referral bonuses
        """
        logger.info(f"🏃 Testing limit bypass race on {url}")
        
        results = await self.send_concurrent_requests(
            url=url,
            method=method,
            body=body,
            count=attempts
        )
        
        # Count successful requests
        successes = sum(1 for r in results if r.get("success"))
        
        if successes > expected_limit:
            return RaceFinding(
                endpoint=url,
                vulnerability="Limit Bypass via Race Condition",
                severity="high",
                description=f"Expected limit of {expected_limit} bypassed - {successes} successful requests",
                successful_races=successes,
                total_attempts=attempts,
                evidence={
                    "expected_limit": expected_limit,
                    "actual_successes": successes,
                    "results": results[:5],  # First 5 results
                },
            )
        
        return None
    
    async def test_double_spending(
        self,
        transfer_url: str,
        amount: float,
        headers: Dict[str, str] = None,
        attempts: int = 10
    ) -> Optional[RaceFinding]:
        """
        Test for double spending in financial transactions.
        
        Send multiple transfer requests simultaneously to
        spend the same funds multiple times.
        """
        logger.info(f"🏃 Testing double spending on {transfer_url}")
        
        body = {"amount": amount}
        
        results = await self.send_concurrent_requests(
            url=transfer_url,
            method="POST",
            body=body,
            headers=headers,
            count=attempts
        )
        
        # Count successful transactions
        successes = sum(1 for r in results if r.get("success"))
        
        if successes > 1:
            return RaceFinding(
                endpoint=transfer_url,
                vulnerability="Double Spending Race Condition",
                severity="critical",
                description=f"Same funds spent {successes} times",
                successful_races=successes,
                total_attempts=attempts,
                evidence={
                    "amount": amount,
                    "times_spent": successes,
                    "results": results,
                },
            )
        
        return None
    
    async def test_state_manipulation(
        self,
        action_url: str,
        check_url: str,
        expected_state: str,
        body: Dict[str, Any] = None,
        attempts: int = 10
    ) -> Optional[RaceFinding]:
        """
        Test for state manipulation via race condition.
        
        Try to perform an action while state is being checked.
        """
        logger.info(f"🏃 Testing state manipulation on {action_url}")
        
        # Send concurrent action requests
        results = await self.send_concurrent_requests(
            url=action_url,
            body=body,
            count=attempts
        )
        
        # Check final state
        await asyncio.sleep(0.5)  # Wait for state to settle
        state_response = await self.client.get(check_url)
        
        successes = sum(1 for r in results if r.get("success"))
        
        if successes > 1 and expected_state not in state_response.response.body:
            return RaceFinding(
                endpoint=action_url,
                vulnerability="State Manipulation Race Condition",
                severity="high",
                description="State was manipulated via concurrent requests",
                successful_races=successes,
                total_attempts=attempts,
                evidence={
                    "expected_state": expected_state,
                    "final_state_preview": state_response.response.body[:500],
                },
            )
        
        return None
    
    async def test_registration_race(
        self,
        register_url: str,
        email: str,
        body_template: Dict[str, Any],
        attempts: int = 5
    ) -> Optional[RaceFinding]:
        """
        Test for account duplication via registration race.
        
        Register the same email simultaneously to create
        multiple accounts.
        """
        logger.info(f"🏃 Testing registration race with {email}")
        
        body = {**body_template, "email": email}
        
        results = await self.send_concurrent_requests(
            url=register_url,
            body=body,
            count=attempts
        )
        
        successes = sum(1 for r in results if r.get("success"))
        
        if successes > 1:
            return RaceFinding(
                endpoint=register_url,
                vulnerability="Account Duplication via Race Condition",
                severity="medium",
                description=f"Created {successes} accounts with same email",
                successful_races=successes,
                total_attempts=attempts,
                evidence={
                    "email": email,
                    "accounts_created": successes,
                },
            )
        
        return None
    
    async def turbo_intruder_style(
        self,
        url: str,
        method: str = "POST",
        body: Dict[str, Any] = None,
        batch_size: int = 50,
        batches: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Turbo Intruder style attack.
        
        Sends requests in large batches for maximum impact.
        """
        logger.info(f"🚀 Turbo Intruder attack on {url}")
        
        all_results = []
        
        for batch in range(batches):
            results = await self.send_concurrent_requests(
                url=url,
                method=method,
                body=body,
                count=batch_size
            )
            all_results.extend(results)
            
            # Brief pause between batches
            await asyncio.sleep(0.1)
        
        total_success = sum(1 for r in all_results if r.get("success"))
        logger.info(f"✅ {total_success}/{len(all_results)} successful")
        
        return all_results


# Quick access
async def test_race(
    url: str,
    body: Dict[str, Any] = None,
    expected_limit: int = 1
) -> Optional[RaceFinding]:
    """Quick race condition test."""
    tester = RaceConditionTester()
    return await tester.test_limit_bypass(url, body=body, expected_limit=expected_limit)
