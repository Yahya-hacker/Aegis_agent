# tools/race_engine.py
# --- VERSION 7.5 - Chronos Concurrency Engine ---
"""
The "Chronos" Concurrency Engine - Race Condition Detection

A "Gatekeeper" socket engine that opens multiple connections, sends the first
byte of requests to all connections, waits, and then sends the last byte to all
simultaneously to detect race conditions and time-of-check-time-of-use (TOCTOU) bugs.
"""

import asyncio
import aiohttp
import logging
import time
from typing import Dict, List, Any, Optional
from collections import Counter

logger = logging.getLogger(__name__)


class ChronosEngine:
    """
    Synchronization Barrier Pattern for Race Condition Testing.
    
    This engine:
    1. Opens multiple concurrent connections
    2. Sends requests simultaneously using barrier synchronization
    3. Analyzes responses for race condition indicators
    """
    
    def __init__(self):
        """Initialize the Chronos race engine"""
        self.default_threads = 30
        self.results_history: List[Dict] = []
        
    async def execute_race(
        self,
        url: str,
        headers: Dict[str, str] = None,
        data: Any = None,
        method: str = "POST",
        threads: int = 30,
        delay_before_release: float = 0.0
    ) -> Dict[str, Any]:
        """
        Execute a race condition attack using synchronization barrier pattern.
        
        Args:
            url: Target URL
            headers: HTTP headers
            data: Request payload (dict for JSON, str for raw data)
            method: HTTP method (POST, PUT, etc.)
            threads: Number of concurrent threads
            delay_before_release: Delay in seconds before releasing all requests
        
        Returns:
            Dictionary with race test results and anomaly analysis
        """
        logger.info(f"[Chronos] Preparing race condition test with {threads} threads")
        
        # Create synchronization barrier
        barrier = asyncio.Barrier(threads)
        results = []
        
        # Configure session
        connector = aiohttp.TCPConnector(limit=threads + 10, limit_per_host=threads + 10)
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers or {}
        ) as session:
            # Create attack workers
            tasks = []
            for worker_id in range(threads):
                task = self._attack_worker(
                    session=session,
                    worker_id=worker_id,
                    url=url,
                    method=method,
                    data=data,
                    barrier=barrier,
                    delay_before_release=delay_before_release
                )
                tasks.append(task)
            
            # Execute all workers
            logger.info(f"[Chronos] Releasing {threads} requests simultaneously...")
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions
            valid_results = [r for r in results if not isinstance(r, Exception)]
            error_results = [r for r in results if isinstance(r, Exception)]
            
            if error_results:
                logger.warning(f"[Chronos] {len(error_results)} requests failed with errors")
        
        # Analyze results for race condition indicators
        analysis = self._analyze_results_for_anomalies(valid_results)
        
        # Store in history
        race_test = {
            "timestamp": time.time(),
            "url": url,
            "threads": threads,
            "total_requests": len(valid_results),
            "errors": len(error_results),
            "analysis": analysis
        }
        self.results_history.append(race_test)
        
        logger.info(f"[Chronos] Race test completed. Anomalies detected: {analysis['has_anomaly']}")
        
        return {
            "success": True,
            "results": valid_results,
            "total_requests": len(valid_results),
            "errors": len(error_results),
            "analysis": analysis,
            "summary": self._generate_summary(valid_results, analysis)
        }
    
    async def _attack_worker(
        self,
        session: aiohttp.ClientSession,
        worker_id: int,
        url: str,
        method: str,
        data: Any,
        barrier: asyncio.Barrier,
        delay_before_release: float
    ) -> Dict[str, Any]:
        """
        Individual attack worker that waits at the barrier before executing.
        
        Args:
            session: aiohttp session
            worker_id: Unique worker identifier
            url: Target URL
            method: HTTP method
            data: Request data
            barrier: Synchronization barrier
            delay_before_release: Optional delay before releasing
        
        Returns:
            Dictionary with request results
        """
        try:
            # Wait at the barrier - all workers will wait here
            await barrier.wait()
            
            # Optional delay before release (for fine-tuning)
            if delay_before_release > 0:
                await asyncio.sleep(delay_before_release)
            
            # RELEASE THE KRAKEN: All threads execute at this exact moment
            start_time = time.time()
            
            if method.upper() == "GET":
                async with session.get(url, ssl=False) as response:
                    content = await response.text()
                    elapsed = time.time() - start_time
                    
                    return {
                        "worker_id": worker_id,
                        "status_code": response.status,
                        "content_length": len(content),
                        "response_time": elapsed,
                        "headers": dict(response.headers),
                        "content": content,
                        "timestamp": start_time
                    }
            else:
                # POST, PUT, etc.
                kwargs = {"ssl": False}
                
                if isinstance(data, dict):
                    kwargs["json"] = data
                elif isinstance(data, str):
                    kwargs["data"] = data
                
                async with session.request(method.upper(), url, **kwargs) as response:
                    content = await response.text()
                    elapsed = time.time() - start_time
                    
                    return {
                        "worker_id": worker_id,
                        "status_code": response.status,
                        "content_length": len(content),
                        "response_time": elapsed,
                        "headers": dict(response.headers),
                        "content": content,
                        "timestamp": start_time
                    }
                    
        except Exception as e:
            logger.debug(f"[Chronos] Worker {worker_id} error: {e}")
            return {
                "worker_id": worker_id,
                "error": str(e),
                "timestamp": time.time()
            }
    
    def _analyze_results_for_anomalies(self, results: List[Dict]) -> Dict[str, Any]:
        """
        Analyze results for race condition indicators.
        
        Race condition indicators:
        1. Different status codes across requests (some succeed, some fail)
        2. Different content lengths (inconsistent state)
        3. Different response content (data inconsistency)
        4. Sequential IDs with gaps (counter race condition)
        
        Args:
            results: List of request results
        
        Returns:
            Dictionary with analysis findings
        """
        if not results:
            return {
                "has_anomaly": False,
                "confidence": 0,
                "findings": []
            }
        
        findings = []
        confidence = 0
        
        # Filter valid results
        valid_results = [r for r in results if "error" not in r]
        
        if not valid_results:
            return {
                "has_anomaly": False,
                "confidence": 0,
                "findings": ["All requests failed"]
            }
        
        # Analyze status codes
        status_codes = [r["status_code"] for r in valid_results]
        status_counter = Counter(status_codes)
        unique_status_codes = len(status_counter)
        
        if unique_status_codes > 1:
            findings.append({
                "type": "status_code_variance",
                "severity": "HIGH",
                "description": f"Detected {unique_status_codes} different status codes: {dict(status_counter)}",
                "indicator": "Possible race condition - inconsistent request handling"
            })
            confidence += 40
        
        # Analyze content lengths
        content_lengths = [r["content_length"] for r in valid_results]
        unique_lengths = len(set(content_lengths))
        
        if unique_lengths > 1:
            length_counter = Counter(content_lengths)
            # If we have minority responses with different lengths
            if len(length_counter) > 1 and min(length_counter.values()) < len(valid_results) * 0.5:
                findings.append({
                    "type": "content_length_variance",
                    "severity": "MEDIUM",
                    "description": f"Detected {unique_lengths} different content lengths: {dict(length_counter)}",
                    "indicator": "Possible race condition - inconsistent response data"
                })
                confidence += 30
        
        # Analyze response content for variations
        if len(valid_results) >= 5:
            content_hashes = [hash(r["content"]) for r in valid_results]
            unique_content = len(set(content_hashes))
            
            # If more than 10% of responses differ
            if unique_content > 1 and unique_content > len(valid_results) * 0.1:
                findings.append({
                    "type": "content_variance",
                    "severity": "HIGH",
                    "description": f"{unique_content} unique responses out of {len(valid_results)} requests",
                    "indicator": "Strong indicator of race condition - inconsistent application state"
                })
                confidence += 50
        
        # Check for error rate anomalies
        error_count = len([r for r in results if "error" in r])
        error_rate = error_count / len(results) if results else 0
        
        if error_rate > 0.1:  # More than 10% errors
            findings.append({
                "type": "high_error_rate",
                "severity": "MEDIUM",
                "description": f"{error_rate*100:.1f}% of requests failed",
                "indicator": "Possible resource exhaustion or race condition in error handling"
            })
            confidence += 20
        
        # Analyze response times for synchronization
        response_times = [r["response_time"] for r in valid_results]
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            max_time = max(response_times)
            min_time = min(response_times)
            time_variance = max_time - min_time
            
            # High variance in response times could indicate resource contention
            if time_variance > avg_time * 2:
                findings.append({
                    "type": "response_time_variance",
                    "severity": "LOW",
                    "description": f"Response time variance: {time_variance:.3f}s (avg: {avg_time:.3f}s)",
                    "indicator": "Possible resource contention under concurrent load"
                })
                confidence += 10
        
        # Check for sequential identifiers or counters in responses
        # This could indicate a counter race condition
        for result in valid_results[:5]:  # Sample first 5 responses
            content = result.get("content", "")
            # Look for numeric patterns that might be IDs
            import re
            numbers = re.findall(r'\b\d{3,}\b', content)
            if numbers:
                findings.append({
                    "type": "potential_counter_detected",
                    "severity": "INFO",
                    "description": f"Detected numeric values in response: {numbers[:3]}",
                    "indicator": "Check if these are sequential IDs that could race"
                })
                break
        
        # Cap confidence at 100
        confidence = min(confidence, 100)
        
        has_anomaly = confidence >= 30  # Threshold for anomaly detection
        
        return {
            "has_anomaly": has_anomaly,
            "confidence": confidence,
            "findings": findings,
            "statistics": {
                "total_requests": len(results),
                "successful_requests": len(valid_results),
                "failed_requests": error_count,
                "unique_status_codes": unique_status_codes,
                "unique_content_lengths": unique_lengths,
                "status_code_distribution": dict(status_counter)
            }
        }
    
    def _generate_summary(self, results: List[Dict], analysis: Dict) -> str:
        """
        Generate human-readable summary of race condition test.
        
        Args:
            results: Test results
            analysis: Analysis findings
        
        Returns:
            Summary string
        """
        summary = "Race Condition Test Summary:\n"
        summary += f"  Total Requests: {len(results)}\n"
        summary += f"  Anomaly Detected: {analysis['has_anomaly']}\n"
        summary += f"  Confidence: {analysis['confidence']}%\n"
        
        if analysis['findings']:
            summary += f"\nFindings ({len(analysis['findings'])}):\n"
            for finding in analysis['findings']:
                summary += f"  [{finding['severity']}] {finding['description']}\n"
        
        return summary
    
    async def test_counter_race(
        self,
        url: str,
        data: Dict[str, Any],
        threads: int = 50,
        headers: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        Specialized test for counter/ID race conditions.
        
        This test is useful for:
        - Coupon code generation
        - Order ID assignment
        - Account creation with sequential IDs
        - Any resource with limited quantity
        
        Args:
            url: Target URL
            data: Request data
            threads: Number of concurrent requests (default: 50)
            headers: HTTP headers
        
        Returns:
            Analysis of potential counter race conditions
        """
        logger.info(f"[Chronos] Testing for counter race conditions with {threads} threads")
        
        result = await self.execute_race(
            url=url,
            headers=headers,
            data=data,
            method="POST",
            threads=threads
        )
        
        # Additional analysis for counter races
        valid_results = [r for r in result["results"] if "error" not in r]
        
        # Extract potential IDs from responses
        import re
        extracted_ids = []
        for r in valid_results:
            content = r.get("content", "")
            # Look for common ID patterns
            numbers = re.findall(r'"id"\s*:\s*(\d+)|"order_id"\s*:\s*"?(\d+)"?|"transaction"\s*:\s*"?(\d+)"?', content)
            for match in numbers:
                for num in match:
                    if num:
                        extracted_ids.append(int(num))
        
        if extracted_ids:
            extracted_ids.sort()
            result["analysis"]["extracted_ids"] = extracted_ids[:10]  # Sample
            
            # Check for duplicates
            duplicates = len(extracted_ids) - len(set(extracted_ids))
            if duplicates > 0:
                result["analysis"]["findings"].append({
                    "type": "duplicate_ids",
                    "severity": "CRITICAL",
                    "description": f"Found {duplicates} duplicate IDs out of {len(extracted_ids)} total",
                    "indicator": "CONFIRMED counter race condition - multiple requests got same ID"
                })
                result["analysis"]["confidence"] = 100
                result["analysis"]["has_anomaly"] = True
            
            # Check for gaps in sequential IDs
            if len(set(extracted_ids)) > 2:
                gaps = []
                sorted_ids = sorted(set(extracted_ids))
                for i in range(len(sorted_ids) - 1):
                    gap = sorted_ids[i + 1] - sorted_ids[i]
                    if gap > 1:
                        gaps.append(gap)
                
                if gaps:
                    result["analysis"]["findings"].append({
                        "type": "id_gaps",
                        "severity": "INFO",
                        "description": f"Detected gaps in ID sequence: {gaps[:5]}",
                        "indicator": "Possible lost updates or other concurrent transactions"
                    })
        
        return result


# Singleton instance
_chronos_engine_instance = None

def get_chronos_engine() -> ChronosEngine:
    """Get or create the singleton Chronos engine instance"""
    global _chronos_engine_instance
    if _chronos_engine_instance is None:
        _chronos_engine_instance = ChronosEngine()
    return _chronos_engine_instance
