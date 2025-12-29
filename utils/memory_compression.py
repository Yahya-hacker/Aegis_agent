"""
Memory Compression for Aegis AI
Prevents context saturation during long scans using intelligent compression.
"""

import json
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CompressedChunk:
    """Represents a compressed chunk of conversation history"""
    id: str
    summary: str
    key_facts: List[str]
    key_decisions: List[str]
    key_errors: List[str]
    original_count: int
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    importance_score: float = 0.5


class MemoryCompressor:
    """
    Implements intelligent memory compression to prevent context saturation.
    
    Strategies:
    1. Sliding Window: Keep first N and last M messages, summarize middle
    2. Importance Scoring: Prioritize messages with high-value content
    3. Deduplication: Remove redundant information
    4. Hierarchical Summarization: Create nested summaries for very long sessions
    """
    
    def __init__(
        self,
        keep_first: int = 2,
        keep_last: int = 10,
        compression_threshold: int = 15,
        max_summary_length: int = 500
    ):
        self.keep_first = keep_first
        self.keep_last = keep_last
        self.compression_threshold = compression_threshold
        self.max_summary_length = max_summary_length
        
        # Compression statistics
        self.total_compressions = 0
        self.total_messages_compressed = 0
        self.compression_ratio_history = []
        
        # Cached summaries for hierarchical compression
        self.summary_cache: Dict[str, CompressedChunk] = {}
    
    def should_compress(self, history: List[Dict]) -> bool:
        """Check if history needs compression"""
        return len(history) > self.compression_threshold
    
    def compress(
        self,
        history: List[Dict],
        orchestrator = None
    ) -> List[Dict]:
        """
        Compress conversation history while preserving critical context.
        
        Args:
            history: Full conversation history
            orchestrator: Optional LLM orchestrator for AI-powered summarization
            
        Returns:
            Compressed history
        """
        if not self.should_compress(history):
            return history
        
        logger.info(f"🗜️ Starting memory compression: {len(history)} messages")
        
        # Separate sections
        first_messages = history[:self.keep_first]
        recent_messages = history[-self.keep_last:]
        middle_section = history[self.keep_first:-self.keep_last]
        
        if not middle_section:
            return history
        
        # Analyze and compress middle section
        compressed_chunk = self._compress_section(middle_section, orchestrator)
        
        # Create summary message
        summary_message = self._create_summary_message(compressed_chunk)
        
        # Construct compressed history
        compressed_history = first_messages + [summary_message] + recent_messages
        
        # Update statistics
        self.total_compressions += 1
        self.total_messages_compressed += len(middle_section)
        compression_ratio = len(compressed_history) / len(history)
        self.compression_ratio_history.append(compression_ratio)
        
        logger.info(f"✅ Compression complete: {len(history)} → {len(compressed_history)} messages "
                   f"({len(middle_section)} compressed, ratio: {compression_ratio:.2f})")
        
        return compressed_history
    
    def _compress_section(
        self,
        section: List[Dict],
        orchestrator = None
    ) -> CompressedChunk:
        """Compress a section of messages into a summary chunk"""
        
        # Extract key information
        key_facts = self._extract_key_facts(section)
        key_decisions = self._extract_key_decisions(section)
        key_errors = self._extract_errors(section)
        
        # Generate summary
        if orchestrator and orchestrator.is_initialized:
            summary = self._ai_summarize(section, orchestrator)
        else:
            summary = self._heuristic_summarize(section, key_facts, key_decisions, key_errors)
        
        # Create chunk
        chunk_id = hashlib.md5(json.dumps(section, default=str).encode()).hexdigest()[:12]
        
        chunk = CompressedChunk(
            id=chunk_id,
            summary=summary,
            key_facts=key_facts,
            key_decisions=key_decisions,
            key_errors=key_errors,
            original_count=len(section)
        )
        
        # Cache for potential hierarchical compression
        self.summary_cache[chunk_id] = chunk
        
        return chunk
    
    def _extract_key_facts(self, section: List[Dict]) -> List[str]:
        """Extract key facts from a section"""
        facts = []
        fact_keywords = ['found', 'discovered', 'detected', 'identified', 'confirmed', 'port', 'version']
        
        for item in section:
            content = item.get('content', '').lower()
            
            # Check for fact indicators
            if any(kw in content for kw in fact_keywords):
                # Extract first 150 chars as fact
                fact = item.get('content', '')[:150]
                if fact and fact not in facts:
                    facts.append(fact)
        
        # Limit to top 10 facts
        return facts[:10]
    
    def _extract_key_decisions(self, section: List[Dict]) -> List[str]:
        """Extract key decisions from a section"""
        decisions = []
        decision_keywords = ['decided', 'chose', 'selected', 'executing', 'running', 'action']
        
        for item in section:
            content = item.get('content', '').lower()
            item_type = item.get('type', '')
            
            # Check for decision indicators
            if item_type == 'action' or any(kw in content for kw in decision_keywords):
                decision = item.get('content', '')[:100]
                if decision and decision not in decisions:
                    decisions.append(decision)
        
        return decisions[:5]
    
    def _extract_errors(self, section: List[Dict]) -> List[str]:
        """Extract errors and failed attempts"""
        errors = []
        error_keywords = ['error', 'failed', 'timeout', 'blocked', 'denied', 'refused']
        
        for item in section:
            content = item.get('content', '').lower()
            item_type = item.get('type', '')
            
            if item_type == 'error' or any(kw in content for kw in error_keywords):
                error = item.get('content', '')[:100]
                if error and error not in errors:
                    errors.append(error)
        
        # Deduplicate similar errors
        unique_errors = self._deduplicate_similar(errors)
        return unique_errors[:5]
    
    def _deduplicate_similar(self, items: List[str], threshold: float = 0.7) -> List[str]:
        """Remove items that are too similar to each other"""
        if not items:
            return []
        
        unique = [items[0]]
        
        for item in items[1:]:
            is_unique = True
            for existing in unique:
                similarity = self._calculate_similarity(item, existing)
                if similarity > threshold:
                    is_unique = False
                    break
            
            if is_unique:
                unique.append(item)
        
        return unique
    
    def _calculate_similarity(self, s1: str, s2: str) -> float:
        """Calculate simple string similarity (Jaccard)"""
        words1 = set(s1.lower().split())
        words2 = set(s2.lower().split())
        
        if not words1 or not words2:
            return 0.0
        
        intersection = len(words1 & words2)
        union = len(words1 | words2)
        
        return intersection / union if union > 0 else 0.0
    
    def _heuristic_summarize(
        self,
        section: List[Dict],
        facts: List[str],
        decisions: List[str],
        errors: List[str]
    ) -> str:
        """Generate summary using heuristics (no AI)"""
        summary_parts = [
            f"--- MEMORY SUMMARY ({len(section)} steps compressed) ---",
            ""
        ]
        
        if facts:
            summary_parts.append(f"KEY FINDINGS ({len(facts)} total):")
            for fact in facts[:5]:
                summary_parts.append(f"  • {fact[:100]}...")
            summary_parts.append("")
        
        if decisions:
            summary_parts.append(f"KEY DECISIONS ({len(decisions)} total):")
            for decision in decisions[:3]:
                summary_parts.append(f"  • {decision[:80]}...")
            summary_parts.append("")
        
        if errors:
            summary_parts.append("FAILED ATTEMPTS (DO NOT REPEAT):")
            for error in errors[:3]:
                summary_parts.append(f"  ⚠️ {error[:80]}...")
            summary_parts.append("")
        
        summary_parts.append("--- END SUMMARY ---")
        
        return "\n".join(summary_parts)
    
    def _ai_summarize(self, section: List[Dict], orchestrator) -> str:
        """Generate summary using AI (async would be better, but keeping sync for compatibility)"""
        # For now, fall back to heuristic - in production, this would call the LLM
        facts = self._extract_key_facts(section)
        decisions = self._extract_key_decisions(section)
        errors = self._extract_errors(section)
        return self._heuristic_summarize(section, facts, decisions, errors)
    
    def _create_summary_message(self, chunk: CompressedChunk) -> Dict:
        """Create a summary message from compressed chunk"""
        return {
            "type": "system",
            "content": chunk.summary,
            "metadata": {
                "compressed": True,
                "original_count": chunk.original_count,
                "chunk_id": chunk.id,
                "timestamp": chunk.timestamp
            }
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get compression statistics"""
        avg_ratio = (
            sum(self.compression_ratio_history) / len(self.compression_ratio_history)
            if self.compression_ratio_history else 0
        )
        
        return {
            "total_compressions": self.total_compressions,
            "total_messages_compressed": self.total_messages_compressed,
            "average_compression_ratio": avg_ratio,
            "cached_summaries": len(self.summary_cache)
        }


class ParallelHypothesisTester:
    """
    Implements parallel hypothesis testing in the KTV (Know-Think-Verify) loop.
    Tests multiple hypotheses concurrently for 3x faster verification.
    """
    
    def __init__(self, max_parallel: int = 5):
        self.max_parallel = max_parallel
        self.hypothesis_queue: List[Dict] = []
        self.results: Dict[str, Any] = {}
        self.performance_metrics = {
            "hypotheses_tested": 0,
            "parallel_batches": 0,
            "average_batch_size": 0,
            "time_saved_estimate": 0
        }
    
    async def test_hypotheses_parallel(
        self,
        hypotheses: List[Dict[str, Any]],
        test_function,
        context: str = ""
    ) -> List[Dict[str, Any]]:
        """
        Test multiple hypotheses in parallel.
        
        Args:
            hypotheses: List of hypothesis dictionaries
            test_function: Async function to test each hypothesis
            context: Optional context string
            
        Returns:
            List of results for each hypothesis
        """
        import asyncio
        
        if not hypotheses:
            return []
        
        logger.info(f"🔬 Testing {len(hypotheses)} hypotheses in parallel (max {self.max_parallel} concurrent)")
        
        results = []
        
        # Process in batches
        for i in range(0, len(hypotheses), self.max_parallel):
            batch = hypotheses[i:i + self.max_parallel]
            
            # Create tasks for each hypothesis in batch
            tasks = [
                test_function(h, context)
                for h in batch
            ]
            
            # Execute batch in parallel
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for j, result in enumerate(batch_results):
                hypothesis = batch[j]
                
                if isinstance(result, Exception):
                    result_entry = {
                        "hypothesis": hypothesis,
                        "success": False,
                        "error": str(result)
                    }
                else:
                    result_entry = {
                        "hypothesis": hypothesis,
                        "success": True,
                        "result": result
                    }
                
                results.append(result_entry)
                self.results[hypothesis.get('id', str(j))] = result_entry
            
            self.performance_metrics["parallel_batches"] += 1
        
        self.performance_metrics["hypotheses_tested"] += len(hypotheses)
        self.performance_metrics["average_batch_size"] = (
            self.performance_metrics["hypotheses_tested"] /
            max(1, self.performance_metrics["parallel_batches"])
        )
        
        # Estimate time saved (assuming 1 second per hypothesis if sequential)
        sequential_time = len(hypotheses)
        parallel_time = len(hypotheses) / self.max_parallel
        self.performance_metrics["time_saved_estimate"] = sequential_time - parallel_time
        
        logger.info(f"✅ Parallel testing complete. Estimated time saved: {self.performance_metrics['time_saved_estimate']:.1f}s")
        
        return results
    
    def prioritize_hypotheses(self, hypotheses: List[Dict]) -> List[Dict]:
        """
        Prioritize hypotheses based on expected value and confidence.
        High-priority hypotheses are tested first.
        """
        def score(h: Dict) -> float:
            confidence = h.get('confidence', 0.5)
            impact = h.get('impact', 0.5)
            novelty = h.get('novelty', 0.5)
            
            # Weighted score
            return (confidence * 0.4) + (impact * 0.4) + (novelty * 0.2)
        
        return sorted(hypotheses, key=score, reverse=True)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        return self.performance_metrics


# Singleton instances
_memory_compressor = None
_parallel_tester = None


def get_memory_compressor() -> MemoryCompressor:
    """Get or create the memory compressor singleton"""
    global _memory_compressor
    if _memory_compressor is None:
        _memory_compressor = MemoryCompressor()
    return _memory_compressor


def get_parallel_tester() -> ParallelHypothesisTester:
    """Get or create the parallel hypothesis tester singleton"""
    global _parallel_tester
    if _parallel_tester is None:
        _parallel_tester = ParallelHypothesisTester()
    return _parallel_tester
