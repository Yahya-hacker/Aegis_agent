"""
Nexus v2.0 - Long-term Vector Memory
=====================================

Persistent memory using vector embeddings for:
- Deduplication (don't report known issues)
- Attack pattern learning
- Cross-session knowledge transfer
"""

import os
import json
import logging
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from nexus.config import get_config

logger = logging.getLogger(__name__)

# Try to import vector store backends
try:
    import chromadb
    from chromadb.config import Settings
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False
    logger.warning("⚠️ ChromaDB not installed. Run: pip install chromadb")


@dataclass
class MemoryEntry:
    """A single memory entry."""
    id: str
    content: str
    metadata: Dict[str, Any]
    embedding: Optional[List[float]] = None
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "content": self.content,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


class VectorMemory:
    """
    Long-term vector memory for Nexus.
    
    Stores:
    - Discovered vulnerabilities (for dedup)
    - Attack patterns that worked
    - Failed attempts (to avoid repetition)
    - Target-specific knowledge
    """
    
    def __init__(self, collection_name: str = "nexus_memory"):
        self.config = get_config()
        self.collection_name = collection_name
        self._client = None
        self._collection = None
        
        # Initialize based on config
        if self.config.data.vector_store == "chromadb" and CHROMADB_AVAILABLE:
            self._init_chromadb()
        else:
            logger.warning("⚠️ Using in-memory fallback for vector store")
            self._fallback_store: Dict[str, MemoryEntry] = {}
    
    def _init_chromadb(self):
        """Initialize ChromaDB client."""
        persist_dir = self.config.data.chromadb_path
        Path(persist_dir).mkdir(parents=True, exist_ok=True)
        
        self._client = chromadb.PersistentClient(
            path=persist_dir,
            settings=Settings(anonymized_telemetry=False)
        )
        
        self._collection = self._client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"}
        )
        
        logger.info(f"🧠 Vector memory initialized: {persist_dir}")
    
    def _generate_id(self, content: str, metadata: Dict[str, Any]) -> str:
        """Generate unique ID for a memory entry."""
        key = f"{content}:{json.dumps(metadata, sort_keys=True)}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]
    
    async def store(
        self,
        content: str,
        metadata: Dict[str, Any],
        entry_type: str = "general"
    ) -> str:
        """
        Store a memory entry.
        
        Args:
            content: Text content to store
            metadata: Associated metadata
            entry_type: Type of entry (vulnerability, pattern, knowledge)
        
        Returns:
            Entry ID
        """
        entry_id = self._generate_id(content, metadata)
        metadata = {
            **metadata,
            "type": entry_type,
            "timestamp": datetime.now().isoformat(),
        }
        
        if self._collection is not None:
            # ChromaDB handles embedding automatically
            self._collection.upsert(
                ids=[entry_id],
                documents=[content],
                metadatas=[metadata]
            )
        else:
            # Fallback
            self._fallback_store[entry_id] = MemoryEntry(
                id=entry_id,
                content=content,
                metadata=metadata,
            )
        
        logger.debug(f"📝 Stored memory: {entry_id[:8]}... ({entry_type})")
        return entry_id
    
    async def search(
        self,
        query: str,
        n_results: int = 5,
        filter_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for similar memories.
        
        Args:
            query: Search query
            n_results: Number of results
            filter_type: Optional type filter
        
        Returns:
            List of matching memories
        """
        if self._collection is not None:
            where = {"type": filter_type} if filter_type else None
            
            results = self._collection.query(
                query_texts=[query],
                n_results=n_results,
                where=where
            )
            
            memories = []
            for i, doc in enumerate(results.get("documents", [[]])[0]):
                memories.append({
                    "id": results["ids"][0][i],
                    "content": doc,
                    "metadata": results["metadatas"][0][i] if results.get("metadatas") else {},
                    "distance": results["distances"][0][i] if results.get("distances") else 0,
                })
            return memories
        else:
            # Simple fallback search
            query_lower = query.lower()
            matches = []
            for entry in self._fallback_store.values():
                if filter_type and entry.metadata.get("type") != filter_type:
                    continue
                if query_lower in entry.content.lower():
                    matches.append(entry.to_dict())
            return matches[:n_results]
    
    async def is_duplicate(
        self,
        vulnerability: str,
        target: str,
        threshold: float = 0.85
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if a vulnerability is a duplicate.
        
        Args:
            vulnerability: Vulnerability description
            target: Target domain
            threshold: Similarity threshold
        
        Returns:
            (is_duplicate, existing_id)
        """
        results = await self.search(
            query=f"{target} {vulnerability}",
            n_results=3,
            filter_type="vulnerability"
        )
        
        for result in results:
            # ChromaDB uses distance (lower = more similar)
            distance = result.get("distance", 1.0)
            similarity = 1 - distance
            
            if similarity >= threshold:
                logger.info(f"🔄 Duplicate found: {result['id'][:8]}... (similarity: {similarity:.2%})")
                return True, result["id"]
        
        return False, None
    
    async def store_vulnerability(
        self,
        vuln_type: str,
        target: str,
        endpoint: str,
        severity: str,
        description: str,
        poc: str = ""
    ) -> str:
        """Store a discovered vulnerability."""
        content = f"""
Vulnerability: {vuln_type}
Target: {target}
Endpoint: {endpoint}
Severity: {severity}
Description: {description}
PoC: {poc}
""".strip()
        
        return await self.store(
            content=content,
            metadata={
                "vuln_type": vuln_type,
                "target": target,
                "endpoint": endpoint,
                "severity": severity,
            },
            entry_type="vulnerability"
        )
    
    async def store_attack_pattern(
        self,
        pattern_name: str,
        target_type: str,
        payload: str,
        success: bool
    ) -> str:
        """Store an attack pattern that worked (or didn't)."""
        content = f"""
Pattern: {pattern_name}
Target Type: {target_type}
Payload: {payload}
Success: {success}
""".strip()
        
        return await self.store(
            content=content,
            metadata={
                "pattern": pattern_name,
                "target_type": target_type,
                "success": success,
            },
            entry_type="attack_pattern"
        )
    
    async def get_successful_patterns(self, target_type: str) -> List[Dict[str, Any]]:
        """Get attack patterns that worked for a target type."""
        results = await self.search(
            query=f"success true {target_type}",
            n_results=10,
            filter_type="attack_pattern"
        )
        return [r for r in results if r.get("metadata", {}).get("success")]
    
    async def store_knowledge(
        self,
        category: str,
        key: str,
        value: str,
        target: str = ""
    ) -> str:
        """Store general knowledge."""
        content = f"""
Category: {category}
Key: {key}
Value: {value}
Target: {target}
""".strip()
        
        return await self.store(
            content=content,
            metadata={
                "category": category,
                "key": key,
                "target": target,
            },
            entry_type="knowledge"
        )
    
    async def get_knowledge(self, category: str, target: str = "") -> List[Dict[str, Any]]:
        """Retrieve knowledge for a category/target."""
        query = f"{category} {target}".strip()
        return await self.search(
            query=query,
            n_results=20,
            filter_type="knowledge"
        )
    
    def get_stats(self) -> Dict[str, int]:
        """Get memory statistics."""
        if self._collection is not None:
            return {
                "total_entries": self._collection.count(),
                "collection": self.collection_name,
            }
        else:
            return {
                "total_entries": len(self._fallback_store),
                "collection": "in_memory_fallback",
            }


# Singleton
_memory: Optional[VectorMemory] = None


def get_vector_memory(collection: str = "nexus_memory") -> VectorMemory:
    """Get the global vector memory instance."""
    global _memory
    if _memory is None:
        _memory = VectorMemory(collection)
    return _memory
