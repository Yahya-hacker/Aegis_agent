"""
HTTP Replay Memory with Vector Database (RAG)

This module implements a vector database for storing and querying HTTP interactions.
It allows the agent to:
1. Store HTTP requests and responses with embeddings
2. Query similar past interactions: "Have we seen this CSRF token format before?"
3. Bypass short-term context window limits by using semantic search
4. Learn from past interactions to avoid repeating mistakes

The implementation uses TF-IDF vectorization for simplicity and efficiency,
avoiding the need for external embedding models while still providing
effective similarity search.
"""

import json
import hashlib
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from pathlib import Path
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import pickle

logger = logging.getLogger(__name__)


class HTTPInteraction:
    """Represents a single HTTP request-response interaction"""
    
    def __init__(
        self,
        request: Dict[str, Any],
        response: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
        interaction_id: Optional[str] = None
    ):
        """
        Initialize an HTTP interaction.
        
        Args:
            request: Request details (method, url, headers, body, etc.)
            response: Response details (status, headers, body, etc.)
            metadata: Additional metadata (timestamp, tags, etc.)
            interaction_id: Unique identifier (auto-generated if not provided)
        """
        self.request = request
        self.response = response
        self.metadata = metadata or {}
        
        # Generate ID if not provided
        if interaction_id:
            self.id = interaction_id
        else:
            # Create hash from request details
            req_str = f"{request.get('method', '')}:{request.get('url', '')}:{request.get('body', '')}"
            self.id = hashlib.sha256(req_str.encode()).hexdigest()[:16]
        
        # Add timestamp if not present
        if 'timestamp' not in self.metadata:
            self.metadata['timestamp'] = datetime.now().isoformat()
    
    def to_text(self) -> str:
        """
        Convert interaction to searchable text.
        
        Returns:
            Combined text representation of request and response
        """
        parts = []
        
        # Request parts
        parts.append(f"Method: {self.request.get('method', 'UNKNOWN')}")
        parts.append(f"URL: {self.request.get('url', '')}")
        
        # Request headers
        if 'headers' in self.request:
            for key, value in self.request['headers'].items():
                parts.append(f"Request-Header {key}: {value}")
        
        # Request body (truncated)
        if 'body' in self.request and self.request['body']:
            body = str(self.request['body'])[:500]  # Limit length
            parts.append(f"Request-Body: {body}")
        
        # Response parts
        parts.append(f"Status: {self.response.get('status_code', 0)}")
        
        # Response headers
        if 'headers' in self.response:
            for key, value in self.response['headers'].items():
                parts.append(f"Response-Header {key}: {value}")
        
        # Response body (truncated)
        if 'body' in self.response and self.response['body']:
            body = str(self.response['body'])[:500]  # Limit length
            parts.append(f"Response-Body: {body}")
        
        return " ".join(parts)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'request': self.request,
            'response': self.response,
            'metadata': self.metadata
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'HTTPInteraction':
        """Create from dictionary"""
        return HTTPInteraction(
            request=data['request'],
            response=data['response'],
            metadata=data.get('metadata', {}),
            interaction_id=data.get('id')
        )


class HTTPReplayMemory:
    """
    Vector database for HTTP interaction replay and similarity search.
    """
    
    def __init__(self, storage_dir: Optional[Path] = None, max_interactions: int = 1000):
        """
        Initialize the HTTP replay memory.
        
        Args:
            storage_dir: Directory to store interactions (default: data/http_memory/)
            max_interactions: Maximum number of interactions to keep in memory
        """
        self.storage_dir = storage_dir or Path("data/http_memory")
        self.storage_dir.mkdir(exist_ok=True, parents=True)
        
        self.max_interactions = max_interactions
        self.interactions: List[HTTPInteraction] = []
        self.vectorizer = TfidfVectorizer(
            max_features=500,  # Limit vocabulary size
            ngram_range=(1, 2),  # Unigrams and bigrams
            min_df=1,
            stop_words=None  # Keep all words for technical content
        )
        self.vectors = None  # Will be computed when needed
        
        # Storage files
        self.interactions_file = self.storage_dir / "interactions.pkl"
        self.vectorizer_file = self.storage_dir / "vectorizer.pkl"
        
        # Load existing data
        self._load()
    
    def _load(self) -> None:
        """Load interactions and vectorizer from disk"""
        # Load interactions
        if self.interactions_file.exists():
            try:
                with open(self.interactions_file, 'rb') as f:
                    data = pickle.load(f)
                    self.interactions = [HTTPInteraction.from_dict(d) for d in data]
                    logger.info(f"📥 Loaded {len(self.interactions)} HTTP interactions")
            except Exception as e:
                logger.warning(f"Failed to load interactions: {e}")
                self.interactions = []
        
        # Load vectorizer if we have interactions
        if self.vectorizer_file.exists() and self.interactions:
            try:
                with open(self.vectorizer_file, 'rb') as f:
                    self.vectorizer = pickle.load(f)
                    # Rebuild vectors
                    texts = [interaction.to_text() for interaction in self.interactions]
                    self.vectors = self.vectorizer.transform(texts)
                    logger.info(f"📥 Loaded vectorizer and rebuilt vectors")
            except Exception as e:
                logger.warning(f"Failed to load vectorizer: {e}")
    
    def _save(self) -> None:
        """Save interactions and vectorizer to disk"""
        try:
            # Save interactions
            data = [interaction.to_dict() for interaction in self.interactions]
            with open(self.interactions_file, 'wb') as f:
                pickle.dump(data, f)
            
            # Save vectorizer if we have built it
            if self.vectors is not None:
                with open(self.vectorizer_file, 'wb') as f:
                    pickle.dump(self.vectorizer, f)
            
            logger.debug(f"💾 Saved {len(self.interactions)} interactions")
        except Exception as e:
            logger.error(f"Failed to save interactions: {e}")
    
    def add_interaction(
        self,
        request: Dict[str, Any],
        response: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Add an HTTP interaction to the memory.
        
        Args:
            request: Request details
            response: Response details
            metadata: Additional metadata
        
        Returns:
            Interaction ID
        """
        interaction = HTTPInteraction(request, response, metadata)
        
        # Add to list
        self.interactions.append(interaction)
        
        # Enforce max size
        if len(self.interactions) > self.max_interactions:
            # Remove oldest interactions
            removed = len(self.interactions) - self.max_interactions
            self.interactions = self.interactions[removed:]
            logger.debug(f"Removed {removed} old interaction(s)")
            # Invalidate vectors - they'll be rebuilt on next search
            self.vectors = None
        
        # Rebuild vectors (we do this lazily on search to batch updates)
        self.vectors = None
        
        # Save to disk
        self._save()
        
        logger.info(f"✅ Added HTTP interaction: {interaction.request.get('method', '')} {interaction.request.get('url', '')[:50]}")
        
        return interaction.id
    
    def _rebuild_vectors(self) -> None:
        """Rebuild TF-IDF vectors from all interactions"""
        if not self.interactions:
            self.vectors = None
            return
        
        texts = [interaction.to_text() for interaction in self.interactions]
        
        try:
            # Fit and transform
            self.vectors = self.vectorizer.fit_transform(texts)
            logger.debug(f"Rebuilt vectors for {len(self.interactions)} interactions")
        except Exception as e:
            logger.error(f"Failed to rebuild vectors: {e}")
            self.vectors = None
    
    def search_similar(
        self,
        query: str,
        top_k: int = 5,
        min_similarity: float = 0.1
    ) -> List[Tuple[HTTPInteraction, float]]:
        """
        Search for similar past interactions.
        
        Args:
            query: Query text (e.g., "CSRF token in cookie", "Authentication header format")
            top_k: Number of results to return
            min_similarity: Minimum cosine similarity threshold (0-1)
        
        Returns:
            List of (interaction, similarity_score) tuples, sorted by similarity
        """
        if not self.interactions:
            logger.debug("No interactions in memory")
            return []
        
        # Rebuild vectors if needed
        if self.vectors is None:
            self._rebuild_vectors()
        
        if self.vectors is None:
            logger.warning("Failed to build vectors")
            return []
        
        try:
            # Transform query
            query_vector = self.vectorizer.transform([query])
            
            # Compute similarities
            similarities = cosine_similarity(query_vector, self.vectors)[0]
            
            # Get top-k indices
            top_indices = np.argsort(similarities)[::-1][:top_k]
            
            # Filter by minimum similarity
            results = []
            for idx in top_indices:
                similarity = similarities[idx]
                if similarity >= min_similarity:
                    results.append((self.interactions[idx], float(similarity)))
            
            logger.info(f"🔍 Found {len(results)} similar interaction(s) for query: '{query[:50]}...'")
            
            return results
            
        except Exception as e:
            logger.error(f"Search error: {e}")
            return []
    
    def search_by_pattern(
        self,
        pattern: Dict[str, Any],
        top_k: int = 5
    ) -> List[Tuple[HTTPInteraction, float]]:
        """
        Search for interactions matching a pattern.
        
        Args:
            pattern: Pattern dict with keys like:
                - url_contains: str
                - method: str
                - status_code: int
                - header_contains: Dict[str, str]
            top_k: Number of results to return
        
        Returns:
            List of (interaction, match_score) tuples
        """
        matches = []
        
        for interaction in self.interactions:
            score = 0.0
            checks = 0
            
            # Check URL pattern
            if 'url_contains' in pattern:
                checks += 1
                if pattern['url_contains'].lower() in interaction.request.get('url', '').lower():
                    score += 1.0
            
            # Check method
            if 'method' in pattern:
                checks += 1
                if pattern['method'].upper() == interaction.request.get('method', '').upper():
                    score += 1.0
            
            # Check status code
            if 'status_code' in pattern:
                checks += 1
                if pattern['status_code'] == interaction.response.get('status_code'):
                    score += 1.0
            
            # Check headers
            if 'header_contains' in pattern:
                for header, value in pattern['header_contains'].items():
                    checks += 1
                    resp_headers = interaction.response.get('headers', {})
                    if header in resp_headers and value.lower() in str(resp_headers[header]).lower():
                        score += 1.0
            
            if checks > 0:
                match_score = score / checks
                if match_score > 0:
                    matches.append((interaction, match_score))
        
        # Sort by score and return top-k
        matches.sort(key=lambda x: x[1], reverse=True)
        results = matches[:top_k]
        
        logger.info(f"🔍 Found {len(results)} interaction(s) matching pattern")
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get memory statistics.
        
        Returns:
            Dictionary with statistics
        """
        if not self.interactions:
            return {
                'total_interactions': 0,
                'oldest': None,
                'newest': None,
                'methods': {},
                'status_codes': {}
            }
        
        methods = {}
        status_codes = {}
        
        for interaction in self.interactions:
            # Count methods
            method = interaction.request.get('method', 'UNKNOWN')
            methods[method] = methods.get(method, 0) + 1
            
            # Count status codes
            status = interaction.response.get('status_code', 0)
            status_codes[status] = status_codes.get(status, 0) + 1
        
        timestamps = [
            datetime.fromisoformat(i.metadata.get('timestamp', ''))
            for i in self.interactions
            if 'timestamp' in i.metadata
        ]
        
        return {
            'total_interactions': len(self.interactions),
            'oldest': min(timestamps).isoformat() if timestamps else None,
            'newest': max(timestamps).isoformat() if timestamps else None,
            'methods': methods,
            'status_codes': status_codes,
            'vector_dimension': self.vectors.shape[1] if self.vectors is not None else 0
        }
    
    def clear(self) -> None:
        """Clear all interactions"""
        self.interactions = []
        self.vectors = None
        self._save()
        logger.info("🗑️ Cleared HTTP replay memory")


# Singleton instance
_replay_memory = None


def get_replay_memory() -> HTTPReplayMemory:
    """
    Get the singleton HTTPReplayMemory instance.
    
    Returns:
        HTTPReplayMemory instance
    """
    global _replay_memory
    if _replay_memory is None:
        _replay_memory = HTTPReplayMemory()
    return _replay_memory
