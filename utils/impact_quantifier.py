# utils/impact_quantifier.py
"""
Impact Quantifier Module with RAG (Retrieval-Augmented Generation)

This module provides:
1. Documentation ingestion and indexing
2. RAG-based query system for assessing real-world impact
3. Integration with Strategic LLM for impact reasoning
"""

import logging
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import asyncio
import aiohttp
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class DocumentStore:
    """
    Simple document store for RAG system
    Stores documentation chunks with metadata for retrieval
    """
    
    def __init__(self, storage_path: str = "data/rag_docs"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True, parents=True)
        self.documents = []  # List of {id, source, content, metadata}
        self.index_file = self.storage_path / "index.json"
        self._load_index()
    
    def _load_index(self):
        """Load document index from disk"""
        if self.index_file.exists():
            try:
                with open(self.index_file, 'r') as f:
                    self.documents = json.load(f)
                logger.info(f"📚 Loaded {len(self.documents)} documents from index")
            except Exception as e:
                logger.warning(f"Failed to load document index: {e}")
                self.documents = []
    
    def _save_index(self):
        """Save document index to disk"""
        try:
            with open(self.index_file, 'w') as f:
                json.dump(self.documents, f, indent=2)
            logger.debug(f"💾 Saved {len(self.documents)} documents to index")
        except Exception as e:
            logger.error(f"Failed to save document index: {e}")
    
    def add_document(self, source: str, content: str, metadata: Dict = None) -> int:
        """
        Add a document to the store
        
        Args:
            source: Source URL or identifier
            content: Document content
            metadata: Optional metadata dict
            
        Returns:
            Document ID
        """
        doc_id = len(self.documents)
        document = {
            "id": doc_id,
            "source": source,
            "content": content,
            "metadata": metadata or {}
        }
        
        self.documents.append(document)
        self._save_index()
        
        logger.info(f"📄 Added document #{doc_id} from {source}")
        return doc_id
    
    def search(self, query: str, max_results: int = 5) -> List[Dict]:
        """
        Simple keyword-based search (can be enhanced with embeddings later)
        
        Args:
            query: Search query
            max_results: Maximum number of results to return
            
        Returns:
            List of matching documents
        """
        query_lower = query.lower()
        query_terms = set(query_lower.split())
        
        # Score documents by keyword overlap
        scored_docs = []
        for doc in self.documents:
            content_lower = doc['content'].lower()
            content_terms = set(content_lower.split())
            
            # Simple scoring: count matching terms
            score = len(query_terms & content_terms)
            
            # Boost score if query appears as substring
            if query_lower in content_lower:
                score += 10
            
            if score > 0:
                scored_docs.append((score, doc))
        
        # Sort by score descending
        scored_docs.sort(key=lambda x: x[0], reverse=True)
        
        # Return top results
        results = [doc for score, doc in scored_docs[:max_results]]
        
        logger.info(f"🔍 Found {len(results)} documents matching '{query}'")
        return results
    
    def get_all_sources(self) -> List[str]:
        """Get list of all ingested sources"""
        return list(set(doc['source'] for doc in self.documents))
    
    def clear(self):
        """Clear all documents"""
        self.documents = []
        self._save_index()
        logger.info("🗑️ Cleared document store")


class ImpactQuantifier:
    """
    RAG-based impact quantification system
    
    Workflow:
    1. Agent finds hidden API endpoint
    2. Queries RAG: "What does POST /api/create_report do?"
    3. RAG retrieves relevant documentation
    4. Strategic LLM reasons about real-world impact
    5. Returns impact assessment
    """
    
    def __init__(self, ai_core=None):
        """
        Initialize impact quantifier
        
        Args:
            ai_core: EnhancedAegisAI instance for LLM access
        """
        self.ai_core = ai_core
        self.doc_store = DocumentStore()
    
    async def ingest_documentation(self, url: str, doc_type: str = "api") -> Dict:
        """
        Fetch and ingest documentation from a URL
        
        Args:
            url: Documentation URL
            doc_type: Type of documentation (api, guide, reference)
            
        Returns:
            Status dictionary
        """
        logger.info(f"📥 Ingesting documentation from {url}")
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=False, timeout=30) as response:
                    if response.status != 200:
                        return {
                            "status": "error",
                            "error": f"Failed to fetch documentation: HTTP {response.status}"
                        }
                    
                    content = await response.text()
                    
                    # Simple chunking: split by paragraphs or sections
                    # In production, you'd use more sophisticated chunking
                    chunks = self._chunk_content(content)
                    
                    # Add each chunk to document store
                    doc_ids = []
                    for i, chunk in enumerate(chunks):
                        doc_id = self.doc_store.add_document(
                            source=url,
                            content=chunk,
                            metadata={
                                "doc_type": doc_type,
                                "chunk_index": i,
                                "total_chunks": len(chunks)
                            }
                        )
                        doc_ids.append(doc_id)
                    
                    logger.info(f"✅ Ingested {len(chunks)} chunks from {url}")
                    
                    return {
                        "status": "success",
                        "data": {
                            "url": url,
                            "chunks_added": len(chunks),
                            "doc_ids": doc_ids
                        }
                    }
                    
        except Exception as e:
            logger.error(f"❌ Failed to ingest documentation: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    def _chunk_content(self, content: str, chunk_size: int = 500) -> List[str]:
        """
        Simple content chunking by character count
        
        Args:
            content: Full content to chunk
            chunk_size: Approximate size of each chunk in characters
            
        Returns:
            List of content chunks
        """
        # Split by newlines first
        lines = content.split('\n')
        
        chunks = []
        current_chunk = []
        current_size = 0
        
        for line in lines:
            line_size = len(line)
            
            if current_size + line_size > chunk_size and current_chunk:
                # Save current chunk and start new one
                chunks.append('\n'.join(current_chunk))
                current_chunk = [line]
                current_size = line_size
            else:
                current_chunk.append(line)
                current_size += line_size
        
        # Add final chunk
        if current_chunk:
            chunks.append('\n'.join(current_chunk))
        
        return chunks
    
    async def assess_impact(self, finding: Dict, context: str = "") -> Dict:
        """
        Assess the real-world impact of a finding using RAG
        
        Args:
            finding: Vulnerability finding dict with:
                - type: Finding type
                - endpoint: API endpoint or URL
                - description: Finding description
            context: Additional context
            
        Returns:
            Impact assessment dict
        """
        if not self.ai_core:
            return {
                "status": "error",
                "error": "AI core not initialized"
            }
        
        endpoint = finding.get('endpoint', finding.get('url', 'unknown'))
        finding_type = finding.get('type', 'unknown')
        
        logger.info(f"🎯 Assessing impact for {finding_type} at {endpoint}")
        
        # Query RAG for relevant documentation
        query = f"{endpoint} {finding_type} functionality impact"
        relevant_docs = self.doc_store.search(query, max_results=3)
        
        # Build context from retrieved documents
        doc_context = ""
        if relevant_docs:
            doc_context = "\n\nRELEVANT DOCUMENTATION:\n"
            for i, doc in enumerate(relevant_docs, 1):
                doc_context += f"\n[Doc {i}] From {doc['source']}:\n{doc['content'][:500]}...\n"
        else:
            doc_context = "\n\nNOTE: No relevant documentation found in RAG system."
        
        # Build prompt for Strategic LLM
        impact_prompt = f"""You are analyzing the real-world business impact of a security finding.

FINDING:
Type: {finding_type}
Endpoint: {endpoint}
Description: {finding.get('description', 'No description')}

CONTEXT:
{context}
{doc_context}

Your task is to assess the REAL-WORLD IMPACT:
1. What does this endpoint do based on the documentation?
2. What resources does it consume (disk, memory, CPU)?
3. What happens if this vulnerability is exploited?
4. What is the business impact (DoS, data breach, financial loss)?
5. How severe is this in the real world?

Provide your assessment as JSON:
{{
  "functionality": "What this endpoint does",
  "resource_consumption": "Resources it consumes (e.g., 500MB disk per call)",
  "exploit_scenario": "How an attacker could exploit this",
  "business_impact": "Real-world business impact",
  "impact_severity": "critical|high|medium|low",
  "impact_score": 0-10,
  "reasoning": "Your detailed reasoning"
}}
"""
        
        try:
            # Call Strategic LLM for impact assessment
            response = await self.ai_core.orchestrator.execute_task(
                task_type='triage',
                system_prompt="You are a security impact analyst assessing business risks.",
                user_message=impact_prompt,
                temperature=0.6,
                max_tokens=1024
            )
            
            content = response['content']
            
            # Extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                impact_assessment = json.loads(json_match.group(0))
                
                logger.info(f"✅ Impact assessed: {impact_assessment.get('impact_severity', 'unknown')} severity")
                
                return {
                    "status": "success",
                    "data": {
                        "finding": finding,
                        "impact_assessment": impact_assessment,
                        "documentation_used": len(relevant_docs),
                        "sources": [doc['source'] for doc in relevant_docs]
                    }
                }
            else:
                logger.warning("Could not parse impact assessment JSON")
                return {
                    "status": "success",
                    "data": {
                        "finding": finding,
                        "impact_assessment": {
                            "raw_response": content,
                            "note": "Could not parse structured response"
                        },
                        "documentation_used": len(relevant_docs)
                    }
                }
                
        except Exception as e:
            logger.error(f"❌ Failed to assess impact: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    def get_statistics(self) -> Dict:
        """Get statistics about the RAG system"""
        return {
            "total_documents": len(self.doc_store.documents),
            "sources": self.doc_store.get_all_sources(),
            "source_count": len(self.doc_store.get_all_sources())
        }


# Singleton instance
_impact_quantifier = None


def get_impact_quantifier(ai_core=None) -> ImpactQuantifier:
    """Get or create the global impact quantifier instance"""
    global _impact_quantifier
    if _impact_quantifier is None:
        _impact_quantifier = ImpactQuantifier(ai_core)
    elif ai_core is not None and _impact_quantifier.ai_core is None:
        # Update AI core if it was not set before
        _impact_quantifier.ai_core = ai_core
    return _impact_quantifier
