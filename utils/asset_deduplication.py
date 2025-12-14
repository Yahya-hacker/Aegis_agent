#!/usr/bin/env python3
"""
Asset Deduplication System
===========================

Implements asset deduplication using:
- SimHash: Content similarity detection
- ImageHash: Visual screenshot similarity detection

This system groups similar assets (e.g., identical staging environments)
to avoid redundant testing and optimize computational resources.
"""

import asyncio
import hashlib
import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import re

logger = logging.getLogger(__name__)


def simhash(text: str, hash_bits: int = 64) -> int:
    """
    Calculate SimHash for content similarity.
    
    SimHash is a locality-sensitive hash that maps similar documents
    to similar hash values.
    
    Args:
        text: Text content to hash
        hash_bits: Number of bits in the hash (default 64)
        
    Returns:
        Integer hash value
    """
    # Tokenize text
    tokens = re.findall(r'\w+', text.lower())
    
    # Calculate feature hashes
    v = [0] * hash_bits
    
    for token in tokens:
        # Use SHA-256 instead of MD5 for better security
        h = int(hashlib.sha256(token.encode()).hexdigest(), 16)
        
        # Update vector
        for i in range(hash_bits):
            if h & (1 << i):
                v[i] += 1
            else:
                v[i] -= 1
    
    # Generate final hash
    fingerprint = 0
    for i in range(hash_bits):
        if v[i] > 0:
            fingerprint |= (1 << i)
    
    return fingerprint


def hamming_distance(hash1: int, hash2: int, hash_bits: int = 64) -> int:
    """
    Calculate Hamming distance between two hashes.
    
    Args:
        hash1: First hash
        hash2: Second hash
        hash_bits: Number of bits in the hash
        
    Returns:
        Number of differing bits
    """
    x = hash1 ^ hash2
    distance = 0
    
    for i in range(hash_bits):
        if x & (1 << i):
            distance += 1
    
    return distance


def similarity_score(hash1: int, hash2: int, hash_bits: int = 64) -> float:
    """
    Calculate similarity score (0.0 to 1.0) between two hashes.
    
    Args:
        hash1: First hash
        hash2: Second hash
        hash_bits: Number of bits in the hash
        
    Returns:
        Similarity score (1.0 = identical, 0.0 = completely different)
    """
    distance = hamming_distance(hash1, hash2, hash_bits)
    return 1.0 - (distance / hash_bits)


def image_hash_dhash(image_path: str, hash_size: int = 8) -> int:
    """
    Calculate difference hash (dHash) for an image.
    
    This is a simple perceptual hash that's resistant to small modifications.
    
    Args:
        image_path: Path to image file
        hash_size: Size of the hash (default 8x8 = 64 bits)
        
    Returns:
        Integer hash value
    """
    try:
        from PIL import Image
        
        # Load and resize image
        img = Image.open(image_path).convert('L')  # Convert to grayscale
        img = img.resize((hash_size + 1, hash_size), Image.Resampling.LANCZOS)
        
        # Calculate differences
        pixels = list(img.getdata())
        
        # Create hash based on horizontal gradients
        hash_value = 0
        for row in range(hash_size):
            for col in range(hash_size):
                pixel_left = pixels[row * (hash_size + 1) + col]
                pixel_right = pixels[row * (hash_size + 1) + col + 1]
                
                if pixel_left < pixel_right:
                    hash_value |= (1 << (row * hash_size + col))
        
        return hash_value
        
    except Exception as e:
        logger.error(f"Error calculating image hash: {e}")
        return 0


@dataclass
class Asset:
    """Represents a web asset (URL, domain, etc.)"""
    id: str
    url: str
    content: Optional[str] = None
    screenshot_path: Optional[str] = None
    content_hash: Optional[int] = None
    image_hash: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.now)


@dataclass
class AssetCluster:
    """Group of similar assets"""
    id: str
    representative: Asset  # The "canonical" asset in this cluster
    members: List[Asset] = field(default_factory=list)
    similarity_threshold: float = 0.95
    findings: Dict[str, Any] = field(default_factory=dict)  # Findings for this cluster


class AssetDeduplicator:
    """
    Asset deduplication system using SimHash and ImageHash.
    
    This system:
    1. Calculates content and visual hashes for assets
    2. Groups similar assets into clusters
    3. Tests only one asset per cluster
    4. Extrapolates findings to similar assets
    """
    
    def __init__(self, content_threshold: float = 0.95, image_threshold: float = 0.90):
        """
        Initialize the deduplicator.
        
        Args:
            content_threshold: Similarity threshold for content (0.0-1.0)
            image_threshold: Similarity threshold for images (0.0-1.0)
        """
        self.content_threshold = content_threshold
        self.image_threshold = image_threshold
        self.assets: Dict[str, Asset] = {}
        self.clusters: Dict[str, AssetCluster] = {}
        self._asset_counter = 0
        self._cluster_counter = 0
        
    def add_asset(self, url: str, content: Optional[str] = None, 
                  screenshot_path: Optional[str] = None, metadata: Optional[Dict] = None) -> Asset:
        """
        Add an asset and calculate its hashes.
        
        Args:
            url: Asset URL
            content: HTML content
            screenshot_path: Path to screenshot
            metadata: Additional metadata
            
        Returns:
            The created Asset object
        """
        self._asset_counter += 1
        
        # Calculate hashes
        content_hash = None
        image_hash = None
        
        if content:
            content_hash = simhash(content)
        
        if screenshot_path and Path(screenshot_path).exists():
            image_hash = image_hash_dhash(screenshot_path)
        
        asset = Asset(
            id=f"asset_{self._asset_counter}",
            url=url,
            content=content,
            screenshot_path=screenshot_path,
            content_hash=content_hash,
            image_hash=image_hash,
            metadata=metadata or {}
        )
        
        self.assets[asset.id] = asset
        
        # Try to add to existing cluster or create new one
        self._assign_to_cluster(asset)
        
        logger.info(f"📦 Added asset: {url} (content_hash: {content_hash}, image_hash: {image_hash})")
        
        return asset
    
    def _assign_to_cluster(self, asset: Asset) -> None:
        """Assign an asset to a cluster or create a new one"""
        
        best_cluster = None
        best_similarity = 0.0
        
        # Find best matching cluster
        for cluster_id, cluster in self.clusters.items():
            similarity = self._calculate_similarity(asset, cluster.representative)
            
            if similarity > best_similarity and similarity >= max(self.content_threshold, self.image_threshold):
                best_similarity = similarity
                best_cluster = cluster
        
        if best_cluster:
            # Add to existing cluster
            best_cluster.members.append(asset)
            logger.info(f"🔗 Added {asset.url} to cluster {best_cluster.id} (similarity: {best_similarity:.2%})")
        else:
            # Create new cluster
            self._cluster_counter += 1
            new_cluster = AssetCluster(
                id=f"cluster_{self._cluster_counter}",
                representative=asset,
                members=[asset]
            )
            self.clusters[new_cluster.id] = new_cluster
            logger.info(f"✨ Created new cluster {new_cluster.id} for {asset.url}")
    
    def _calculate_similarity(self, asset1: Asset, asset2: Asset) -> float:
        """
        Calculate similarity between two assets.
        
        Uses both content and image similarity, taking the maximum.
        
        Args:
            asset1: First asset
            asset2: Second asset
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        similarities = []
        
        # Content similarity
        if asset1.content_hash is not None and asset2.content_hash is not None:
            content_sim = similarity_score(asset1.content_hash, asset2.content_hash)
            similarities.append(content_sim)
        
        # Image similarity
        if asset1.image_hash is not None and asset2.image_hash is not None:
            image_sim = similarity_score(asset1.image_hash, asset2.image_hash)
            similarities.append(image_sim)
        
        # Return maximum similarity
        return max(similarities) if similarities else 0.0
    
    def get_assets_to_test(self) -> List[Asset]:
        """
        Get the list of assets that should be tested.
        
        Returns only one representative asset per cluster to avoid
        redundant testing.
        
        Returns:
            List of representative assets
        """
        representatives = [cluster.representative for cluster in self.clusters.values()]
        
        logger.info(f"📊 Testing {len(representatives)} representative assets "
                   f"(out of {len(self.assets)} total assets)")
        
        return representatives
    
    def extrapolate_finding(self, asset: Asset, finding: Dict[str, Any]) -> List[Tuple[Asset, Dict[str, Any]]]:
        """
        Extrapolate a finding from one asset to similar assets in the same cluster.
        
        Args:
            asset: Asset where finding was discovered
            finding: The finding details
            
        Returns:
            List of (asset, finding) tuples for similar assets
        """
        extrapolated = []
        
        # Find the cluster this asset belongs to
        cluster = None
        for c in self.clusters.values():
            if asset in c.members:
                cluster = c
                break
        
        if not cluster:
            logger.warning(f"Asset {asset.id} not found in any cluster")
            return extrapolated
        
        # Store finding in cluster
        cluster.findings[finding.get("type", "unknown")] = finding
        
        # Extrapolate to all members
        for member in cluster.members:
            if member.id != asset.id:
                # Create adapted finding
                adapted_finding = finding.copy()
                adapted_finding["url"] = member.url
                adapted_finding["extrapolated_from"] = asset.url
                adapted_finding["confidence"] = finding.get("confidence", 1.0) * 0.9  # Slight confidence reduction
                
                extrapolated.append((member, adapted_finding))
                
                logger.info(f"📋 Extrapolated finding from {asset.url} to {member.url}")
        
        return extrapolated
    
    def get_cluster_report(self) -> Dict[str, Any]:
        """
        Get a report of asset clustering.
        
        Returns:
            Dictionary with clustering statistics
        """
        cluster_sizes = [len(c.members) for c in self.clusters.values()]
        
        return {
            "total_assets": len(self.assets),
            "total_clusters": len(self.clusters),
            "assets_to_test": len(self.get_assets_to_test()),
            "efficiency_gain": 1.0 - (len(self.get_assets_to_test()) / max(len(self.assets), 1)),
            "average_cluster_size": sum(cluster_sizes) / max(len(cluster_sizes), 1),
            "largest_cluster_size": max(cluster_sizes) if cluster_sizes else 0,
            "clusters": [
                {
                    "id": c.id,
                    "representative": c.representative.url,
                    "member_count": len(c.members),
                    "members": [m.url for m in c.members],
                    "findings_count": len(c.findings)
                }
                for c in self.clusters.values()
            ]
        }
    
    def find_similar_assets(self, asset: Asset, min_similarity: float = 0.8) -> List[Tuple[Asset, float]]:
        """
        Find all assets similar to the given asset.
        
        Args:
            asset: Asset to compare against
            min_similarity: Minimum similarity threshold
            
        Returns:
            List of (asset, similarity) tuples
        """
        similar = []
        
        for other_asset in self.assets.values():
            if other_asset.id == asset.id:
                continue
            
            similarity = self._calculate_similarity(asset, other_asset)
            
            if similarity >= min_similarity:
                similar.append((other_asset, similarity))
        
        # Sort by similarity (descending)
        similar.sort(key=lambda x: x[1], reverse=True)
        
        return similar


def get_asset_deduplicator(content_threshold: float = 0.95, 
                           image_threshold: float = 0.90) -> AssetDeduplicator:
    """
    Get asset deduplicator instance.
    
    Args:
        content_threshold: Content similarity threshold
        image_threshold: Image similarity threshold
        
    Returns:
        AssetDeduplicator instance
    """
    return AssetDeduplicator(content_threshold, image_threshold)


# Example usage
async def example_deduplication():
    """Example of asset deduplication workflow"""
    
    deduplicator = get_asset_deduplicator()
    
    # Add assets
    asset1 = deduplicator.add_asset(
        "https://stage-01.corp.com",
        content="<html><body>Welcome to staging</body></html>",
        metadata={"environment": "staging"}
    )
    
    asset2 = deduplicator.add_asset(
        "https://stage-02.corp.com",
        content="<html><body>Welcome to staging</body></html>",  # Identical content
        metadata={"environment": "staging"}
    )
    
    asset3 = deduplicator.add_asset(
        "https://prod.corp.com",
        content="<html><body>Welcome to production</body></html>",  # Different content
        metadata={"environment": "production"}
    )
    
    # Get assets to test (should only test 2: one staging, one production)
    to_test = deduplicator.get_assets_to_test()
    print(f"Assets to test: {len(to_test)}")
    
    # Simulate finding on stage-01
    finding = {
        "type": "SQL Injection",
        "endpoint": "/search",
        "confidence": 0.95
    }
    
    # Extrapolate to similar assets
    extrapolated = deduplicator.extrapolate_finding(asset1, finding)
    print(f"Extrapolated to {len(extrapolated)} similar assets")
    
    # Get report
    report = deduplicator.get_cluster_report()
    print(f"Efficiency gain: {report['efficiency_gain']:.1%}")


if __name__ == "__main__":
    asyncio.run(example_deduplication())
