#!/usr/bin/env python3
"""
Bloom Filter-based Replay Protection with Automatic Rotation
=============================================================

Implements a rotating Bloom filter for efficient nonce tracking
and replay attack prevention with minimal memory overhead.
"""

import hashlib
import time
import threading
from typing import Set, Optional, List
from dataclasses import dataclass
import math


@dataclass
class BloomFilter:
    """
    Space-efficient probabilistic data structure for set membership testing
    
    Provides O(1) insertion and lookup with configurable false positive rate.
    """
    
    def __init__(self, expected_items: int = 10000, false_positive_rate: float = 0.001):
        """
        Initialize Bloom filter
        
        Args:
            expected_items: Expected number of items to insert
            false_positive_rate: Desired false positive probability
        """
        # Calculate optimal size and hash functions
        self.size = self._optimal_size(expected_items, false_positive_rate)
        self.hash_count = self._optimal_hash_count(self.size, expected_items)
        
        # Initialize bit array
        self.bit_array = bytearray((self.size + 7) // 8)
        self.count = 0
        self.capacity = expected_items
        
        # Track creation time for rotation
        self.created_at = time.time()
        
    @staticmethod
    def _optimal_size(n: int, p: float) -> int:
        """Calculate optimal bit array size for given parameters"""
        if p <= 0 or p >= 1:
            raise ValueError("False positive rate must be between 0 and 1")
        
        # Formula: m = -n * ln(p) / (ln(2)^2)
        m = -n * math.log(p) / (math.log(2) ** 2)
        return int(math.ceil(m))
    
    @staticmethod
    def _optimal_hash_count(m: int, n: int) -> int:
        """Calculate optimal number of hash functions"""
        if n == 0:
            return 1
        
        # Formula: k = (m/n) * ln(2)
        k = (m / n) * math.log(2)
        return max(1, int(round(k)))
    
    def _hash(self, item: bytes, seed: int) -> int:
        """
        Generate hash value for item with given seed
        
        Uses SHA-256 with seed for independent hash functions
        """
        h = hashlib.sha256()
        h.update(item)
        h.update(seed.to_bytes(4, 'big'))
        
        # Convert to integer and modulo by size
        hash_value = int.from_bytes(h.digest()[:8], 'big')
        return hash_value % self.size
    
    def add(self, item: bytes) -> None:
        """Add item to the Bloom filter"""
        for i in range(self.hash_count):
            pos = self._hash(item, i)
            byte_index = pos // 8
            bit_index = pos % 8
            self.bit_array[byte_index] |= (1 << bit_index)
        
        self.count += 1
    
    def contains(self, item: bytes) -> bool:
        """Check if item might be in the set (may have false positives)"""
        for i in range(self.hash_count):
            pos = self._hash(item, i)
            byte_index = pos // 8
            bit_index = pos % 8
            
            if not (self.bit_array[byte_index] & (1 << bit_index)):
                return False  # Definitely not in set
        
        return True  # Possibly in set
    
    def get_load_factor(self) -> float:
        """Get current load factor (items / capacity)"""
        return self.count / self.capacity if self.capacity > 0 else 0
    
    def get_age(self) -> float:
        """Get age of filter in seconds"""
        return time.time() - self.created_at
    
    def clear(self) -> None:
        """Clear all bits in the filter"""
        self.bit_array = bytearray((self.size + 7) // 8)
        self.count = 0
        self.created_at = time.time()


class RotatingBloomFilter:
    """
    Rotating Bloom filter system for time-windowed replay protection
    
    Maintains multiple Bloom filters with automatic rotation to prevent
    unbounded growth while maintaining replay protection.
    """
    
    def __init__(self, 
                 rotation_interval: int = 300,  # 5 minutes
                 expected_items_per_interval: int = 5000,
                 false_positive_rate: float = 0.001):
        """
        Initialize rotating Bloom filter
        
        Args:
            rotation_interval: Seconds between rotations
            expected_items_per_interval: Expected items per time window
            false_positive_rate: Acceptable false positive rate
        """
        self.rotation_interval = rotation_interval
        self.expected_items = expected_items_per_interval
        self.false_positive_rate = false_positive_rate
        
        # Active filters (current and previous for overlap)
        self.current_filter = BloomFilter(expected_items_per_interval, false_positive_rate)
        self.previous_filter: Optional[BloomFilter] = None
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Rotation management
        self.last_rotation = time.time()
        self.rotation_count = 0
        
        # Statistics
        self.total_checks = 0
        self.total_adds = 0
        self.false_positive_estimate = 0
    
    def _should_rotate(self) -> bool:
        """Check if rotation is needed"""
        age = time.time() - self.last_rotation
        load = self.current_filter.get_load_factor()
        
        # Rotate if time exceeded or filter is getting full
        return age >= self.rotation_interval or load > 0.75
    
    def _rotate(self) -> None:
        """Perform filter rotation"""
        with self.lock:
            # Move current to previous
            self.previous_filter = self.current_filter
            
            # Create new current filter
            self.current_filter = BloomFilter(
                self.expected_items,
                self.false_positive_rate
            )
            
            # Update rotation tracking
            self.last_rotation = time.time()
            self.rotation_count += 1
            
            print(f"[BloomFilter] Rotated filters (rotation #{self.rotation_count})")
            print(f"[BloomFilter]   Previous filter: {self.previous_filter.count} items")
            print(f"[BloomFilter]   New filter started")
    
    def check_and_add(self, nonce: bytes) -> bool:
        """
        Check if nonce was seen before and add it
        
        Args:
            nonce: Nonce bytes to check
            
        Returns:
            True if nonce is new (not seen), False if replay detected
        """
        with self.lock:
            # Check for rotation need
            if self._should_rotate():
                self._rotate()
            
            self.total_checks += 1
            
            # Check in both filters
            in_current = self.current_filter.contains(nonce)
            in_previous = (self.previous_filter.contains(nonce) 
                          if self.previous_filter else False)
            
            if in_current or in_previous:
                # Possible replay (or false positive)
                self.false_positive_estimate += 1
                return False
            
            # Add to current filter
            self.current_filter.add(nonce)
            self.total_adds += 1
            
            return True
    
    def check_only(self, nonce: bytes) -> bool:
        """Check if nonce exists without adding it"""
        with self.lock:
            in_current = self.current_filter.contains(nonce)
            in_previous = (self.previous_filter.contains(nonce) 
                          if self.previous_filter else False)
            
            return not (in_current or in_previous)
    
    def force_rotation(self) -> None:
        """Force immediate rotation (useful for testing or security events)"""
        with self.lock:
            self._rotate()
    
    def get_statistics(self) -> dict:
        """Get current statistics"""
        with self.lock:
            stats = {
                'rotation_count': self.rotation_count,
                'current_filter_items': self.current_filter.count,
                'current_filter_age': self.current_filter.get_age(),
                'current_filter_load': self.current_filter.get_load_factor(),
                'previous_filter_items': (self.previous_filter.count 
                                         if self.previous_filter else 0),
                'total_checks': self.total_checks,
                'total_adds': self.total_adds,
                'estimated_false_positives': self.false_positive_estimate,
                'false_positive_rate': (self.false_positive_estimate / self.total_checks 
                                       if self.total_checks > 0 else 0)
            }
            return stats
    
    def clear_all(self) -> None:
        """Clear all filters (reset state)"""
        with self.lock:
            self.current_filter.clear()
            self.previous_filter = None
            self.last_rotation = time.time()
            self.rotation_count = 0
            self.total_checks = 0
            self.total_adds = 0
            self.false_positive_estimate = 0


class NonceTracker:
    """
    High-level nonce tracking with Bloom filter and fallback mechanisms
    
    Provides replay protection with automatic cleanup and monitoring.
    """
    
    def __init__(self, 
                 window_size: int = 300,
                 max_exact_tracking: int = 1000):
        """
        Initialize nonce tracker
        
        Args:
            window_size: Time window in seconds for nonce validity
            max_exact_tracking: Maximum exact nonces to track (fallback)
        """
        # Primary: Rotating Bloom filter
        self.bloom_filter = RotatingBloomFilter(
            rotation_interval=window_size,
            expected_items_per_interval=10000,
            false_positive_rate=0.0001
        )
        
        # Fallback: Exact tracking for recent nonces
        self.exact_nonces: Set[bytes] = set()
        self.exact_timestamps: dict = {}
        self.max_exact = max_exact_tracking
        self.window_size = window_size
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Statistics
        self.replay_count = 0
        self.valid_count = 0
    
    def verify_nonce(self, nonce: bytes, timestamp: Optional[float] = None) -> bool:
        """
        Verify nonce is fresh and not replayed
        
        Args:
            nonce: Nonce to verify
            timestamp: Optional timestamp for time-based validation
            
        Returns:
            True if nonce is valid, False if replay detected
        """
        if timestamp is None:
            timestamp = time.time()
        
        with self.lock:
            # First check Bloom filter
            if not self.bloom_filter.check_only(nonce):
                self.replay_count += 1
                return False  # Definitely seen before
            
            # Check exact tracking
            if nonce in self.exact_nonces:
                self.replay_count += 1
                return False  # Definitely seen before
            
            # Add to both systems
            self.bloom_filter.check_and_add(nonce)
            
            # Add to exact tracking with cleanup
            self.exact_nonces.add(nonce)
            self.exact_timestamps[nonce] = timestamp
            
            # Cleanup old exact nonces
            self._cleanup_exact_nonces(timestamp)
            
            self.valid_count += 1
            return True
    
    def _cleanup_exact_nonces(self, current_time: float) -> None:
        """Remove old nonces from exact tracking"""
        if len(self.exact_nonces) > self.max_exact:
            # Remove oldest nonces
            cutoff_time = current_time - self.window_size
            
            to_remove = []
            for nonce, timestamp in self.exact_timestamps.items():
                if timestamp < cutoff_time:
                    to_remove.append(nonce)
            
            for nonce in to_remove:
                self.exact_nonces.discard(nonce)
                del self.exact_timestamps[nonce]
            
            # If still too many, remove oldest
            if len(self.exact_nonces) > self.max_exact:
                sorted_nonces = sorted(self.exact_timestamps.items(), 
                                     key=lambda x: x[1])
                
                remove_count = len(self.exact_nonces) - self.max_exact
                for nonce, _ in sorted_nonces[:remove_count]:
                    self.exact_nonces.discard(nonce)
                    del self.exact_timestamps[nonce]
    
    def get_statistics(self) -> dict:
        """Get comprehensive statistics"""
        with self.lock:
            bloom_stats = self.bloom_filter.get_statistics()
            
            stats = {
                'replay_attempts': self.replay_count,
                'valid_nonces': self.valid_count,
                'exact_nonces_tracked': len(self.exact_nonces),
                'bloom_filter': bloom_stats,
                'replay_rate': (self.replay_count / (self.replay_count + self.valid_count) 
                              if (self.replay_count + self.valid_count) > 0 else 0)
            }
            
            return stats
    
    def reset(self) -> None:
        """Reset all tracking state"""
        with self.lock:
            self.bloom_filter.clear_all()
            self.exact_nonces.clear()
            self.exact_timestamps.clear()
            self.replay_count = 0
            self.valid_count = 0


# Global nonce tracker instance
_global_nonce_tracker: Optional[NonceTracker] = None


def get_nonce_tracker() -> NonceTracker:
    """Get or create global nonce tracker instance"""
    global _global_nonce_tracker
    
    if _global_nonce_tracker is None:
        _global_nonce_tracker = NonceTracker()
    
    return _global_nonce_tracker