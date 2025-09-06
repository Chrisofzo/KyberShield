#!/usr/bin/env python3
"""
Quantum-Safe Random Number Generator with ChaCha20 Fallback
===========================================================

Implements a robust RNG system with multiple entropy sources and
ChaCha20-based DRBG for cryptographically secure random generation.
"""

import os
import time
import hashlib
import secrets
import struct
from typing import Optional, List, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class ChaCha20DRBG:
    """
    Deterministic Random Bit Generator using ChaCha20
    
    Provides a cryptographically secure PRNG with periodic reseeding
    from system entropy sources.
    """
    
    RESEED_INTERVAL = 1048576  # Reseed after 1MB of output
    
    def __init__(self, seed: Optional[bytes] = None):
        """
        Initialize ChaCha20 DRBG
        
        Args:
            seed: Initial seed (32 bytes), generates random if not provided
        """
        if seed is None:
            seed = os.urandom(32)
        elif len(seed) != 32:
            # Hash seed to correct length if needed
            seed = hashlib.sha256(seed).digest()
        
        self.key = seed
        self.counter = 0
        self.bytes_generated = 0
        
        # Initialize ChaCha20 state
        self._initialize_cipher()
    
    def _initialize_cipher(self) -> None:
        """Initialize ChaCha20 cipher with current key"""
        # Use counter as nonce (ChaCha20 uses 16-byte nonce)
        nonce = self.counter.to_bytes(8, 'little') + b'\x00' * 8
        
        # Create cipher
        algorithm = algorithms.ChaCha20(self.key, nonce)
        self.cipher = Cipher(algorithm, mode=None, backend=default_backend())
    
    def generate(self, num_bytes: int) -> bytes:
        """
        Generate random bytes
        
        Args:
            num_bytes: Number of random bytes to generate
            
        Returns:
            Random bytes
        """
        if num_bytes <= 0:
            return b''
        
        # Check if reseeding is needed
        if self.bytes_generated >= self.RESEED_INTERVAL:
            self.reseed()
        
        # Generate random bytes by encrypting zeros
        plaintext = b'\x00' * num_bytes
        encryptor = self.cipher.encryptor()
        random_bytes = encryptor.update(plaintext) + encryptor.finalize()
        
        # Update state
        self.counter += 1
        self.bytes_generated += num_bytes
        
        # Reinitialize cipher with new counter
        self._initialize_cipher()
        
        return random_bytes[:num_bytes]
    
    def reseed(self, additional_entropy: Optional[bytes] = None) -> None:
        """
        Reseed the DRBG with fresh entropy
        
        Args:
            additional_entropy: Optional additional entropy to mix in
        """
        # Get fresh entropy from OS
        fresh_entropy = os.urandom(32)
        
        # Mix with current key and additional entropy
        h = hashlib.sha256()
        h.update(self.key)
        h.update(fresh_entropy)
        
        if additional_entropy:
            h.update(additional_entropy)
        
        # Update key
        self.key = h.digest()
        
        # Reset counter and bytes generated
        self.counter = 0
        self.bytes_generated = 0
        
        # Reinitialize cipher
        self._initialize_cipher()


class QuantumRNG:
    """
    Quantum-safe RNG with multiple entropy sources
    
    Combines system entropy, hardware RNG (if available), and
    ChaCha20 DRBG for robust random number generation.
    """
    
    def __init__(self):
        """Initialize Quantum RNG"""
        # Primary entropy source
        self.use_os_random = True
        
        # Hardware RNG availability
        self.hw_rng_available = self._check_hw_rng()
        
        # ChaCha20 DRBG as fallback/mixer
        initial_seed = self._gather_entropy(32)
        self.chacha_drbg = ChaCha20DRBG(initial_seed)
        
        # Entropy pool for mixing
        self.entropy_pool = bytearray(64)
        self._update_entropy_pool()
        
        # Statistics
        self.bytes_generated = 0
        self.hw_bytes_used = 0
        self.reseeds = 0
    
    def _check_hw_rng(self) -> bool:
        """Check if hardware RNG is available"""
        # Check for common hardware RNG devices
        hw_rng_devices = [
            '/dev/hwrng',      # Linux hardware RNG
            '/dev/random',     # May be backed by hardware on some systems
        ]
        
        for device in hw_rng_devices:
            if os.path.exists(device):
                try:
                    # Try to read a byte to verify access
                    with open(device, 'rb') as f:
                        f.read(1)
                    print(f"[QuantumRNG] Hardware RNG available: {device}")
                    return True
                except (OSError, IOError):
                    pass
        
        return False
    
    def _read_hw_rng(self, num_bytes: int) -> Optional[bytes]:
        """
        Read from hardware RNG if available
        
        Args:
            num_bytes: Number of bytes to read
            
        Returns:
            Random bytes from hardware RNG or None if unavailable
        """
        if not self.hw_rng_available:
            return None
        
        try:
            # Try hardware RNG first
            with open('/dev/hwrng', 'rb') as f:
                data = f.read(num_bytes)
                if len(data) == num_bytes:
                    self.hw_bytes_used += num_bytes
                    return data
        except (OSError, IOError):
            self.hw_rng_available = False
        
        return None
    
    def _gather_entropy(self, num_bytes: int) -> bytes:
        """
        Gather entropy from multiple sources
        
        Args:
            num_bytes: Number of entropy bytes needed
            
        Returns:
            Mixed entropy bytes
        """
        entropy_sources: List[bytes] = []
        
        # 1. OS random (primary source)
        if self.use_os_random:
            entropy_sources.append(os.urandom(num_bytes))
        
        # 2. Hardware RNG (if available)
        hw_entropy = self._read_hw_rng(num_bytes)
        if hw_entropy:
            entropy_sources.append(hw_entropy)
        
        # 3. Time-based entropy (weak but adds variation)
        time_entropy = struct.pack('d', time.time())
        time_entropy += struct.pack('q', time.time_ns())
        entropy_sources.append(time_entropy)
        
        # 4. Process-based entropy
        try:
            pid_entropy = os.getpid().to_bytes(4, 'big')
            entropy_sources.append(pid_entropy)
        except:
            pass
        
        # Mix all entropy sources
        if len(entropy_sources) == 1:
            return entropy_sources[0][:num_bytes]
        
        # XOR mix for simple combining
        mixed = bytearray(num_bytes)
        for source in entropy_sources:
            source_bytes = source[:num_bytes]
            for i in range(len(source_bytes)):
                mixed[i] ^= source_bytes[i]
        
        # Final mixing with SHA-256
        h = hashlib.sha256()
        for source in entropy_sources:
            h.update(source)
        
        # Extend if needed
        output = h.digest()
        while len(output) < num_bytes:
            h.update(output)
            output += h.digest()
        
        return bytes(output[:num_bytes])
    
    def _update_entropy_pool(self) -> None:
        """Update internal entropy pool"""
        fresh_entropy = self._gather_entropy(64)
        
        # XOR mix with existing pool
        for i in range(64):
            self.entropy_pool[i] ^= fresh_entropy[i]
        
        # Hash for avalanche effect
        h = hashlib.sha3_256()
        h.update(bytes(self.entropy_pool))
        h.update(fresh_entropy)
        
        # Update pool with hash output
        hash_output = h.digest()
        for i in range(32):
            self.entropy_pool[i] = hash_output[i]
    
    def get_random_bytes(self, num_bytes: int) -> bytes:
        """
        Get cryptographically secure random bytes
        
        Args:
            num_bytes: Number of random bytes
            
        Returns:
            Random bytes
        """
        if num_bytes <= 0:
            return b''
        
        # For small requests, use os.urandom directly
        if num_bytes <= 32 and self.use_os_random:
            self.bytes_generated += num_bytes
            return os.urandom(num_bytes)
        
        # For larger requests, use mixed approach
        output = bytearray()
        
        while len(output) < num_bytes:
            # Get entropy from multiple sources
            chunk_size = min(256, num_bytes - len(output))
            
            # Try hardware RNG first
            hw_bytes = self._read_hw_rng(chunk_size)
            if hw_bytes:
                output.extend(hw_bytes)
            else:
                # Fall back to OS random
                if self.use_os_random:
                    output.extend(os.urandom(chunk_size))
                else:
                    # Last resort: ChaCha20 DRBG
                    output.extend(self.chacha_drbg.generate(chunk_size))
        
        # Mix with ChaCha20 for additional security
        mixed_output = bytearray(num_bytes)
        chacha_stream = self.chacha_drbg.generate(num_bytes)
        
        for i in range(num_bytes):
            mixed_output[i] = output[i] ^ chacha_stream[i]
        
        # Periodic reseeding
        self.bytes_generated += num_bytes
        if self.bytes_generated % (1024 * 1024) == 0:  # Every 1MB
            self.reseed()
        
        return bytes(mixed_output[:num_bytes])
    
    def reseed(self) -> None:
        """Reseed all PRNGs with fresh entropy"""
        # Gather fresh entropy
        fresh_entropy = self._gather_entropy(64)
        
        # Update entropy pool
        self._update_entropy_pool()
        
        # Reseed ChaCha20 DRBG
        self.chacha_drbg.reseed(fresh_entropy[:32])
        
        self.reseeds += 1
        print(f"[QuantumRNG] Reseeded (#{self.reseeds})")
    
    def get_random_int(self, min_val: int, max_val: int) -> int:
        """
        Get random integer in range [min_val, max_val]
        
        Args:
            min_val: Minimum value (inclusive)
            max_val: Maximum value (inclusive)
            
        Returns:
            Random integer
        """
        if min_val > max_val:
            min_val, max_val = max_val, min_val
        
        range_size = max_val - min_val + 1
        
        # Use secrets.randbelow for uniform distribution
        return min_val + secrets.randbelow(range_size)
    
    def get_statistics(self) -> dict:
        """Get RNG statistics"""
        return {
            'bytes_generated': self.bytes_generated,
            'hw_bytes_used': self.hw_bytes_used,
            'hw_rng_available': self.hw_rng_available,
            'reseeds': self.reseeds,
            'chacha_bytes': self.chacha_drbg.bytes_generated
        }


# Global RNG instance
_global_quantum_rng: Optional[QuantumRNG] = None


def get_quantum_rng() -> QuantumRNG:
    """Get or create global Quantum RNG instance"""
    global _global_quantum_rng
    
    if _global_quantum_rng is None:
        _global_quantum_rng = QuantumRNG()
        print("[QuantumRNG] Initialized with entropy sources:")
        print(f"  OS Random: Yes")
        print(f"  Hardware RNG: {'Yes' if _global_quantum_rng.hw_rng_available else 'No'}")
        print(f"  ChaCha20 DRBG: Yes (fallback)")
    
    return _global_quantum_rng


def secure_random_bytes(num_bytes: int) -> bytes:
    """
    Convenience function for getting secure random bytes
    
    Args:
        num_bytes: Number of random bytes
        
    Returns:
        Cryptographically secure random bytes
    """
    rng = get_quantum_rng()
    return rng.get_random_bytes(num_bytes)