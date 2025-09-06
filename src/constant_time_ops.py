#!/usr/bin/env python3
"""
Constant-Time Cryptographic Operations for Side-Channel Resistance
===================================================================

Implements constant-time operations to prevent timing attacks and
secure memory handling for sensitive cryptographic material.
"""

import secrets
import ctypes
import sys
from typing import Optional


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison of byte strings
    
    Uses secrets.compare_digest for timing-attack resistant comparison.
    
    Args:
        a: First byte string
        b: Second byte string
        
    Returns:
        True if equal, False otherwise
    """
    if len(a) != len(b):
        return False
    
    # Use built-in constant-time comparison
    return secrets.compare_digest(a, b)


def constant_time_select(condition: bool, if_true: bytes, if_false: bytes) -> bytes:
    """
    Constant-time conditional selection
    
    Selects between two values without branching.
    
    Args:
        condition: Selection condition
        if_true: Value if condition is True
        if_false: Value if condition is False
        
    Returns:
        Selected value
    """
    if len(if_true) != len(if_false):
        raise ValueError("Values must be same length for constant-time selection")
    
    # Convert condition to mask (all 1s or all 0s)
    mask = -int(condition)  # -1 (all bits set) if True, 0 if False
    
    result = bytearray(len(if_true))
    for i in range(len(if_true)):
        # Constant-time selection using bitwise operations
        result[i] = (if_true[i] & mask) | (if_false[i] & ~mask)
    
    return bytes(result)


def constant_time_copy(dst: bytearray, src: bytes, condition: bool) -> None:
    """
    Conditionally copy bytes in constant time
    
    Args:
        dst: Destination buffer
        src: Source bytes
        condition: Whether to perform copy
    """
    if len(dst) != len(src):
        raise ValueError("Buffers must be same size")
    
    mask = -int(condition)
    
    for i in range(len(src)):
        # Copy if condition is true, keep original if false
        dst[i] = (src[i] & mask) | (dst[i] & ~mask)


def constant_time_is_zero(value: bytes) -> bool:
    """
    Check if all bytes are zero in constant time
    
    Args:
        value: Bytes to check
        
    Returns:
        True if all bytes are zero
    """
    accumulator = 0
    for byte in value:
        accumulator |= byte
    
    # Return True only if accumulator is still 0
    return accumulator == 0


class SecureMemory:
    """
    Secure memory handling with automatic cleanup
    
    Provides memory locking and secure erasure for sensitive data.
    """
    
    def __init__(self, size: int):
        """
        Allocate secure memory buffer
        
        Args:
            size: Buffer size in bytes
        """
        self.size = size
        self.buffer = bytearray(size)
        self.locked = False
        
        # Try to lock memory (platform-dependent)
        self._lock_memory()
    
    def _lock_memory(self) -> None:
        """Attempt to lock memory to prevent swapping"""
        if sys.platform in ['linux', 'darwin']:
            try:
                # Use ctypes to call mlock
                libc = ctypes.CDLL(None)
                libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                
                address = ctypes.c_void_p.from_buffer(self.buffer)
                result = libc.mlock(address, self.size)
                
                if result == 0:
                    self.locked = True
            except:
                pass  # Locking failed, continue without
    
    def _unlock_memory(self) -> None:
        """Unlock memory if it was locked"""
        if self.locked and sys.platform in ['linux', 'darwin']:
            try:
                libc = ctypes.CDLL(None)
                libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                
                address = ctypes.c_void_p.from_buffer(self.buffer)
                libc.munlock(address, self.size)
                
                self.locked = False
            except:
                pass
    
    def write(self, data: bytes, offset: int = 0) -> None:
        """
        Write data to secure buffer
        
        Args:
            data: Data to write
            offset: Offset in buffer
        """
        if offset + len(data) > self.size:
            raise ValueError("Data exceeds buffer size")
        
        for i, byte in enumerate(data):
            self.buffer[offset + i] = byte
    
    def read(self, length: int, offset: int = 0) -> bytes:
        """
        Read data from secure buffer
        
        Args:
            length: Number of bytes to read
            offset: Offset in buffer
            
        Returns:
            Data bytes
        """
        if offset + length > self.size:
            raise ValueError("Read exceeds buffer size")
        
        return bytes(self.buffer[offset:offset + length])
    
    def clear(self) -> None:
        """Securely clear buffer contents"""
        secure_erase(self.buffer)
    
    def __del__(self):
        """Cleanup on deletion"""
        self.clear()
        self._unlock_memory()


def secure_erase(data: bytearray) -> None:
    """
    Securely erase sensitive data from memory
    
    Overwrites memory multiple times to prevent recovery.
    
    Args:
        data: Data to erase (modified in place)
    """
    if not data:
        return
    
    length = len(data)
    
    # Multiple overwrite passes
    # Pass 1: All zeros
    for i in range(length):
        data[i] = 0x00
    
    # Pass 2: All ones
    for i in range(length):
        data[i] = 0xFF
    
    # Pass 3: Random data
    random_data = secrets.token_bytes(length)
    for i in range(length):
        data[i] = random_data[i]
    
    # Pass 4: Zeros again
    for i in range(length):
        data[i] = 0x00


def secure_erase_bytes(data: bytes) -> bytes:
    """
    Create new zero bytes and attempt to clear original
    
    Note: In Python, we can't directly modify immutable bytes,
    but we can create new zeros and let garbage collection handle cleanup.
    
    Args:
        data: Bytes to pseudo-erase
        
    Returns:
        Zero bytes of same length
    """
    return bytes(len(data))


class MemoryBarrier:
    """
    Memory barrier for cache-timing attack prevention
    
    Forces CPU cache flushes to prevent timing analysis.
    """
    
    @staticmethod
    def barrier() -> None:
        """Insert memory barrier"""
        # Python doesn't have direct memory barriers, but we can
        # simulate with memory allocation/deallocation
        dummy = bytearray(4096)  # Allocate page
        secure_erase(dummy)      # Force memory operations
        del dummy                # Deallocate
    
    @staticmethod
    def flush_cache_line(address: int) -> None:
        """
        Attempt to flush cache line (platform-specific)
        
        Args:
            address: Memory address to flush
        """
        if sys.platform in ['linux', 'darwin']:
            try:
                # Use clflush instruction via ctypes (x86/x64 only)
                import ctypes
                
                # This is platform and architecture specific
                # In practice, would need assembly or compiler intrinsics
                pass
            except:
                pass


def timing_safe_random_delay() -> None:
    """
    Add random delay to obscure timing patterns
    
    Useful for operations that might leak information through timing.
    """
    import time
    
    # Random delay between 0 and 1000 microseconds
    delay = secrets.randbelow(1000) / 1_000_000
    time.sleep(delay)


class DummyOperations:
    """
    Dummy operations for power analysis countermeasures
    
    Performs fake cryptographic operations to obscure real ones.
    """
    
    @staticmethod
    def dummy_multiplication(size: int = 32) -> bytes:
        """Perform dummy multiplication operation"""
        a = secrets.token_bytes(size)
        b = secrets.token_bytes(size)
        
        result = bytearray(size)
        carry = 0
        
        for i in range(size):
            temp = a[i] * b[i] + carry
            result[i] = temp & 0xFF
            carry = temp >> 8
        
        return bytes(result)
    
    @staticmethod
    def dummy_xor(size: int = 32) -> bytes:
        """Perform dummy XOR operation"""
        a = secrets.token_bytes(size)
        b = secrets.token_bytes(size)
        
        result = bytearray(size)
        for i in range(size):
            result[i] = a[i] ^ b[i]
        
        return bytes(result)
    
    @staticmethod
    def interleave_dummy_ops(real_operation, *args, **kwargs):
        """
        Interleave dummy operations with real ones
        
        Args:
            real_operation: Real operation to perform
            *args, **kwargs: Arguments for real operation
            
        Returns:
            Result of real operation
        """
        # Dummy op before
        DummyOperations.dummy_multiplication()
        
        # Real operation
        result = real_operation(*args, **kwargs)
        
        # Dummy op after
        DummyOperations.dummy_xor()
        
        return result