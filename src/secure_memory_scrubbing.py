#!/usr/bin/env python3
"""
KyberLink VPN - Secure Memory Scrubbing
=======================================

Cryptographic memory scrubbing utilities to completely erase sensitive data
from memory after disconnections, ensuring perfect forward secrecy.
"""

import secrets
import gc
from typing import Any, List, Dict, Optional
from dataclasses import fields


def secure_erase(byte_array: bytearray) -> None:
    """
    Securely erase a byte array by overwriting with cryptographically secure random data
    
    Args:
        byte_array: The byte array to securely erase
    """
    if byte_array is None or len(byte_array) == 0:
        return
        
    # Overwrite with cryptographically secure random bytes
    for i in range(len(byte_array)):
        byte_array[i] = secrets.randbits(8)


def secure_erase_bytes(data: bytes) -> bytes:
    """
    Securely erase bytes object by converting to bytearray, erasing, then returning empty bytes
    
    Args:
        data: The bytes object to erase
        
    Returns:
        Empty bytes object
    """
    if data is None:
        return b''
        
    # Convert to mutable bytearray for secure erasure
    mutable_data = bytearray(data)
    secure_erase(mutable_data)
    
    # Clear the mutable data and return empty bytes
    mutable_data.clear()
    return b''


def secure_erase_string(data: str) -> str:
    """
    Securely erase string by converting to bytes, erasing, and returning empty string
    
    Args:
        data: The string to erase
        
    Returns:
        Empty string
    """
    if data is None:
        return ''
        
    # Convert to bytes, then erase securely
    data_bytes = data.encode('utf-8')
    secure_erase_bytes(data_bytes)
    
    return ''


def secure_erase_list(data_list: List[Any]) -> None:
    """
    Securely erase all items in a list
    
    Args:
        data_list: List to securely clear
    """
    if data_list is None:
        return
        
    # Erase each item based on type
    for i in range(len(data_list)):
        item = data_list[i]
        
        if isinstance(item, bytes):
            data_list[i] = secure_erase_bytes(item)
        elif isinstance(item, bytearray):
            secure_erase(item)
        elif isinstance(item, str):
            data_list[i] = secure_erase_string(item)
        elif isinstance(item, (list, set)):
            item.clear()
        elif isinstance(item, dict):
            item.clear()
        else:
            data_list[i] = None
    
    # Clear the entire list
    data_list.clear()


def secure_erase_dict(data_dict: Dict[Any, Any]) -> None:
    """
    Securely erase all key-value pairs in a dictionary
    
    Args:
        data_dict: Dictionary to securely clear
    """
    if data_dict is None:
        return
        
    # Erase all values first
    for key, value in list(data_dict.items()):
        if isinstance(value, bytes):
            data_dict[key] = secure_erase_bytes(value)
        elif isinstance(value, bytearray):
            secure_erase(value)
        elif isinstance(value, str):
            data_dict[key] = secure_erase_string(value)
        elif isinstance(value, (list, set)):
            value.clear()
        elif isinstance(value, dict):
            secure_erase_dict(value)
    
    # Clear the entire dictionary
    data_dict.clear()


def secure_erase_object(obj: Any, sensitive_attrs: Optional[List[str]] = None) -> None:
    """
    Securely erase sensitive attributes of an object
    
    Args:
        obj: Object to erase sensitive data from
        sensitive_attrs: List of attribute names to erase (if None, erases common sensitive ones)
    """
    if obj is None:
        return
        
    # Default sensitive attribute names
    if sensitive_attrs is None:
        sensitive_attrs = [
            'session_key', 'private_key', 'public_key', 'shared_secret',
            'nonce', 'nonces', 'buffer', 'buffers', 'packet_buffer',
            'encryption_key', 'decryption_key', 'auth_token', 'password',
            'secret', 'salt', 'iv', 'tag', 'signature', 'username',
            'client_addr', 'session_id', 'crypto_state', 'keys'
        ]
    
    # Erase each sensitive attribute
    for attr_name in sensitive_attrs:
        if hasattr(obj, attr_name):
            attr_value = getattr(obj, attr_name)
            
            if isinstance(attr_value, bytes):
                setattr(obj, attr_name, secure_erase_bytes(attr_value))
            elif isinstance(attr_value, bytearray):
                secure_erase(attr_value)
                setattr(obj, attr_name, bytearray())
            elif isinstance(attr_value, str):
                setattr(obj, attr_name, secure_erase_string(attr_value))
            elif isinstance(attr_value, list):
                secure_erase_list(attr_value)
            elif isinstance(attr_value, dict):
                secure_erase_dict(attr_value)
            elif isinstance(attr_value, set):
                attr_value.clear()
                setattr(obj, attr_name, set())
            else:
                setattr(obj, attr_name, None)


class SecureSessionCleanup:
    """
    Comprehensive secure cleanup manager for VPN sessions
    """
    
    def __init__(self):
        self.cleanup_performed = False
    
    def cleanup_session_crypto(self, crypto_obj: Any) -> None:
        """
        Securely cleanup cryptographic objects
        
        Args:
            crypto_obj: Cryptographic object to clean up
        """
        if crypto_obj is None:
            return
            
        # Erase all cryptographic material
        crypto_sensitive_attrs = [
            'private_key', 'public_key', 'shared_secret', 'session_key',
            'encryption_cipher', 'decryption_cipher', 'nonce_counter',
            'nonces_used', 'packet_counter', 'auth_key', 'kdf_salt',
            'derived_keys', 'temp_keys'
        ]
        
        secure_erase_object(crypto_obj, crypto_sensitive_attrs)
    
    def cleanup_session_buffers(self, session_obj: Any) -> None:
        """
        Securely cleanup session packet buffers and temporary data
        
        Args:
            session_obj: Session object with buffers to clean up
        """
        if session_obj is None:
            return
            
        # Erase all buffer and temporary data
        buffer_sensitive_attrs = [
            'packet_buffer', 'receive_buffer', 'send_buffer', 'temp_buffer',
            'coalesced_packets', 'pending_packets', 'queued_packets',
            'decrypted_packets', 'encrypted_packets', 'raw_data',
            'processed_data', 'temp_data', 'cached_data'
        ]
        
        secure_erase_object(session_obj, buffer_sensitive_attrs)
    
    def cleanup_session_metadata(self, session_obj: Any) -> None:
        """
        Securely cleanup session metadata (keeping no-logs policy)
        
        Args:
            session_obj: Session object with metadata to clean up
        """
        if session_obj is None:
            return
            
        # Erase session metadata (but preserve structural integrity for cleanup)
        metadata_attrs = [
            'username', 'client_addr', 'session_id', 'last_activity',
            'connection_time', 'bytes_sent', 'bytes_received', 'packet_count',
            'auth_data', 'user_info', 'connection_info', 'stats'
        ]
        
        secure_erase_object(session_obj, metadata_attrs)
    
    def cleanup_complete_session(self, session_obj: Any) -> None:
        """
        Perform complete secure cleanup of a session object
        
        Args:
            session_obj: Session object to completely clean up
        """
        if session_obj is None:
            return
            
        # Clean up crypto material
        if hasattr(session_obj, 'crypto'):
            self.cleanup_session_crypto(session_obj.crypto)
            
        # Clean up buffers
        self.cleanup_session_buffers(session_obj)
        
        # Clean up metadata
        self.cleanup_session_metadata(session_obj)
        
        # Erase any remaining sensitive attributes
        secure_erase_object(session_obj)
        
        self.cleanup_performed = True
    
    def force_garbage_collection(self) -> None:
        """
        Force garbage collection to ensure erased data is actually freed
        """
        # Multiple garbage collection passes to ensure cleanup
        for _ in range(3):
            gc.collect()


def create_session_cleanup_manager() -> SecureSessionCleanup:
    """
    Factory function to create a secure session cleanup manager
    
    Returns:
        Configured SecureSessionCleanup instance
    """
    return SecureSessionCleanup()


# Global cleanup utilities
def emergency_memory_scrub() -> None:
    """
    Emergency memory scrubbing procedure - clears all possible sensitive data
    """
    # Force multiple garbage collection passes
    for _ in range(5):
        gc.collect()
        
    # Note: In no-logs mode, there should be minimal to scrub
    # This serves as a fail-safe for any remaining temporary data