#!/usr/bin/env python3
"""
Double Ratchet Protocol Implementation for Forward-Secure Communication
========================================================================

Implements the Double Ratchet algorithm similar to Signal Protocol for
per-message forward secrecy with both symmetric and asymmetric ratcheting.
"""

import os
import hmac
import hashlib
import secrets
from typing import Optional, Tuple, Dict, List
from dataclasses import dataclass, field
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


@dataclass
class MessageKey:
    """Represents a message encryption key with its index"""
    index: int
    key: bytes
    
    def __del__(self):
        # Secure cleanup
        if hasattr(self, 'key') and self.key:
            self.key = bytes(len(self.key))


@dataclass 
class ChainKey:
    """Represents a symmetric chain key for ratcheting"""
    key: bytes
    index: int = 0
    
    def __del__(self):
        # Secure cleanup
        if hasattr(self, 'key') and self.key:
            self.key = bytes(len(self.key))


class DoubleRatchet:
    """
    Double Ratchet implementation for forward-secure messaging
    
    Provides:
    - Asymmetric ratchet: New DH exchange per message chain
    - Symmetric ratchet: Key derivation chain per message
    - Out-of-order message handling with skipped key storage
    """
    
    # Constants for key derivation
    KDF_RK_INFO = b"KyberLink-RootKey-v1"
    KDF_CK_INFO = b"KyberLink-ChainKey-v1"
    KDF_MK_INFO = b"KyberLink-MessageKey-v1"
    
    MAX_SKIP = 1000  # Maximum number of skipped message keys to store
    
    def __init__(self, is_initiator: bool = False):
        """
        Initialize Double Ratchet
        
        Args:
            is_initiator: True if this party initiates the conversation
        """
        self.is_initiator = is_initiator
        
        # Diffie-Hellman keys
        self.dh_self: Optional[x25519.X25519PrivateKey] = None
        self.dh_remote: Optional[x25519.X25519PublicKey] = None
        self.dh_ratchet_key: Optional[x25519.X25519PrivateKey] = None
        self.dh_ratchet_public: Optional[x25519.X25519PublicKey] = None
        
        # Chain keys
        self.root_key: Optional[bytes] = None
        self.sending_chain_key: Optional[ChainKey] = None
        self.receiving_chain_key: Optional[ChainKey] = None
        
        # Message counters
        self.send_message_number = 0
        self.receive_message_number = 0
        self.previous_send_chain_length = 0
        
        # Skipped message keys for out-of-order handling
        self.skipped_message_keys: Dict[Tuple[bytes, int], MessageKey] = {}
        
    def initialize_with_keys(self, 
                            shared_secret: bytes,
                            remote_public_key: x25519.X25519PublicKey) -> None:
        """
        Initialize ratchet with initial shared secret and remote public key
        
        Args:
            shared_secret: Initial shared secret from handshake
            remote_public_key: Remote party's public key
        """
        # Generate our DH keypair for ratcheting
        self.dh_self = x25519.X25519PrivateKey.generate()
        
        # Initialize root key from shared secret with proper KDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"KyberLink-Ratchet-Init",
            info=self.KDF_RK_INFO
        )
        self.root_key = hkdf.derive(shared_secret)
        
        if self.is_initiator:
            # Initiator generates first ratchet key pair
            self.dh_ratchet_key = x25519.X25519PrivateKey.generate()
            self.dh_ratchet_public = self.dh_ratchet_key.public_key()
            # Don't perform ratchet step yet - wait for receiver's key
            # Just prepare sending chain
            self.sending_chain_key = ChainKey(
                key=self._kdf(self.root_key, self.KDF_CK_INFO + b"-init-send", 32)
            )
        else:
            # Receiver waits for first message with initiator's ratchet public key
            # No chains initialized yet
            pass
    
    def _kdf(self, input_key: bytes, info: bytes, length: int) -> bytes:
        """
        Key derivation function using HKDF-SHA256
        
        Args:
            input_key: Input key material
            info: Application-specific info string
            length: Output length in bytes
            
        Returns:
            Derived key bytes
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=info
        )
        return hkdf.derive(input_key)
    
    def _kdf_chain(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        """
        Derive next chain key and message key from current chain key
        
        Args:
            chain_key: Current chain key
            
        Returns:
            Tuple of (new_chain_key, message_key)
        """
        # Use HMAC for chain key derivation
        new_chain = hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
        message_key = hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
        return new_chain, message_key
    
    def _dh_ratchet_step(self) -> None:
        """Perform Diffie-Hellman ratchet step"""
        if not self.dh_ratchet_key or not self.dh_remote:
            raise RuntimeError("DH keys not initialized for ratchet step")
        
        # Perform DH exchange
        dh_output = self.dh_ratchet_key.exchange(self.dh_remote)
        
        # Derive new root and chain keys
        combined = self.root_key + dh_output if self.root_key else dh_output
        
        # Derive new root key and sending chain key
        new_root = self._kdf(combined, self.KDF_RK_INFO + b"-root", 32)
        new_chain = self._kdf(combined, self.KDF_RK_INFO + b"-chain", 32)
        
        self.root_key = new_root
        self.sending_chain_key = ChainKey(key=new_chain, index=0)
        
        # Reset send message counter
        self.send_message_number = 0
    
    def ratchet_encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes, int]:
        """
        Encrypt a message with ratcheting
        
        Args:
            plaintext: Message to encrypt
            associated_data: Additional authenticated data
            
        Returns:
            Tuple of (ciphertext, current_dh_public_key, message_number)
        """
        # For initiator's first message, ensure we have the ratchet public key
        if self.is_initiator and self.send_message_number == 0:
            if not self.dh_ratchet_public:
                # This should already be set in initialize_with_keys
                raise RuntimeError("Initiator's ratchet public key not set")
            dh_public_bytes = self.dh_ratchet_public.public_bytes_raw()
        elif self.dh_ratchet_public:
            dh_public_bytes = self.dh_ratchet_public.public_bytes_raw()
        else:
            dh_public_bytes = b""
        
        if not self.sending_chain_key:
            raise RuntimeError("Sending chain not initialized")
        
        # Derive message key from chain
        self.sending_chain_key.key, message_key = self._kdf_chain(self.sending_chain_key.key)
        message_number = self.send_message_number
        self.send_message_number += 1
        
        # Encrypt with ChaCha20-Poly1305
        cipher = ChaCha20Poly1305(message_key[:32])
        nonce = os.urandom(12)
        
        # Include message number and DH public key in associated data
        ad = associated_data + message_number.to_bytes(4, 'big') + dh_public_bytes
        ciphertext = cipher.encrypt(nonce, plaintext, ad)
        
        # Clear message key from memory
        message_key = bytes(len(message_key))
        
        return nonce + ciphertext, dh_public_bytes, message_number
    
    def ratchet_decrypt(self, ciphertext: bytes, 
                        dh_public_key: bytes,
                        message_number: int,
                        associated_data: bytes = b"") -> bytes:
        """
        Decrypt a message with ratcheting
        
        Args:
            ciphertext: Encrypted message with nonce
            dh_public_key: Sender's DH public key
            message_number: Message sequence number
            associated_data: Additional authenticated data
            
        Returns:
            Decrypted plaintext
        """
        # First message handling for receiver
        if not self.is_initiator and not self.dh_remote and dh_public_key:
            # First message from initiator - set up receiving chain
            self.dh_remote = x25519.X25519PublicKey.from_public_bytes(dh_public_key)
            
            # Perform initial DH to get receiving chain
            dh_output = self.dh_self.exchange(self.dh_remote)
            combined = self.root_key + dh_output
            
            # Derive receiving chain key
            self.receiving_chain_key = ChainKey(
                key=self._kdf(combined, self.KDF_CK_INFO + b"-recv", 32)
            )
            self.receive_message_number = 0
            
            # Prepare for sending (generate our ratchet key)
            self.dh_ratchet_key = x25519.X25519PrivateKey.generate()
            self.dh_ratchet_public = self.dh_ratchet_key.public_key()
        
        # Check if we need to perform DH ratchet (new DH key from sender)
        elif dh_public_key and self.dh_remote and \
             dh_public_key != self.dh_remote.public_bytes_raw():
            self._handle_dh_ratchet(dh_public_key)
        
        # Try skipped message keys first
        skip_key = (dh_public_key, message_number)
        if skip_key in self.skipped_message_keys:
            message_key = self.skipped_message_keys.pop(skip_key)
            return self._decrypt_with_key(ciphertext, message_key.key, 
                                         message_number, associated_data, dh_public_key)
        
        # Skip forward if needed
        if not self.receiving_chain_key:
            raise RuntimeError("Receiving chain not initialized")
        
        if message_number < self.receive_message_number:
            raise ValueError(f"Message number {message_number} already processed")
        
        # Store skipped keys
        while self.receive_message_number < message_number:
            if len(self.skipped_message_keys) >= self.MAX_SKIP:
                raise RuntimeError("Too many skipped messages")
            
            # Derive and store skipped key
            self.receiving_chain_key.key, skipped_key = self._kdf_chain(
                self.receiving_chain_key.key
            )
            
            self.skipped_message_keys[(dh_public_key, self.receive_message_number)] = \
                MessageKey(self.receive_message_number, skipped_key)
            
            self.receive_message_number += 1
        
        # Derive key for this message
        self.receiving_chain_key.key, message_key = self._kdf_chain(
            self.receiving_chain_key.key
        )
        self.receive_message_number += 1
        
        return self._decrypt_with_key(ciphertext, message_key, 
                                     message_number, associated_data, dh_public_key)
    
    def _handle_dh_ratchet(self, dh_public_key: bytes) -> None:
        """Handle DH ratchet when receiving new DH public key"""
        # Store previous chain length
        self.previous_send_chain_length = self.send_message_number
        
        # Update remote DH key
        self.dh_remote = x25519.X25519PublicKey.from_public_bytes(dh_public_key)
        
        # Generate new DH keypair
        self.dh_ratchet_key = x25519.X25519PrivateKey.generate()
        self.dh_ratchet_public = self.dh_ratchet_key.public_key()
        
        # Perform ratchet step
        self._dh_ratchet_step()
        
        # Initialize new receiving chain
        dh_output = self.dh_self.exchange(self.dh_remote) if self.dh_self else b""
        combined = self.root_key + dh_output if self.root_key else dh_output
        
        self.root_key = self._kdf(combined, self.KDF_RK_INFO + b"-root", 32)
        chain_key = self._kdf(combined, self.KDF_RK_INFO + b"-chain", 32)
        
        self.receiving_chain_key = ChainKey(key=chain_key, index=0)
        self.receive_message_number = 0
    
    def _decrypt_with_key(self, ciphertext: bytes, message_key: bytes,
                         message_number: int, associated_data: bytes, 
                         dh_public_key: bytes = b"") -> bytes:
        """Decrypt ciphertext with given message key"""
        if len(ciphertext) < 12:
            raise ValueError("Ciphertext too short")
        
        nonce = ciphertext[:12]
        actual_ciphertext = ciphertext[12:]
        
        # Decrypt with ChaCha20-Poly1305
        cipher = ChaCha20Poly1305(message_key[:32])
        # Match the AD format used in encryption
        ad = associated_data + message_number.to_bytes(4, 'big') + dh_public_key
        
        try:
            plaintext = cipher.decrypt(nonce, actual_ciphertext, ad)
            # Clear message key
            message_key = bytes(len(message_key))
            return plaintext
        except Exception as e:
            # Clear message key
            message_key = bytes(len(message_key))
            raise ValueError(f"Decryption failed: {e}")
    
    def get_fingerprint(self) -> bytes:
        """Get session fingerprint for verification"""
        if not self.root_key:
            return b""
        
        # Create fingerprint from root key
        return hashlib.sha256(self.root_key).digest()[:16]
    
    def secure_delete(self) -> None:
        """Securely clear all key material from memory"""
        # Clear all keys
        if self.root_key:
            self.root_key = bytes(len(self.root_key))
        
        if self.sending_chain_key:
            self.sending_chain_key.key = bytes(len(self.sending_chain_key.key))
        
        if self.receiving_chain_key:
            self.receiving_chain_key.key = bytes(len(self.receiving_chain_key.key))
        
        # Clear skipped keys
        for key in self.skipped_message_keys.values():
            if key.key:
                key.key = bytes(len(key.key))
        
        self.skipped_message_keys.clear()
        
        # Clear DH keys
        self.dh_self = None
        self.dh_remote = None
        self.dh_ratchet_key = None
        self.dh_ratchet_public = None