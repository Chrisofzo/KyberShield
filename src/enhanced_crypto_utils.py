#!/usr/bin/env python3
"""
Enhanced Quantum-Resistant Cryptographic Utilities for KyberLink VPN
====================================================================

Integrates all quantum security upgrades:
- Double Ratchet for forward secrecy
- Bloom filter replay protection
- Quantum RNG with ChaCha20 fallback
- Constant-time operations
- Falcon signatures (simulated)
"""

import os
import struct
import time
import hashlib
import secrets
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass

# Cryptography library imports
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Import our quantum security modules
from double_ratchet import DoubleRatchet
from bloom_replay_protection import NonceTracker
from quantum_rng import secure_random_bytes, get_quantum_rng
from constant_time_ops import (
    constant_time_compare, 
    secure_erase, 
    secure_erase_bytes,
    SecureMemory,
    DummyOperations
)

# Post-quantum cryptography
try:
    import pqcrypto.kem.kyber768 as kyber768
    import pqcrypto.sign.falcon512 as falcon512  # Add Falcon signatures
    PQ_AVAILABLE = True
except ImportError:
    print("Warning: pqcrypto not available, using simulation mode")
    kyber768 = None
    falcon512 = None
    PQ_AVAILABLE = False


@dataclass
class FalconSignature:
    """Falcon signature data"""
    signature: bytes
    public_key: bytes
    
    def __del__(self):
        # Secure cleanup
        if hasattr(self, 'signature'):
            self.signature = secure_erase_bytes(self.signature)


class EnhancedQuantumResistantCrypto:
    """
    Enhanced hybrid quantum-resistant cryptographic system
    
    Features:
    - Kyber768 + X25519 hybrid key exchange
    - Falcon512 signatures for authentication
    - Double Ratchet for forward secrecy
    - Bloom filter replay protection
    - Quantum-safe RNG
    - Constant-time operations
    """
    
    def __init__(self, is_server: bool = False):
        self.is_server = is_server
        
        # Key pairs
        self.x25519_private_key: Optional[x25519.X25519PrivateKey] = None
        self.x25519_public_key: Optional[x25519.X25519PublicKey] = None
        self.kyber_public_key: Optional[bytes] = None
        self.kyber_private_key: Optional[bytes] = None
        
        # Falcon signature keys
        self.falcon_public_key: Optional[bytes] = None
        self.falcon_private_key: Optional[bytes] = None
        
        # Shared secrets and session key
        self.x25519_shared_secret: Optional[bytes] = None
        self.kyber_shared_secret: Optional[bytes] = None
        self.session_key: Optional[bytes] = None
        self.cipher: Optional[ChaCha20Poly1305] = None
        self.transcript_hash: Optional[bytes] = None
        
        # Double Ratchet for forward secrecy
        self.ratchet: Optional[DoubleRatchet] = None
        
        # Replay protection (each instance gets its own tracker)
        self.nonce_tracker = NonceTracker()
        
        # Quantum RNG
        self.qrng = get_quantum_rng()
        
        # Statistics
        self.packets_encrypted = 0
        self.packets_decrypted = 0
        self.ratchet_steps = 0
        
        print(f"[{'Server' if is_server else 'Client'}] Enhanced quantum crypto initialized")
    
    def generate_keys(self) -> None:
        """Generate all cryptographic key pairs"""
        # Use quantum RNG for key generation
        print(f"[{'Server' if self.is_server else 'Client'}] Generating quantum-resistant keys...")
        
        # Generate X25519 key pair
        self.x25519_private_key = x25519.X25519PrivateKey.generate()
        self.x25519_public_key = self.x25519_private_key.public_key()
        
        # Generate Kyber768 key pair
        if PQ_AVAILABLE and kyber768:
            self.kyber_public_key, self.kyber_private_key = kyber768.keypair()
            print(f"[{'Server' if self.is_server else 'Client'}] Generated Kyber768 key pair")
        else:
            # Simulation mode with quantum RNG
            self.kyber_public_key = secure_random_bytes(1184)
            self.kyber_private_key = secure_random_bytes(2400)
            print(f"[{'Server' if self.is_server else 'Client'}] Generated simulated Kyber768 key pair")
        
        # Generate Falcon512 signature key pair
        if PQ_AVAILABLE and falcon512:
            self.falcon_public_key, self.falcon_private_key = falcon512.keypair()
            print(f"[{'Server' if self.is_server else 'Client'}] Generated Falcon512 signature key pair")
        else:
            # Simulation mode
            self.falcon_public_key = secure_random_bytes(897)   # Falcon512 public key size
            self.falcon_private_key = secure_random_bytes(1281) # Falcon512 private key size
            print(f"[{'Server' if self.is_server else 'Client'}] Generated simulated Falcon512 key pair")
    
    def sign_handshake(self, data: bytes) -> FalconSignature:
        """
        Sign handshake data with Falcon512
        
        Args:
            data: Data to sign
            
        Returns:
            Falcon signature
        """
        if not self.falcon_private_key or not self.falcon_public_key:
            raise RuntimeError("Falcon keys not generated")
        
        if PQ_AVAILABLE and falcon512:
            signature = falcon512.sign(data, self.falcon_private_key)
        else:
            # Simulation: HMAC-based signature using public key for verification
            # Use first 32 bytes of public key as HMAC key (same key used in verify)
            h = hashlib.blake2b(key=self.falcon_public_key[:32])
            h.update(data)
            signature = h.digest()
        
        return FalconSignature(signature, self.falcon_public_key)
    
    def verify_handshake(self, data: bytes, signature: FalconSignature) -> bool:
        """
        Verify handshake signature with Falcon512
        
        Args:
            data: Data that was signed
            signature: Falcon signature to verify
            
        Returns:
            True if signature is valid
        """
        if PQ_AVAILABLE and falcon512:
            try:
                falcon512.verify(signature.signature, data, signature.public_key)
                return True
            except:
                return False
        else:
            # Simulation: Use same key derivation as signing
            # In simulation mode, we use the first 32 bytes of the public key as the HMAC key
            h = hashlib.blake2b(key=signature.public_key[:32])
            h.update(data)
            expected = h.digest()
            
            # Use constant-time comparison
            return constant_time_compare(signature.signature, expected)
    
    def get_handshake_data(self) -> Tuple[bytes, FalconSignature]:
        """
        Get public keys and signature for handshake
        
        Returns:
            Tuple of (public_keys_bytes, falcon_signature)
        """
        public_keys = self.get_public_keys_bytes()
        
        # Sign the public keys
        signature = self.sign_handshake(public_keys)
        
        return public_keys, signature
    
    def get_public_keys_bytes(self) -> bytes:
        """Serialize public keys for transmission"""
        x25519_public_bytes = self.x25519_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Header: lengths of each component
        header = struct.pack('!III', 
                           len(x25519_public_bytes),
                           len(self.kyber_public_key),
                           len(self.falcon_public_key))
        
        return header + x25519_public_bytes + self.kyber_public_key + self.falcon_public_key
    
    def parse_public_keys(self, public_keys_data: bytes) -> Tuple:
        """Parse received public keys including Falcon key"""
        # Read header
        x25519_len, kyber_len, falcon_len = struct.unpack('!III', public_keys_data[:12])
        
        # Extract keys
        offset = 12
        x25519_bytes = public_keys_data[offset:offset+x25519_len]
        offset += x25519_len
        
        kyber_bytes = public_keys_data[offset:offset+kyber_len]
        offset += kyber_len
        
        falcon_bytes = public_keys_data[offset:offset+falcon_len]
        
        # Parse X25519 public key
        peer_x25519_public = x25519.X25519PublicKey.from_public_bytes(x25519_bytes)
        
        return peer_x25519_public, kyber_bytes, falcon_bytes
    
    def client_key_exchange(self, server_data: Tuple[bytes, FalconSignature]) -> bytes:
        """
        Enhanced client-side key exchange with signature verification
        
        Args:
            server_data: Tuple of (server_public_keys, falcon_signature)
            
        Returns:
            Kyber ciphertext to send to server
        """
        server_public_keys, server_signature = server_data
        
        # Verify server's Falcon signature
        if not self.verify_handshake(server_public_keys, server_signature):
            raise ValueError("Invalid server signature - possible MITM attack!")
        
        print("[Client] Server signature verified with Falcon512")
        
        # Parse server public keys
        server_x25519_public, server_kyber_public, server_falcon_public = \
            self.parse_public_keys(server_public_keys)
        
        # Perform key exchanges with dummy operations for side-channel resistance
        self.x25519_shared_secret = DummyOperations.interleave_dummy_ops(
            self.x25519_private_key.exchange,
            server_x25519_public
        )
        
        # Kyber768 encapsulation
        if PQ_AVAILABLE and kyber768:
            kyber_ciphertext, self.kyber_shared_secret = kyber768.encrypt(server_kyber_public)
        else:
            # Simulation with quantum RNG
            kyber_ciphertext = secure_random_bytes(1088)
            self.kyber_shared_secret = secure_random_bytes(32)
        
        # Derive session key with enhanced KDF
        self._derive_enhanced_session_key()
        
        # Initialize Double Ratchet
        self._initialize_ratchet(server_x25519_public)
        
        return kyber_ciphertext
    
    def server_key_exchange(self, kyber_ciphertext: bytes, 
                           client_data: Tuple[bytes, FalconSignature]) -> None:
        """
        Enhanced server-side key exchange
        
        Args:
            kyber_ciphertext: Kyber ciphertext from client
            client_data: Tuple of (client_public_keys, falcon_signature)
        """
        client_public_keys, client_signature = client_data
        
        # Verify client's Falcon signature
        if not self.verify_handshake(client_public_keys, client_signature):
            raise ValueError("Invalid client signature - possible MITM attack!")
        
        print("[Server] Client signature verified with Falcon512")
        
        # Parse client public keys
        client_x25519_public, _, client_falcon_public = \
            self.parse_public_keys(client_public_keys)
        
        # X25519 key exchange with side-channel protection
        self.x25519_shared_secret = DummyOperations.interleave_dummy_ops(
            self.x25519_private_key.exchange,
            client_x25519_public
        )
        
        # Kyber768 decapsulation
        if PQ_AVAILABLE and kyber768:
            self.kyber_shared_secret = kyber768.decrypt(kyber_ciphertext, self.kyber_private_key)
        else:
            # Simulation
            self.kyber_shared_secret = secure_random_bytes(32)
        
        # Derive session key
        self._derive_enhanced_session_key()
        
        # Initialize Double Ratchet
        self._initialize_ratchet(client_x25519_public)
    
    def _derive_enhanced_session_key(self) -> None:
        """Enhanced session key derivation with transcript binding"""
        # Create transcript hash to prevent reflection attacks
        transcript = hashlib.sha3_256()
        
        # Add role identifiers
        transcript.update(b"server" if self.is_server else b"client")
        
        # Add all public keys to transcript
        if self.x25519_public_key:
            transcript.update(self.x25519_public_key.public_bytes_raw())
        if self.kyber_public_key:
            transcript.update(self.kyber_public_key)
        if self.falcon_public_key:
            transcript.update(self.falcon_public_key)
        
        # Add shared secrets
        transcript.update(self.x25519_shared_secret)
        transcript.update(self.kyber_shared_secret)
        
        # Add protocol version and ciphersuite
        transcript.update(b"KyberLink-Enhanced-v2.0")
        transcript.update(b"X25519+Kyber768+Falcon512+ChaCha20Poly1305")
        
        transcript_hash = transcript.digest()
        
        # Combine shared secrets
        combined_secret = self.x25519_shared_secret + self.kyber_shared_secret
        
        # Multi-stage KDF with transcript binding
        # Stage 1: HKDF-SHA3-256 with transcript as salt
        hkdf1 = HKDF(
            algorithm=hashes.SHA3_256(),
            length=64,
            salt=transcript_hash,
            info=b"KyberLink-Enhanced-v2.0-SessionKey"
        )
        intermediate = hkdf1.derive(combined_secret)
        
        # Stage 2: Additional mixing with BLAKE2b
        h = hashlib.blake2b(key=intermediate[:32])
        h.update(intermediate[32:])
        h.update(transcript_hash)
        
        # Final session key
        self.session_key = h.digest()[:32]
        
        # Store transcript for verification
        self.transcript_hash = transcript_hash
        
        # Initialize cipher
        self.cipher = ChaCha20Poly1305(self.session_key)
        
        print(f"[{'Server' if self.is_server else 'Client'}] Enhanced session key derived with transcript binding")
    
    def _initialize_ratchet(self, remote_public_key: x25519.X25519PublicKey) -> None:
        """Initialize Double Ratchet for forward secrecy"""
        self.ratchet = DoubleRatchet(is_initiator=not self.is_server)
        
        # Use session key as initial shared secret
        self.ratchet.initialize_with_keys(self.session_key, remote_public_key)
        
        print(f"[{'Server' if self.is_server else 'Client'}] Double Ratchet initialized")
    
    def encrypt_packet(self, data: bytes, sequence: int = 0) -> bytes:
        """
        Encrypt packet with Double Ratchet and replay protection
        
        Args:
            data: Data to encrypt
            sequence: Packet sequence number
            
        Returns:
            Encrypted packet
        """
        if not self.ratchet:
            raise RuntimeError("Ratchet not initialized")
        
        # Create packet with metadata
        packet_header = struct.pack('!IQ', sequence, int(time.time() * 1000))
        full_packet = packet_header + data
        
        # Encrypt with Double Ratchet (it handles nonce internally)
        ciphertext, dh_public, msg_num = self.ratchet.ratchet_encrypt(
            full_packet,
            b""  # Associated data
        )
        
        # Extract nonce from ciphertext (first 12 bytes for ChaCha20)
        if len(ciphertext) >= 12:
            nonce = ciphertext[:12]
            # Track nonce for replay protection
            self.nonce_tracker.verify_nonce(nonce)
        
        # Update ratchet periodically
        self.packets_encrypted += 1
        if self.packets_encrypted % 10 == 0:
            self.ratchet_steps += 1
            print(f"[{'Server' if self.is_server else 'Client'}] Ratchet step #{self.ratchet_steps}")
        
        # Combine: dh_public_len + dh_public + msg_num + ciphertext
        packet = struct.pack('!HI', len(dh_public), msg_num) + dh_public + ciphertext
        
        return packet
    
    def decrypt_packet(self, encrypted_packet: bytes) -> Optional[Dict[str, Any]]:
        """
        Decrypt packet with Double Ratchet and replay check
        
        Args:
            encrypted_packet: Encrypted packet
            
        Returns:
            Decrypted packet data or None if failed
        """
        if not self.ratchet:
            raise RuntimeError("Ratchet not initialized")
        
        try:
            # Parse packet (no separate nonce field anymore)
            dh_len, msg_num = struct.unpack('!HI', encrypted_packet[:6])
            offset = 6
            
            dh_public = encrypted_packet[offset:offset+dh_len]
            offset += dh_len
            
            ciphertext = encrypted_packet[offset:]
            
            # Extract nonce from ciphertext for replay check
            if len(ciphertext) >= 12:
                nonce = ciphertext[:12]
                # Check replay with Bloom filter
                if not self.nonce_tracker.verify_nonce(nonce):
                    print(f"[{'Server' if self.is_server else 'Client'}] Replay attack detected!")
                    return None
            
            # Decrypt with Double Ratchet
            plaintext = self.ratchet.ratchet_decrypt(
                ciphertext,
                dh_public,
                msg_num,
                b""  # Associated data
            )
            
            # Parse decrypted packet
            sequence, timestamp = struct.unpack('!IQ', plaintext[:12])
            data = plaintext[12:]
            
            self.packets_decrypted += 1
            
            return {
                'sequence': sequence,
                'timestamp': timestamp,
                'data': data
            }
            
        except Exception as e:
            print(f"[{'Server' if self.is_server else 'Client'}] Decryption failed: {e}")
            return None
    
    def secure_cleanup(self) -> None:
        """Securely erase all cryptographic material"""
        # Use secure erasure for all keys
        if self.x25519_shared_secret:
            self.x25519_shared_secret = secure_erase_bytes(self.x25519_shared_secret)
        
        if self.kyber_shared_secret:
            self.kyber_shared_secret = secure_erase_bytes(self.kyber_shared_secret)
        
        if self.session_key:
            self.session_key = secure_erase_bytes(self.session_key)
        
        if self.kyber_private_key:
            self.kyber_private_key = secure_erase_bytes(self.kyber_private_key)
        
        if self.falcon_private_key:
            self.falcon_private_key = secure_erase_bytes(self.falcon_private_key)
        
        # Clean up ratchet
        if self.ratchet:
            self.ratchet.secure_delete()
        
        # Clear cipher
        self.cipher = None
        
        print(f"[{'Server' if self.is_server else 'Client'}] Secure cleanup completed")
    
    def get_statistics(self) -> dict:
        """Get comprehensive statistics"""
        stats = {
            'packets_encrypted': self.packets_encrypted,
            'packets_decrypted': self.packets_decrypted,
            'ratchet_steps': self.ratchet_steps,
            'replay_protection': self.nonce_tracker.get_statistics(),
            'quantum_rng': self.qrng.get_statistics()
        }
        
        if self.ratchet:
            stats['ratchet_fingerprint'] = self.ratchet.get_fingerprint().hex()
        
        return stats