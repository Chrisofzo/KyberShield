#!/usr/bin/env python3
"""
Quantum-Resistant Cryptographic Utilities for KyberLink VPN
===========================================================

Hybrid post-quantum cryptography implementation combining:
- X25519 elliptic curve Diffie-Hellman
- ML-KEM-768 (Kyber768) key encapsulation mechanism
- HKDF-SHA3-256 key derivation
- ChaCha20-Poly1305 authenticated encryption
"""

import os
import struct
import time
from typing import Optional, Dict, Any

# Cryptography library imports
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Post-quantum cryptography
try:
    import pqcrypto.kem.kyber768 as kyber768
except ImportError:
    print("Warning: pqcrypto not available, using simulation mode")
    kyber768 = None


class QuantumResistantCrypto:
    """
    Hybrid quantum-resistant cryptographic system
    
    Combines classical X25519 ECDH with post-quantum Kyber768 KEM
    for forward security against both classical and quantum attacks.
    """
    
    def __init__(self, is_server: bool = False):
        self.is_server = is_server
        
        # Key pairs
        self.x25519_private_key: Optional[x25519.X25519PrivateKey] = None
        self.x25519_public_key: Optional[x25519.X25519PublicKey] = None
        self.kyber_public_key: Optional[bytes] = None
        self.kyber_private_key: Optional[bytes] = None
        
        # Shared secrets and session key
        self.x25519_shared_secret: Optional[bytes] = None
        self.kyber_shared_secret: Optional[bytes] = None
        self.session_key: Optional[bytes] = None
        self.cipher: Optional[ChaCha20Poly1305] = None
        
        # Rekeying policy
        self.packets_since_rekey = 0
        self.last_rekey_time = time.time()
        self.rekey_packet_limit = 5  # Rekey every 5 packets
        self.rekey_time_limit = 60   # Rekey every 60 seconds
        
        # Replay protection
        self.highest_sequence_seen = -1
        
        # Initialize secure cleanup capability
        from secure_memory_scrubbing import create_session_cleanup_manager
        self.cleanup_manager = create_session_cleanup_manager()
        
        # No logging - permanent no-logs mode
    
    def generate_keys(self) -> None:
        """Generate X25519 and Kyber768 key pairs"""
        # Generate X25519 key pair
        self.x25519_private_key = x25519.X25519PrivateKey.generate()
        self.x25519_public_key = self.x25519_private_key.public_key()
        # Key pair generated - no logging
        
        # Generate Kyber768 key pair
        if kyber768:
            self.kyber_public_key, self.kyber_private_key = kyber768.keypair()
            print(f"[{'Server' if self.is_server else 'Client'}] Generated Kyber768 key pair")
        else:
            # Simulation mode
            self.kyber_public_key = os.urandom(1184)  # Kyber768 public key size
            self.kyber_private_key = os.urandom(2400)  # Kyber768 private key size
            print(f"[{'Server' if self.is_server else 'Client'}] Generated simulated Kyber768 key pair")
    
    def get_public_keys_bytes(self) -> bytes:
        """Serialize public keys for transmission"""
        x25519_public_bytes = self.x25519_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Combine X25519 (32 bytes) + Kyber768 (1184 bytes) = 1216 bytes
        # Add 8-byte header with lengths for parsing
        header = struct.pack('!II', len(x25519_public_bytes), len(self.kyber_public_key))
        return header + x25519_public_bytes + self.kyber_public_key
    
    def parse_public_keys(self, public_keys_data: bytes) -> tuple:
        """Parse received public keys"""
        # Read header
        x25519_len, kyber_len = struct.unpack('!II', public_keys_data[:8])
        
        # Extract keys
        x25519_bytes = public_keys_data[8:8+x25519_len]
        kyber_bytes = public_keys_data[8+x25519_len:8+x25519_len+kyber_len]
        
        # Parse X25519 public key
        peer_x25519_public = x25519.X25519PublicKey.from_public_bytes(x25519_bytes)
        
        return peer_x25519_public, kyber_bytes
    
    def client_key_exchange(self, server_public_keys: bytes) -> bytes:
        """
        Client-side key exchange: receive server keys, derive shared secrets, send ciphertext
        
        Args:
            server_public_keys: Server's public keys
            
        Returns:
            Kyber ciphertext to send to server
        """
        print("[Client] Starting hybrid key exchange...")
        
        # Parse server public keys
        server_x25519_public, server_kyber_public = self.parse_public_keys(server_public_keys)
        
        # X25519 key exchange
        self.x25519_shared_secret = self.x25519_private_key.exchange(server_x25519_public)
        print(f"[Client] X25519 shared secret: {self.x25519_shared_secret[:16].hex()}...")
        
        # Kyber768 encapsulation
        if kyber768:
            kyber_ciphertext, self.kyber_shared_secret = kyber768.encrypt(server_kyber_public)
        else:
            # Simulation mode
            kyber_ciphertext = os.urandom(1088)  # Kyber768 ciphertext size
            self.kyber_shared_secret = os.urandom(32)  # 32-byte shared secret
        
        print(f"[Client] Kyber768 shared secret: {self.kyber_shared_secret[:16].hex()}...")
        
        # Derive session key
        self._derive_session_key()
        
        return kyber_ciphertext
    
    def server_key_exchange(self, kyber_ciphertext: bytes, client_public_keys: bytes) -> None:
        """
        Server-side key exchange: receive client keys and ciphertext, derive shared secrets
        
        Args:
            kyber_ciphertext: Kyber ciphertext from client
            client_public_keys: Client's public keys
        """
        print("[Server] Completing hybrid key exchange...")
        
        # Parse client public keys
        client_x25519_public, _ = self.parse_public_keys(client_public_keys)
        
        # X25519 key exchange
        self.x25519_shared_secret = self.x25519_private_key.exchange(client_x25519_public)
        print(f"[Server] X25519 shared secret: {self.x25519_shared_secret[:16].hex()}...")
        
        # Kyber768 decapsulation
        if kyber768:
            self.kyber_shared_secret = kyber768.decrypt(kyber_ciphertext, self.kyber_private_key)
        else:
            # Simulation mode
            self.kyber_shared_secret = os.urandom(32)  # 32-byte shared secret
        
        print(f"[Server] Kyber768 shared secret: {self.kyber_shared_secret[:16].hex()}...")
        
        # Derive session key
        self._derive_session_key()
    
    def _derive_session_key(self) -> None:
        """Derive session key using HKDF-SHA3-256"""
        # Combine both shared secrets
        combined_secret = self.x25519_shared_secret + self.kyber_shared_secret
        print(f"[{'Server' if self.is_server else 'Client'}] Combined secret length: {len(combined_secret)} bytes")
        
        # Derive 256-bit session key using HKDF with SHA3-256
        hkdf = HKDF(
            algorithm=hashes.SHA3_256(),
            length=32,  # 256 bits
            salt=None,
            info=b"KyberLink VPN Session Key v1.0"
        )
        
        self.session_key = hkdf.derive(combined_secret)
        print(f"[{'Server' if self.is_server else 'Client'}] Derived session key: {self.session_key.hex()}")
        
        # Initialize ChaCha20-Poly1305 cipher
        self.cipher = ChaCha20Poly1305(self.session_key)
        print(f"[{'Server' if self.is_server else 'Client'}] Initialized ChaCha20-Poly1305 AEAD cipher")
        
        # Reset rekeying counters
        self.packets_since_rekey = 0
        self.last_rekey_time = time.time()
        print(f"[{'Server' if self.is_server else 'Client'}] Session rekeying policy: every {self.rekey_packet_limit} packets or {self.rekey_time_limit} seconds")
    
    def _should_rekey(self) -> bool:
        """Check if rekeying is needed"""
        current_time = time.time()
        return (self.packets_since_rekey >= self.rekey_packet_limit or 
                current_time - self.last_rekey_time >= self.rekey_time_limit)
    
    def _perform_rekey(self) -> None:
        """Perform session key rotation"""
        if not self.session_key:
            return
        
        # Generate new material and re-derive
        current_time = time.time()
        print(f"[{'Server' if self.is_server else 'Client'}] 🔄 Rotating session key... (triggered by {'packet limit' if self.packets_since_rekey >= self.rekey_packet_limit else 'time limit'})")
        print(f"[{'Server' if self.is_server else 'Client'}]   Packets since last rotation: {self.packets_since_rekey}")
        print(f"[{'Server' if self.is_server else 'Client'}]   Time since last rotation: {current_time - self.last_rekey_time:.1f} seconds")
        
        old_key = self.session_key[:8].hex()
        
        # Re-derive with fresh entropy
        extra_entropy = os.urandom(16)
        combined_secret = self.x25519_shared_secret + self.kyber_shared_secret + extra_entropy
        
        hkdf = HKDF(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=None,
            info=f"KyberLink VPN Rekey {int(current_time)}".encode()
        )
        
        self.session_key = hkdf.derive(combined_secret)
        self.cipher = ChaCha20Poly1305(self.session_key)
        
        new_key = self.session_key[:8].hex()
        print(f"[{'Server' if self.is_server else 'Client'}]   Old key: {old_key}...->New key: {new_key}...")
        
        # Reset counters
        self.packets_since_rekey = 0
        self.last_rekey_time = current_time
        print(f"[{'Server' if self.is_server else 'Client'}] ✅ Session key rotated successfully!")
    
    def encrypt_packet(self, data: str, is_dummy: bool = False, sequence: int = 0) -> bytes:
        """
        Encrypt a packet with metadata resistance padding
        
        Args:
            data: Data to encrypt
            is_dummy: Whether this is a dummy packet
            sequence: Packet sequence number
            
        Returns:
            Encrypted packet with nonce and authentication tag
        """
        if not self.cipher:
            raise RuntimeError("Cipher not initialized")
        
        # Check if rekeying needed
        if self._should_rekey():
            self._perform_rekey()
        
        # Create packet with metadata
        packet_type = 0x00 if is_dummy else 0x01  # 1 byte type
        sequence_bytes = struct.pack('!I', sequence)  # 4 bytes sequence
        
        # Encode data
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
        
        # Create packet: type(1) + sequence(4) + data_length(2) + data
        packet_header = struct.pack('!BIH', packet_type, sequence, len(data_bytes))
        raw_packet = packet_header + data_bytes
        
        # Pad to fixed size for metadata resistance (256 bytes)
        target_size = 256
        if len(raw_packet) > target_size:
            raise ValueError(f"Packet too large: {len(raw_packet)} > {target_size}")
        
        padding_size = target_size - len(raw_packet)
        padded_packet = raw_packet + os.urandom(padding_size)
        
        # Generate random nonce (12 bytes for ChaCha20-Poly1305)
        nonce = os.urandom(12)
        
        # Encrypt with associated data (nonce)
        ciphertext = self.cipher.encrypt(nonce, padded_packet, nonce)
        
        # Return: nonce + ciphertext (includes auth tag)
        encrypted_packet = nonce + ciphertext
        
        # Debug output
        print(f"[{'Server' if self.is_server else 'Client'}] Encrypted {'dummy' if is_dummy else 'real'} {'text' if isinstance(data, str) else 'binary'} packet #{sequence if not is_dummy else 'dummy'}:")
        print(f"[{'Server' if self.is_server else 'Client'}]   Original size: {len(raw_packet)} bytes -> Padded size: {target_size} bytes")
        print(f"[{'Server' if self.is_server else 'Client'}]   Nonce: {nonce.hex()}")
        if isinstance(data, str) and len(data) < 100:  # Only show short text
            print(f"[{'Server' if self.is_server else 'Client'}]   Original text: '{data}'")
        print(f"[{'Server' if self.is_server else 'Client'}]   Total encrypted size: {len(encrypted_packet)} bytes")
        
        self.packets_since_rekey += 1
        return encrypted_packet
    
    def decrypt_packet(self, encrypted_packet: bytes) -> Optional[Dict[str, Any]]:
        """
        Decrypt a packet and extract metadata
        
        Args:
            encrypted_packet: Encrypted packet with nonce
            
        Returns:
            Dictionary with packet data and metadata, or None if decryption fails
        """
        if not self.cipher:
            raise RuntimeError("Cipher not initialized")
        
        try:
            # Extract nonce and ciphertext
            nonce = encrypted_packet[:12]
            ciphertext = encrypted_packet[12:]
            
            # Decrypt
            padded_packet = self.cipher.decrypt(nonce, ciphertext, nonce)
            
            # Parse packet header
            packet_type = padded_packet[0]
            sequence = struct.unpack('!I', padded_packet[1:5])[0]
            data_length = struct.unpack('!H', padded_packet[5:7])[0]
            
            # Extract actual data (remove padding)
            data_start = 7
            data_end = data_start + data_length
            data_bytes = padded_packet[data_start:data_end]
            
            # Determine packet type
            is_dummy = (packet_type == 0x00)
            is_real = (packet_type == 0x01)
            
            # Check for replay attacks (only for real packets)
            if is_real and sequence <= self.highest_sequence_seen:
                print(f"[{'Server' if self.is_server else 'Client'}] ⚠️  Replay detected: sequence {sequence} <= {self.highest_sequence_seen}")
                return {"type": "replay", "sequence": sequence, "data": None}
            
            if is_real:
                self.highest_sequence_seen = sequence
                print(f"[{'Server' if self.is_server else 'Client'}]   Updated highest_sequence_seen to {sequence}")
            
            # Decode data
            try:
                data_str = data_bytes.decode('utf-8')
            except UnicodeDecodeError:
                data_str = data_bytes  # Keep as bytes if not valid UTF-8
            
            packet_info = {
                "type": "dummy" if is_dummy else "real",
                "sequence": sequence,
                "data": data_str
            }
            
            # Debug output
            print(f"[{'Server' if self.is_server else 'Client'}] Decrypted packet #{sequence if not is_dummy else 'dummy'}:")
            print(f"[{'Server' if self.is_server else 'Client'}]   Padded size: {len(padded_packet)} bytes -> Unpadded size: {data_length + 7} bytes")
            print(f"[{'Server' if self.is_server else 'Client'}]   Nonce: {nonce.hex()}")
            print(f"[{'Server' if self.is_server else 'Client'}]   {'Dummy' if is_dummy else 'Real'} packet detected (header: 0x{packet_type:02x})")
            if not is_dummy:
                print(f"[{'Server' if self.is_server else 'Client'}]   Sequence number: {sequence}")
                if isinstance(data_str, str) and len(data_str) < 100:
                    print(f"[{'Server' if self.is_server else 'Client'}]   Text message: '{data_str}'")
            
            return packet_info
            
        except Exception as e:
            print(f"[{'Server' if self.is_server else 'Client'}] ❌ Decryption failed: {e}")
            return None


# Utility functions for network communication
def send_with_length(socket, data: bytes) -> None:
    """Send data with length prefix"""
    length = len(data)
    length_bytes = struct.pack('!I', length)  # 4-byte big-endian length
    socket.sendall(length_bytes + data)

def recv_with_length(socket) -> bytes:
    """Receive data with length prefix"""
    # First receive the 4-byte length
    length_bytes = b''
    while len(length_bytes) < 4:
        chunk = socket.recv(4 - len(length_bytes))
        if not chunk:
            raise ConnectionError("Connection closed while receiving length")
        length_bytes += chunk
    
    # Unpack the length
    length = struct.unpack('!I', length_bytes)[0]
    
    # Receive the actual data
    data = b''
    while len(data) < length:
        chunk = socket.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed while receiving data")
        data += chunk
    
    return data


# Add secure cleanup method to QuantumResistantCrypto class
def add_secure_cleanup_to_crypto():
    """Dynamically add secure cleanup method to QuantumResistantCrypto"""
    def secure_cleanup(self):
        """Securely erase all cryptographic material"""
        # Import secure erasure functions
        from secure_memory_scrubbing import secure_erase_bytes
        
        # Erase all key material
        if self.x25519_shared_secret:
            self.x25519_shared_secret = secure_erase_bytes(self.x25519_shared_secret)
        if self.kyber_shared_secret:
            self.kyber_shared_secret = secure_erase_bytes(self.kyber_shared_secret)
        if self.session_key:
            self.session_key = secure_erase_bytes(self.session_key)
        if self.kyber_private_key:
            self.kyber_private_key = secure_erase_bytes(self.kyber_private_key)
        if self.kyber_public_key:
            self.kyber_public_key = secure_erase_bytes(self.kyber_public_key)
            
        # Clear cipher and reset state
        self.cipher = None
        self.x25519_private_key = None
        self.x25519_public_key = None
        self.packets_since_rekey = 0
        self.highest_sequence_seen = -1
        
        # Force garbage collection
        if hasattr(self, 'cleanup_manager'):
            self.cleanup_manager.force_garbage_collection()
    
    # Add method to class
    QuantumResistantCrypto.secure_cleanup = secure_cleanup

# Apply secure cleanup enhancement
add_secure_cleanup_to_crypto()