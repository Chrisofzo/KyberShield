#!/usr/bin/env python3
"""
Quantum-Resistant VPN Protocol MVP - Hybrid Handshake

This script demonstrates a hybrid key exchange that combines:
1. X25519 elliptic-curve Diffie-Hellman (classical security)
2. Kyber768 post-quantum KEM (quantum resistance)
3. HKDF with SHA3-256 for key derivation

The handshake simulates a client and server independently deriving
the same 256-bit session key for secure communication.
"""

import os
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
# Note: Using ML-KEM-768 which is the NIST standardized version of Kyber768
import pqcrypto.kem.ml_kem_768 as kyber768


class HybridKeyExchange:
    """Implements hybrid classical + post-quantum key exchange"""
    
    def __init__(self):
        self.x25519_private_key = None
        self.x25519_public_key = None
        self.kyber_private_key = None
        self.kyber_public_key = None
        self.session_key = None
        self.aead_cipher = None
    
    def generate_keys(self):
        """Generate both X25519 and Kyber768 key pairs"""
        # Generate X25519 key pair (classical ECDH)
        self.x25519_private_key = X25519PrivateKey.generate()
        self.x25519_public_key = self.x25519_private_key.public_key()
        
        # Generate Kyber768 key pair (post-quantum KEM)
        self.kyber_public_key, self.kyber_private_key = kyber768.generate_keypair()
        
        print(f"Generated X25519 key pair")
        print(f"Generated Kyber768 key pair")
    
    def get_public_keys(self):
        """Return public keys for transmission to peer"""
        x25519_public_bytes = self.x25519_public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )
        return x25519_public_bytes, self.kyber_public_key
    
    def perform_key_exchange(self, peer_x25519_public, peer_kyber_public):
        """
        Perform hybrid key exchange with peer's public keys
        Returns the derived 256-bit session key
        """
        # Step 1: X25519 key exchange (classical)
        peer_x25519_key = X25519PublicKey.from_public_bytes(peer_x25519_public)
        x25519_shared_secret = self.x25519_private_key.exchange(peer_x25519_key)
        
        # Step 2: Kyber768 encapsulation (post-quantum)
        kyber_ciphertext, kyber_shared_secret = kyber768.encrypt(peer_kyber_public)
        
        # Step 3: Combine secrets using HKDF with SHA3-256
        combined_secret = x25519_shared_secret + kyber_shared_secret
        
        # Derive 256-bit session key using HKDF-SHA3-256
        hkdf = HKDF(
            algorithm=hashes.SHA3_256(),
            length=32,  # 256 bits
            salt=b"quantum-resistant-vpn-v1",
            info=b"session-key-derivation",
        )
        self.session_key = hkdf.derive(combined_secret)
        
        print(f"X25519 shared secret: {x25519_shared_secret.hex()[:32]}...")
        print(f"Kyber768 shared secret: {kyber_shared_secret.hex()[:32]}...")
        print(f"Combined secret length: {len(combined_secret)} bytes")
        print(f"Derived session key: {self.session_key.hex()}")
        
        return self.session_key, kyber_ciphertext
    
    def complete_key_exchange(self, kyber_ciphertext, peer_x25519_public):
        """
        Complete key exchange on the receiving side (decrypt Kyber ciphertext)
        """
        # Step 1: X25519 key exchange (classical)
        peer_x25519_key = X25519PublicKey.from_public_bytes(peer_x25519_public)
        x25519_shared_secret = self.x25519_private_key.exchange(peer_x25519_key)
        
        # Step 2: Kyber768 decapsulation (post-quantum)
        kyber_shared_secret = kyber768.decrypt(self.kyber_private_key, kyber_ciphertext)
        
        # Step 3: Combine secrets using HKDF with SHA3-256
        combined_secret = x25519_shared_secret + kyber_shared_secret
        
        # Derive 256-bit session key using HKDF-SHA3-256
        hkdf = HKDF(
            algorithm=hashes.SHA3_256(),
            length=32,  # 256 bits
            salt=b"quantum-resistant-vpn-v1",
            info=b"session-key-derivation",
        )
        self.session_key = hkdf.derive(combined_secret)
        
        print(f"X25519 shared secret: {x25519_shared_secret.hex()[:32]}...")
        print(f"Kyber768 shared secret: {kyber_shared_secret.hex()[:32]}...")
        print(f"Combined secret length: {len(combined_secret)} bytes")
        print(f"Derived session key: {self.session_key.hex()}")
        
        return self.session_key

    def initialize_aead_cipher(self):
        """Initialize ChaCha20-Poly1305 AEAD cipher with the session key"""
        if self.session_key is None:
            raise ValueError("Session key must be derived before initializing AEAD cipher")
        self.aead_cipher = ChaCha20Poly1305(self.session_key)
        print("Initialized ChaCha20-Poly1305 AEAD cipher")

    def encrypt_message(self, plaintext):
        """
        Encrypt a message using ChaCha20-Poly1305 AEAD
        Returns (ciphertext, nonce)
        """
        if self.aead_cipher is None:
            raise ValueError("AEAD cipher not initialized")
        
        # Generate random 12-byte nonce
        nonce = os.urandom(12)
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Encrypt with authentication
        ciphertext = self.aead_cipher.encrypt(nonce, plaintext_bytes, None)
        
        print(f"Encrypted message with nonce: {nonce.hex()}")
        print(f"Ciphertext: {ciphertext.hex()}")
        
        return ciphertext, nonce

    def decrypt_message(self, ciphertext, nonce):
        """
        Decrypt a message using ChaCha20-Poly1305 AEAD
        Returns decrypted plaintext
        """
        if self.aead_cipher is None:
            raise ValueError("AEAD cipher not initialized")
        
        # Decrypt and verify authentication
        plaintext_bytes = self.aead_cipher.decrypt(nonce, ciphertext, None)
        plaintext = plaintext_bytes.decode('utf-8')
        
        print(f"Decrypted with nonce: {nonce.hex()}")
        print(f"Decrypted plaintext: {plaintext}")
        
        return plaintext


def simulate_handshake():
    """Simulate a complete hybrid handshake between client and server"""
    print("=" * 70)
    print("QUANTUM-RESISTANT VPN PROTOCOL - HYBRID HANDSHAKE SIMULATION")
    print("=" * 70)
    print()
    
    # Initialize client and server
    print("🔐 Initializing Client and Server...")
    client = HybridKeyExchange()
    server = HybridKeyExchange()
    
    # Generate key pairs
    print("\n📊 Generating Key Pairs...")
    print("\nClient:")
    client.generate_keys()
    print("\nServer:")
    server.generate_keys()
    
    # Exchange public keys
    print("\n🔄 Exchanging Public Keys...")
    client_x25519_public, client_kyber_public = client.get_public_keys()
    server_x25519_public, server_kyber_public = server.get_public_keys()
    
    print(f"Client X25519 public key: {client_x25519_public.hex()[:32]}...")
    print(f"Server X25519 public key: {server_x25519_public.hex()[:32]}...")
    print(f"Client Kyber768 public key length: {len(client_kyber_public)} bytes")
    print(f"Server Kyber768 public key length: {len(server_kyber_public)} bytes")
    
    # Perform hybrid key exchange
    print("\n🤝 Performing Hybrid Key Exchange...")
    
    print("\nClient deriving session key:")
    client_session_key, kyber_ciphertext_for_server = client.perform_key_exchange(
        server_x25519_public, server_kyber_public
    )
    
    print(f"\nKyber ciphertext length: {len(kyber_ciphertext_for_server)} bytes")
    
    print("\nServer deriving session key:")
    server_session_key = server.complete_key_exchange(
        kyber_ciphertext_for_server, client_x25519_public
    )
    
    # Verify both sides derived the same key
    print("\n✅ VERIFICATION RESULTS:")
    print("=" * 70)
    print(f"Client session key: {client_session_key.hex()}")
    print(f"Server session key: {server_session_key.hex()}")
    print(f"Keys match: {client_session_key == server_session_key}")
    
    if client_session_key == server_session_key:
        print("\n🎉 SUCCESS! Both sides derived the same 256-bit session key!")
        print("The hybrid quantum-resistant handshake is working correctly.")
        
        # Now test authenticated encryption with ChaCha20-Poly1305
        print("\n🔒 TESTING AUTHENTICATED ENCRYPTION...")
        print("=" * 70)
        
        # Initialize AEAD ciphers on both sides
        print("\nInitializing ChaCha20-Poly1305 ciphers:")
        client.initialize_aead_cipher()
        server.initialize_aead_cipher()
        
        # Test message encryption and decryption
        test_message = "Hello, this is a quantum-proof VPN test"
        print(f"\nOriginal message: '{test_message}'")
        
        # Client encrypts the message
        print("\nClient encrypting message:")
        ciphertext, nonce = client.encrypt_message(test_message)
        
        # Simulate sending ciphertext and nonce to server
        print(f"\nSimulating transmission:")
        print(f"Sending ciphertext ({len(ciphertext)} bytes) and nonce ({len(nonce)} bytes) to server...")
        
        # Server decrypts the message
        print("\nServer decrypting message:")
        decrypted_message = server.decrypt_message(ciphertext, nonce)
        
        # Verify the decrypted message matches the original
        print("\n✅ ENCRYPTION/DECRYPTION RESULTS:")
        print("=" * 70)
        print(f"Original message:  '{test_message}'")
        print(f"Decrypted message: '{decrypted_message}'")
        print(f"Messages match: {test_message == decrypted_message}")
        
        if test_message == decrypted_message:
            print("\n🎉 ENCRYPTION TEST SUCCESS!")
            print("ChaCha20-Poly1305 authenticated encryption is working correctly!")
            print("The quantum-resistant VPN protocol is fully functional!")
            encryption_success = True
        else:
            print("\n❌ ENCRYPTION TEST FAILURE!")
            print("There is an issue with the authenticated encryption.")
            encryption_success = False
            
        return client_session_key == server_session_key and encryption_success
    else:
        print("\n❌ FAILURE! Session keys do not match!")
        print("There is an issue with the key exchange implementation.")
        return False


if __name__ == "__main__":
    success = simulate_handshake()
    exit(0 if success else 1)