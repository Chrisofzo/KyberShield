#!/usr/bin/env python3
"""
KyberLink VPN Server - Core VPN Server Implementation
=====================================================

Handles hybrid handshake, session management, and packet encryption/decryption.
"""

import socket
import sys
import time
import json
import secrets
import os
from datetime import datetime, timezone

# Add path for local imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_utils import QuantumResistantCrypto, send_with_length, recv_with_length
from user_manager import UserManager
from session_manager import SessionManager
from obfuscator import get_obfuscator
from traffic_shaper import get_traffic_shaper, extract_real_packet
from audit_logger import get_audit_logger
from pq_signatures import get_pq_signer
import secrets


class KyberLinkVPNServer:
    """Core VPN server with quantum-resistant encryption"""
    
    def __init__(self, host='localhost', port=5555, stealth_mode=False, metadata_protection=False):
        self.host = host
        self.port = port
        self.crypto = QuantumResistantCrypto(is_server=True)
        self.user_manager = UserManager()
        self.session_manager = SessionManager()
        self.authenticated_username = None
        self.used_nonces = set()  # Track nonces to prevent replay attacks
        self.current_session_id = None
        self.stealth_mode = stealth_mode
        self.obfuscator = get_obfuscator() if stealth_mode else None
        self.metadata_protection = metadata_protection
        self.traffic_shaper = get_traffic_shaper()
        self.audit_logger = get_audit_logger()
        self.pq_signer = get_pq_signer()
        
        # Packet sequence tracking for replay detection
        self.client_sequences = {}  # client_ip -> set of sequence numbers
        
        # Post-quantum signature keys
        self.pq_public_key = None
        self.pq_private_key = None
        
        if stealth_mode:
            self.audit_logger.log_system_event("StealthMode", "De-obfuscation system activated")
        if metadata_protection:
            self.audit_logger.log_system_event("MetadataProtection", "Dummy packet filtering activated")
        
    def start_server(self):
        """Start the VPN server and handle connections"""
        self.audit_logger.log_event("INFO", "Server", "KyberLink VPN Server starting up")
        
        # Initialize stealth mode if enabled
        if self.stealth_mode:
            # Generate matching obfuscation session key
            shared_secret = b"KyberLink-Server-Stealth-" + secrets.token_bytes(16)
            self.obfuscator.generate_session_key(shared_secret)
            self.audit_logger.log_event("INFO", "Server", "Stealth mode initialized with session key")
        
        # Generate server keys
        self.crypto.generate_keys()
        self.audit_logger.log_event("SUCCESS", "Server", "Quantum-resistant keys generated (X25519 + ML-KEM-768)")
        
        # Generate post-quantum signature keys
        if self.pq_signer.is_available():
            self.pq_public_key, self.pq_private_key = self.pq_signer.generate_keys()
            if self.pq_public_key and self.pq_private_key:
                self.audit_logger.log_event("SUCCESS", "Server", "Generated Dilithium3 key pair for PQ signatures")
            else:
                self.audit_logger.log_event("WARNING", "Server", "Failed to generate Dilithium3 keys")
        else:
            self.audit_logger.log_event("WARNING", "Server", "Post-quantum signatures unavailable: pqcrypto library not found")
        
        # Create and bind socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(1)
            self.audit_logger.log_event("INFO", "Server", f"VPN server listening on {self.host}:{self.port}")
            
            while True:
                client_socket, client_address = server_socket.accept()
                self.audit_logger.log_event("INFO", "Server", f"Client connection established", client_address[0])
                
                try:
                    self.handle_client(client_socket, client_address)
                except Exception as e:
                    self.audit_logger.log_event("ERROR", "Server", f"Error handling client: {e}", client_address[0])
                finally:
                    client_socket.close()
                    self.audit_logger.log_event("INFO", "Server", "Client connection closed", client_address[0])
                    
        except KeyboardInterrupt:
            self.audit_logger.log_event("INFO", "Server", "Server shutdown requested by user")
        except Exception as e:
            self.audit_logger.log_event("ERROR", "Server", f"Server error: {e}")
        finally:
            server_socket.close()
            self.audit_logger.log_event("INFO", "Server", "KyberLink VPN Server stopped")
    
    def handle_login(self, client_socket, client_address):
        """Handle enhanced user login verification with timestamp and nonce validation"""
        try:
            print(f"\n🔐 Receiving login packet from {client_address[0]}...")
            
            # Receive login packet
            client_socket.settimeout(10.0)
            login_packet = recv_with_length(client_socket)
            login_json = login_packet.decode('utf-8')
            login_data = json.loads(login_json)
            
            # Extract login fields
            username = login_data.get("username")
            client_nonce = login_data.get("client_nonce")
            timestamp_str = login_data.get("timestamp")
            version = login_data.get("version")
            
            # Validate required fields
            if not all([username, client_nonce, timestamp_str, version]):
                self.audit_logger.track_packet_anomaly(client_address[0], "malformed", "Invalid login packet - missing required fields")
                response = "LOGIN_REJECTED"
                send_with_length(client_socket, response.encode('utf-8'))
                return False
            
            self.audit_logger.log_event("INFO", "Authentication", f"Login attempt for user '{username}' with version {version}", client_address[0])
            
            # Check if user exists in database
            if not self.user_manager.user_exists(username):
                self.audit_logger.track_login_attempt(client_address[0], username, False)
                response = "LOGIN_REJECTED"
                send_with_length(client_socket, response.encode('utf-8'))
                return False
            
            # Validate timestamp (within ±30 seconds)
            try:
                if timestamp_str.endswith('Z'):
                    timestamp_str = timestamp_str[:-1] + '+00:00'
                client_timestamp = datetime.fromisoformat(timestamp_str)
                server_timestamp = datetime.now(timezone.utc)
                time_diff = abs((server_timestamp - client_timestamp).total_seconds())
                
                if time_diff > 30:
                    self.audit_logger.track_session_violation(client_address[0], "timestamp_skew", f"Time difference: {time_diff:.1f}s (max 30s)")
                    response = "LOGIN_REJECTED"
                    send_with_length(client_socket, response.encode('utf-8'))
                    return False
                    
                self.audit_logger.log_event("INFO", "Authentication", f"Timestamp validated (diff: {time_diff:.1f}s)", client_address[0])
            except Exception as e:
                self.audit_logger.track_packet_anomaly(client_address[0], "malformed", f"Timestamp parsing error: {e}")
                response = "LOGIN_REJECTED"
                send_with_length(client_socket, response.encode('utf-8'))
                return False
            
            # Check nonce replay protection
            if client_nonce in self.used_nonces:
                self.audit_logger.track_session_violation(client_address[0], "replay_attack", f"Nonce replay detected: {client_nonce[:8]}...")
                response = "LOGIN_REJECTED"
                send_with_length(client_socket, response.encode('utf-8'))
                return False
            
            # Store nonce to prevent reuse
            self.used_nonces.add(client_nonce)
            
            # Verify password
            if not self.user_manager.verify_user(username, login_data.get("password", "")):
                self.audit_logger.track_login_attempt(client_address[0], username, False)
                response = "LOGIN_REJECTED"
                send_with_length(client_socket, response.encode('utf-8'))
                return False
            
            # Authentication successful
            self.audit_logger.track_login_attempt(client_address[0], username, True)
            self.authenticated_username = username
            response = "LOGIN_ACCEPTED"
            send_with_length(client_socket, response.encode('utf-8'))
            return True
    
    def send_obfuscated(self, client_socket, data: bytes):
        """Send data with optional obfuscation"""
        if self.stealth_mode and self.obfuscator:
            try:
                obfuscated_data = self.obfuscator.obfuscate(data)
                send_with_length(client_socket, obfuscated_data)
            except Exception as e:
                print(f"[Server] ❌ Obfuscation failed, sending normal packet: {e}")
                send_with_length(client_socket, data)
        else:
            send_with_length(client_socket, data)
    
    def recv_obfuscated(self, client_socket) -> bytes:
        """Receive data with optional deobfuscation and traffic shaping"""
        data = recv_with_length(client_socket)
        
        # Apply deobfuscation if enabled
        if self.stealth_mode and self.obfuscator:
            try:
                deobfuscated_data = self.obfuscator.deobfuscate(data)
            except Exception as e:
                print(f"[Server] ❌ Obfuscation decode failed: {e}")
                # Return original data as fallback
                deobfuscated_data = data
        else:
            deobfuscated_data = data
        
        # Extract real packet from traffic shaping if enabled
        if self.metadata_protection:
            real_packet = extract_real_packet(deobfuscated_data)
            if real_packet is None:
                # This was a dummy packet, return empty to indicate it should be ignored
                return b''
            return real_packet
        else:
            return deobfuscated_data
    
    def handle_client(self, client_socket, client_address):
        """Handle a client connection with login verification and handshake"""
        # Step 1: Receive and verify login packet
        if not self.handle_login(client_socket, client_address):
            return  # Login failed, connection will be closed
        
        print("\n🤝 Starting handshake process...")
        
        # Step 2: Send server public keys to client with post-quantum signature
        self.audit_logger.log_event("INFO", "Server", "Sending handshake public keys to client", client_address[0])
        server_public_keys = self.crypto.get_public_keys_bytes()
        
        # Create signed handshake packet with PQ signature
        handshake_data = {
            "public_keys": server_public_keys.hex(),
            "pq_signature": None,
            "pq_public_key": None
        }
        
        # Add post-quantum signature if available
        if self.pq_public_key and self.pq_private_key:
            signature = self.pq_signer.sign_message(self.pq_private_key, server_public_keys)
            if signature:
                handshake_data["pq_signature"] = signature.hex()
                handshake_data["pq_public_key"] = self.pq_public_key.hex()
                self.audit_logger.log_event("SUCCESS", "Server", "Handshake signed with Dilithium3", client_address[0])
            else:
                self.audit_logger.log_event("ERROR", "Server", "Failed to sign handshake with Dilithium3", client_address[0])
        
        # Send handshake packet
        handshake_json = json.dumps(handshake_data)
        handshake_bytes = handshake_json.encode('utf-8')
        send_with_length(client_socket, handshake_bytes)
        self.audit_logger.log_event("INFO", "Server", f"Sent handshake packet ({len(handshake_bytes)} bytes)", client_address[0])
        
        # Step 3: Receive client public keys
        print("[KyberLink] Receiving client public keys...")
        client_public_keys = recv_with_length(client_socket)
        print(f"[KyberLink] Received {len(client_public_keys)} bytes of public key data")
        
        # Step 4: Receive Kyber ciphertext from client
        print("[KyberLink] Receiving Kyber ciphertext...")
        kyber_ciphertext = recv_with_length(client_socket)
        print(f"[KyberLink] Received {len(kyber_ciphertext)} bytes of Kyber ciphertext")
        
        # Step 5: Complete key exchange
        print("[KyberLink] Completing hybrid key exchange...")
        self.crypto.server_key_exchange(kyber_ciphertext, client_public_keys)
        
        print("\n✅ Handshake completed successfully!")
        print("🔒 Ready to receive encrypted packets...")
        
        # Step 6: Create session and send session ID to client
        session_id = self.session_manager.create_session(self.authenticated_username, client_address[0])
        self.current_session_id = session_id
        self.send_session_id(client_socket, session_id)
        
        # Step 7: Handle encrypted packet communication
        self.handle_encrypted_communication(client_socket, client_address)
    
    def send_session_id(self, client_socket, session_id):
        """Send session ID to client in JSON format"""
        session_packet = {
            "type": "session_id",
            "session_id": session_id
        }
        session_json = json.dumps(session_packet)
        session_bytes = session_json.encode('utf-8')
        send_with_length(client_socket, session_bytes)
        print(f"[KyberLink] Sent session ID {session_id} to client")
    
    def handle_encrypted_communication(self, client_socket, client_address):
        """Receive and decrypt packets from client with dummy packet detection"""
        packet_count = 0
        real_packet_count = 0
        dummy_packet_count = 0
        traffic_shaper_dummy_count = 0
        
        print(f"\n📦 KYBERLINK ENCRYPTED TUNNEL - USER: {self.authenticated_username}")
        print("=" * 70)
        
        try:
            while True:
                # Receive encrypted packet
                print(f"\n[KyberLink] User {self.authenticated_username} - waiting for packet #{packet_count + 1}...")
                
                try:
                    encrypted_packet = self.recv_obfuscated(client_socket)
                    
                    # Skip empty responses (filtered dummy packets from traffic shaping)
                    if len(encrypted_packet) == 0:
                        traffic_shaper_dummy_count += 1
                        print(f"[Server] 🎭 Dropped traffic shaping dummy packet #{traffic_shaper_dummy_count}")
                        continue
                    
                    packet_count += 1
                    print(f"[KyberLink] User {self.authenticated_username} received packet #{packet_count} ({len(encrypted_packet)} bytes)")
                    
                    try:
                        # Decrypt the packet with metadata resistance
                        decrypted_result = self.crypto.decrypt_packet(encrypted_packet)
                        
                        if not decrypted_result:
                            self.audit_logger.track_packet_anomaly(client_address[0], "tampering", f"Failed to decrypt packet #{packet_count}")
                            continue
                    except Exception as decrypt_error:
                        self.audit_logger.track_packet_anomaly(client_address[0], "tampering", f"Decryption error: {decrypt_error}")
                        continue
                    
                    packet_type = decrypted_result.get("type")
                    packet_data = decrypted_result.get("data")
                    
                    if packet_type == "dummy":
                        # Handle dummy packet - discard silently
                        dummy_packet_count += 1
                        self.session_manager.increment_packets(self.current_session_id, "dummy")
                        print(f"[KyberLink][Session {self.current_session_id}] User {self.authenticated_username} - 🗑️  Dropped dummy packet #{dummy_packet_count}")
                        # No acknowledgment for dummy packets
                        
                    elif packet_type == "replay":
                        # Handle replay packet - log and discard
                        sequence_number = decrypted_result.get("sequence", 0)
                        self.audit_logger.track_session_violation(client_address[0], "replay_packet", f"Duplicate sequence number {sequence_number}")
                        # No acknowledgment for replay packets
                        
                    elif packet_type == "real":
                        # Handle real packet
                        real_packet_count += 1
                        sequence_number = decrypted_result.get("sequence", 0)
                        
                        # Check for sequence number replay attacks
                        if client_address[0] not in self.client_sequences:
                            self.client_sequences[client_address[0]] = set()
                        
                        if sequence_number in self.client_sequences[client_address[0]]:
                            self.audit_logger.track_session_violation(client_address[0], "sequence_replay", f"Duplicate sequence {sequence_number}")
                            continue
                        
                        self.client_sequences[client_address[0]].add(sequence_number)
                        
                        # Increment packets processed for this session
                        self.session_manager.increment_packets(self.current_session_id, "real")
                        
                        self.audit_logger.log_event("INFO", "PacketProcessing", f"Processed packet #{sequence_number}: '{packet_data[:50]}...'", client_address[0])
                        
                        # Send acknowledgment back only for real packets
                        ack_message = f"ACK: Received packet #{sequence_number}"
                        ack_packet = self.crypto.encrypt_packet(ack_message, is_dummy=False)
                        send_with_length(client_socket, ack_packet)
                        
                    else:
                        self.audit_logger.track_packet_anomaly(client_address[0], "malformed", f"Unknown packet type: {packet_type}")
                    
                except socket.timeout:
                    print("[KyberLink] No data received (timeout)")
                    break
                except ConnectionError as e:
                    print(f"[KyberLink] Connection error: {e}")
                    break
                    
        except KeyboardInterrupt:
            print("\n[KyberLink] Communication interrupted by user")
        
        # Clean up session
        if self.current_session_id:
            self.session_manager.remove_session(self.current_session_id)
        else:
            print(f"\n[KyberLink] 🔚 Session ended for user {self.authenticated_username}")
            print(f"[KyberLink] Session Summary:")
            print(f"[KyberLink]   User: {self.authenticated_username}")
            print(f"[KyberLink]   Client IP: {client_address[0]}")
            print(f"[KyberLink]   Total packets received: {packet_count}")
            print(f"[KyberLink]   Real packets processed: {real_packet_count}")
            print(f"[KyberLink]   Crypto dummy packets dropped: {dummy_packet_count}")
            if self.metadata_protection:
                print(f"[KyberLink]   Traffic shaping dummy packets dropped: {traffic_shaper_dummy_count}")


def main():
    server = KyberLinkVPNServer()
    server.start_server()


if __name__ == "__main__":
    main()