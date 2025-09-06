#!/usr/bin/env python3
"""
KyberLink - Quantum-Resistant VPN Server

This server performs:
1. Hybrid key exchange (X25519 + Kyber768)
2. Session key derivation with HKDF-SHA3-256
3. ChaCha20-Poly1305 packet decryption
"""

import socket
import sys
import time
import json
import secrets
from datetime import datetime, timezone
from crypto_utils import QuantumResistantCrypto, send_with_length, recv_with_length
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from user_manager import UserManager
from tun_interface import TunInterface


class VPNServer:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.crypto = QuantumResistantCrypto(is_server=True)
        self.user_manager = UserManager()
        self.authenticated_username = None
        self.used_nonces = set()  # Track nonces to prevent replay attacks
        self.sessions = {}  # Global sessions dictionary
        self.current_session_id = None
        self.tun_interface = None
        self.tun_fd = None
        
    def start_server(self):
        """Start the VPN server and handle connections"""
        print("=" * 70)
        print("🔐 KYBERLINK VPN SERVER - QUANTUM-RESISTANT TUNNEL")
        print("=" * 70)
        
        # Generate server keys
        print("\n🔐 Generating Server Keys...")
        self.crypto.generate_keys()
        
        # Initialize TUN interface
        print("\n🌐 Initializing TUN interface...")
        self.tun_interface = TunInterface()
        self.tun_fd = self.tun_interface.open_tun("tun0")
        
        if self.tun_fd:
            print("[Server] TUN interface ready for packet injection")
        else:
            print("[Server] Warning: TUN interface not available, using simulation mode")
        
        # Create and bind socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(1)
            print(f"\n📡 KyberLink VPN Server listening on {self.host}:{self.port}")
            print("Waiting for client connection...")
            
            while True:
                client_socket, client_address = server_socket.accept()
                print(f"\n📡 Client connected from {client_address}")
                
                try:
                    self.handle_client(client_socket)
                except Exception as e:
                    print(f"❌ Error handling client: {e}")
                finally:
                    client_socket.close()
                    print("🔌 Client disconnected")
                    
        except KeyboardInterrupt:
            print("\n🛑 Server shutdown requested")
        except Exception as e:
            print(f"❌ Server error: {e}")
        finally:
            server_socket.close()
            print("🔚 Server stopped")
    
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
                print("[Server] ❌ Invalid login packet - missing required fields")
                print(f"[Server] ❌ Authentication failed for user {username or 'unknown'}")
                response = "LOGIN_REJECTED"
                send_with_length(client_socket, response.encode('utf-8'))
                return False
            
            print(f"[Server] 🔐 Authenticating user: {username}")
            print(f"[Server] Version: {version}, Nonce: {client_nonce[:8]}...")
            
            # Check if user exists in database
            if not self.user_manager.user_exists(username):
                print(f"[Server] ❌ Unknown user {username} – connection dropped")
                print(f"[Server] ❌ Authentication failed for user {username}")
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
                    print(f"[Server] ❌ Timestamp validation failed - time difference: {time_diff}s")
                    print(f"[Server] ❌ Authentication failed for user {username}")
                    response = "LOGIN_REJECTED"
                    send_with_length(client_socket, response.encode('utf-8'))
                    return False
                    
                print(f"[Server] ✅ Timestamp valid (diff: {time_diff:.1f}s)")
            except Exception as e:
                print(f"[Server] ❌ Timestamp parsing error: {e}")
                print(f"[Server] ❌ Authentication failed for user {username}")
                response = "LOGIN_REJECTED"
                send_with_length(client_socket, response.encode('utf-8'))
                return False
            
            # Check nonce replay protection
            if client_nonce in self.used_nonces:
                print(f"[Server] ❌ Nonce replay detected: {client_nonce[:8]}...")
                print(f"[Server] ❌ Authentication failed for user {username}")
                response = "LOGIN_REJECTED"
                send_with_length(client_socket, response.encode('utf-8'))
                return False
            
            # Store nonce to prevent reuse
            self.used_nonces.add(client_nonce)
            print(f"[Server] ✅ Nonce accepted and stored")
            
            # Authentication successful
            print(f"[Server] ✅ User {username} authenticated from {client_address[0]}")
            self.authenticated_username = username
            response = "LOGIN_ACCEPTED"
            send_with_length(client_socket, response.encode('utf-8'))
            return True
                
        except socket.timeout:
            print("[Server] ❌ Login packet timeout")
            return False
        except Exception as e:
            print(f"[Server] ❌ Login error: {e}")
            return False
    
    def generate_session_id(self):
        """Generate a random 128-bit session ID in hex format"""
        return secrets.token_hex(16)  # 16 bytes = 128 bits
    
    def create_session(self, client_address):
        """Create a new session for the authenticated user"""
        session_id = self.generate_session_id()
        session_data = {
            "username": self.authenticated_username,
            "ip": client_address[0],
            "start_time": datetime.now(timezone.utc).isoformat(),
            "packets_processed": 0,
            "dummy_dropped": 0
        }
        
        self.sessions[session_id] = session_data
        self.current_session_id = session_id
        
        print(f"[KyberLink] ✅ Session {session_id} started for user {self.authenticated_username}")
        return session_id
    
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
    
    def cleanup_session(self, session_id):
        """Remove session and log summary"""
        if session_id in self.sessions:
            session_data = self.sessions[session_id]
            username = session_data["username"]
            packets_processed = session_data["packets_processed"]
            dummy_dropped = session_data["dummy_dropped"]
            
            print(f"[KyberLink] 🔚 Session {session_id} for user {username} ended – {packets_processed} packets, {dummy_dropped} dummies dropped")
            del self.sessions[session_id]
    
    def inject_packet_to_tun(self, packet_data):
        """Inject decrypted packet into TUN interface"""
        if self.tun_fd and self.tun_interface:
            try:
                success = self.tun_interface.write_packet(self.tun_fd, packet_data)
                if success:
                    print(f"[Server][Session {self.current_session_id}] Injecting packet into tun0")
                else:
                    print(f"[Server][Session {self.current_session_id}] Failed to inject packet into tun0")
            except Exception as e:
                print(f"[Server][Session {self.current_session_id}] TUN injection error: {e}")
        else:
            # Simulation mode for Replit
            print(f"[Server][Session {self.current_session_id}] SIMULATED: Injecting packet into tun0")
            print(f"[Server] Packet size: {len(packet_data)} bytes, preview: {packet_data[:16].hex()}...")
    
    def handle_client(self, client_socket):
        """Handle a client connection with login verification and handshake"""
        client_address = client_socket.getpeername()
        
        # Step 1: Receive and verify login packet
        if not self.handle_login(client_socket, client_address):
            return  # Login failed, connection will be closed
        
        print("\n🤝 Starting handshake process...")
        
        # Step 2: Send server public keys to client
        print("[Server] Sending public keys to client...")
        server_public_keys = self.crypto.get_public_keys_bytes()
        send_with_length(client_socket, server_public_keys)
        print(f"[Server] Sent {len(server_public_keys)} bytes of public key data")
        
        # Step 3: Receive client public keys
        print("[Server] Receiving client public keys...")
        client_public_keys = recv_with_length(client_socket)
        print(f"[Server] Received {len(client_public_keys)} bytes of public key data")
        
        # Step 4: Receive Kyber ciphertext from client
        print("[Server] Receiving Kyber ciphertext...")
        kyber_ciphertext = recv_with_length(client_socket)
        print(f"[Server] Received {len(kyber_ciphertext)} bytes of Kyber ciphertext")
        
        # Step 5: Complete key exchange
        print("[Server] Completing hybrid key exchange...")
        self.crypto.server_key_exchange(kyber_ciphertext, client_public_keys)
        
        print("\n✅ Handshake completed successfully!")
        print("🔒 Ready to receive encrypted packets...")
        
        # Step 6: Create session and send session ID to client
        session_id = self.create_session(client_address)
        self.send_session_id(client_socket, session_id)
        
        # Step 7: Handle encrypted packet communication
        self.handle_encrypted_communication(client_socket, client_address)
    
    def handle_encrypted_communication(self, client_socket, client_address):
        """Receive and decrypt packets from client with dummy packet detection"""
        packet_count = 0
        real_packet_count = 0
        dummy_packet_count = 0
        
        print(f"\n📦 KYBERLINK ENCRYPTED TUNNEL - USER: {self.authenticated_username}")
        print("=" * 70)
        
        try:
            while True:
                # Receive encrypted packet
                print(f"\n[Server] User {self.authenticated_username} - waiting for packet #{packet_count + 1}...")
                
                try:
                    encrypted_packet = recv_with_length(client_socket)
                    packet_count += 1
                    
                    print(f"[Server] User {self.authenticated_username} received packet #{packet_count} ({len(encrypted_packet)} bytes)")
                    
                    try:
                        # Decrypt the packet with metadata resistance
                        decrypted_result = self.crypto.decrypt_packet(encrypted_packet)
                        
                        if not decrypted_result:
                            print(f"[Server] User {self.authenticated_username} - ❌ Failed to decrypt packet #{packet_count}")
                            continue
                    except Exception as decrypt_error:
                        print(f"[Server] User {self.authenticated_username} - ❌ Decryption error for packet #{packet_count}: {decrypt_error}")
                        continue
                    
                    packet_type = decrypted_result.get("type")
                    packet_data = decrypted_result.get("data")
                    
                    if packet_type == "dummy":
                        # Handle dummy packet - discard silently
                        dummy_packet_count += 1
                        if self.current_session_id in self.sessions:
                            self.sessions[self.current_session_id]["dummy_dropped"] += 1
                        print(f"[Server][Session {self.current_session_id}] User {self.authenticated_username} - 🗑️  Dropped dummy packet #{dummy_packet_count}")
                        print(f"[Server] DEBUG: Dummy data length: {len(packet_data)} bytes")
                        # No acknowledgment for dummy packets
                        
                    elif packet_type == "replay":
                        # Handle replay packet - log and discard
                        print(f"[Server][Session {self.current_session_id}] User {self.authenticated_username} - ⚠️  Replay detected, dropping packet")
                        # No acknowledgment for replay packets
                        
                    elif packet_type == "real":
                        # Handle real packet
                        real_packet_count += 1
                        sequence_number = decrypted_result.get("sequence", 0)
                        
                        # Increment packets processed for this session
                        if self.current_session_id in self.sessions:
                            self.sessions[self.current_session_id]["packets_processed"] += 1
                        
                        if isinstance(packet_data, str):
                            # Check if this is a base64-encoded packet from TUN
                            try:
                                import base64
                                decoded_packet = base64.b64decode(packet_data)
                                print(f"[Server][Session {self.current_session_id}] User {self.authenticated_username} decrypted TUN packet #{real_packet_count}: {len(decoded_packet)} bytes")
                                print(f"[Server]   Hex preview: {decoded_packet[:32].hex()}...")
                                
                                # Inject decoded packet into TUN interface
                                self.inject_packet_to_tun(decoded_packet)
                                data_type = "tun_packet"
                                
                            except Exception:
                                # Not base64, treat as regular text message
                                print(f"[Server][Session {self.current_session_id}] User {self.authenticated_username} decrypted packet #{real_packet_count}: '{packet_data}'")
                                data_type = "text"
                            
                            # Handle IP check request
                            if packet_data == "IP_CHECK_REQUEST":
                                print(f"[Server] 📡 IP check request received")
                                ip_response = "10.0.0.1"
                                ip_packet = self.crypto.encrypt_packet(ip_response, is_dummy=False)
                                send_with_length(client_socket, ip_packet)
                                print(f"[Server] Sent IP response: {ip_response}")
                                continue
                                
                        else:
                            print(f"[Server][Session {self.current_session_id}] User {self.authenticated_username} decrypted packet #{real_packet_count}: Binary data ({len(packet_data)} bytes)")
                            print(f"[Server]   Hex preview: {packet_data[:32].hex()}...")
                            
                            # Inject binary packet into TUN interface (this is real network traffic)
                            self.inject_packet_to_tun(packet_data)
                            data_type = "binary"
                        
                        # Send acknowledgment back only for real packets
                        ack_message = f"ACK: Received {data_type} packet #{sequence_number}"
                        ack_packet = self.crypto.encrypt_packet(ack_message, is_dummy=False)
                        send_with_length(client_socket, ack_packet)
                        print(f"[Server][Session {self.current_session_id}] User {self.authenticated_username} - 📤 Sent acknowledgment for packet #{sequence_number}")
                        
                    else:
                        print(f"[Server][Session {self.current_session_id}] User {self.authenticated_username} - ⚠️  Unknown packet type: {packet_type}")
                    
                except socket.timeout:
                    print("[Server] No data received (timeout)")
                    break
                except ConnectionError as e:
                    print(f"[Server] Connection error: {e}")
                    break
                    
        except KeyboardInterrupt:
            print("\n[Server] Communication interrupted by user")
        
        # Clean up session
        if self.current_session_id:
            self.cleanup_session(self.current_session_id)
        else:
            print(f"\n[Server] 🔚 Session ended for user {self.authenticated_username}")
            print(f"[Server] Session Summary:")
            print(f"[Server]   User: {self.authenticated_username}")
            print(f"[Server]   Client IP: {client_address[0]}")
            print(f"[Server]   Total packets received: {packet_count}")
            print(f"[Server]   Real packets processed: {real_packet_count}")
            print(f"[Server]   Dummy packets dropped: {dummy_packet_count}")


def main():
    server = VPNServer()
    server.start_server()


if __name__ == "__main__":
    main()