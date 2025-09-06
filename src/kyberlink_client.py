#!/usr/bin/env python3
"""
KyberLink - Quantum-Resistant VPN Client

This client performs:
1. Hybrid key exchange (X25519 + Kyber768)
2. Session key derivation with HKDF-SHA3-256
3. ChaCha20-Poly1305 packet encryption
"""

import socket
import sys
import time
import json
import base64
import os
from datetime import datetime
from crypto_utils import QuantumResistantCrypto, send_with_length, recv_with_length

# Add path for TUN interface
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tun_interface import TunInterface


class VPNClient:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.crypto = QuantumResistantCrypto(is_server=False)
        self.username = None
        self.session_id = None
        self.tun_interface = None
        self.tun_fd = None
        
    def send_login_packet(self, client_socket, username):
        """Send enhanced login packet with nonce, timestamp, and version"""
        print(f"[Client] 🔐 Sending login packet for user {username}")
        
        # Generate 16-byte random nonce
        client_nonce = base64.b64encode(os.urandom(16)).decode('utf-8')
        
        # Create ISO8601 timestamp
        timestamp = datetime.utcnow().isoformat() + 'Z'
        
        # Create enhanced login packet
        login_data = {
            "username": username,
            "client_nonce": client_nonce,
            "timestamp": timestamp,
            "version": "1.0"
        }
        
        login_json = json.dumps(login_data)
        login_bytes = login_json.encode('utf-8')
        
        # Send with length prefix
        send_with_length(client_socket, login_bytes)
        print(f"[Client] Login packet sent (nonce: {client_nonce[:8]}...)")
        
        # Wait for server response
        try:
            client_socket.settimeout(10.0)
            response = recv_with_length(client_socket)
            response_text = response.decode('utf-8')
            
            if response_text == "LOGIN_ACCEPTED":
                print("[Client] ✅ Server accepted login")
                self.username = username
                return True
            elif response_text == "LOGIN_REJECTED":
                print("[Client] ❌ Server rejected login")
                return False
            else:
                print(f"[Client] ❌ Unexpected server response: {response_text}")
                return False
                
        except socket.timeout:
            print("[Client] ❌ Server login response timeout")
            return False
    
    def connect_to_server(self, username):
        """Connect to VPN server and perform handshake"""
        print("=" * 70)
        print("🔐 KYBERLINK VPN CLIENT - QUANTUM-RESISTANT TUNNEL")
        print("=" * 70)
        
        # Generate client keys
        print("\n🔐 Generating Client Keys...")
        self.crypto.generate_keys()
        
        # Connect to server
        print(f"\n🌐 Connecting to server at {self.host}:{self.port}...")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            client_socket.connect((self.host, self.port))
            print("✅ Connected to server successfully!")
            
            # Send login packet first
            if not self.send_login_packet(client_socket, username):
                print("[Client] ❌ Authentication failed")
                return
                
            # Perform handshake
            self.perform_handshake(client_socket)
            
            # Start encrypted communication
            self.start_encrypted_communication(client_socket)
            
        except ConnectionRefusedError:
            print("❌ Connection refused. Make sure the server is running.")
            return False
        except Exception as e:
            print(f"❌ Client error: {e}")
            return False
        finally:
            client_socket.close()
            print("🔌 Disconnected from server")
            
        return True
    
    def perform_handshake(self, client_socket):
        """Perform hybrid key exchange with server"""
        print("\n🤝 Starting handshake process...")
        
        # Step 1: Receive server public keys
        print("[Client] Receiving server public keys...")
        server_public_keys = recv_with_length(client_socket)
        print(f"[Client] Received {len(server_public_keys)} bytes of public key data")
        
        # Step 2: Send client public keys to server
        print("[Client] Sending public keys to server...")
        client_public_keys = self.crypto.get_public_keys_bytes()
        send_with_length(client_socket, client_public_keys)
        print(f"[Client] Sent {len(client_public_keys)} bytes of public key data")
        
        # Step 3: Perform key exchange and send Kyber ciphertext
        print("[Client] Performing hybrid key exchange...")
        kyber_ciphertext = self.crypto.client_key_exchange(server_public_keys)
        send_with_length(client_socket, kyber_ciphertext)
        print(f"[Client] Sent {len(kyber_ciphertext)} bytes of Kyber ciphertext")
        
        print("\n✅ Handshake completed successfully!")
        
        # Receive session ID from server
        self.receive_session_id(client_socket)
        
        print("🔒 Ready to send encrypted packets...")
    
    def receive_session_id(self, client_socket):
        """Receive session ID from server after handshake"""
        try:
            client_socket.settimeout(10.0)
            session_packet = recv_with_length(client_socket)
            session_json = session_packet.decode('utf-8')
            session_data = json.loads(session_json)
            
            if session_data.get("type") == "session_id":
                self.session_id = session_data.get("session_id")
                print(f"[Client] ✅ Assigned session {self.session_id}")
            else:
                print(f"[Client] ⚠️  Unexpected packet from server: {session_data}")
                
        except Exception as e:
            print(f"[Client] ❌ Error receiving session ID: {e}")
    
    def start_encrypted_communication(self, client_socket):
        """Send encrypted packets to server"""
        print("\n📦 KYBERLINK ENCRYPTED TUNNEL")
        print("=" * 70)
        
        # Initialize TUN interface for packet reading
        self.tun_interface = TunInterface()
        self.tun_fd = self.tun_interface.open_tun("tun0")
        
        if not self.tun_fd:
            print(f"[Client][Session {self.session_id}] Failed to open TUN interface, using fallback mode")
            
        print(f"[Client][Session {self.session_id}] User {self.username} starting TUN packet transmission...")
        
        # Number of packets to read from TUN and transmit
        packets_to_send = 5
        
        try:
            for i in range(packets_to_send):
                print(f"\n[Client][Session {self.session_id}] User {self.username} - 📤 Reading packet #{i+1} from TUN...")
                
                # Read packet from TUN interface (simulated in Replit)
                if self.tun_fd:
                    raw_packet = self.tun_interface.read_packet(self.tun_fd)
                    print(f"[Client] Read {len(raw_packet)} bytes from TUN interface")
                    print(f"[Client] Packet preview: {raw_packet[:32].hex()}{'...' if len(raw_packet) > 32 else ''}")
                else:
                    # Fallback: generate random packet data
                    raw_packet = os.urandom(64)  # 64-byte random packet
                    print(f"[Client] Generated {len(raw_packet)} bytes fallback packet")
                
                # Encrypt the raw packet (convert bytes to base64 for transmission)
                import base64
                packet_b64 = base64.b64encode(raw_packet).decode('utf-8')
                encrypted_packet = self.crypto.encrypt_packet(packet_b64)
                
                # Send to server
                send_with_length(client_socket, encrypted_packet)
                print(f"[Client] Sent encrypted TUN packet ({len(encrypted_packet)} bytes)")
                
                # Wait for acknowledgment
                try:
                    client_socket.settimeout(5.0)  # 5 second timeout
                    ack_packet = recv_with_length(client_socket)
                    ack_message = self.crypto.decrypt_packet(ack_packet)
                    print(f"[Client][Session {self.session_id}] User {self.username} - 📥 Server ACK: '{ack_message}'")
                    
                    # Extract response packet data if available
                    if isinstance(ack_message, dict) and ack_message.get('type') == 'real':
                        response_data = ack_message.get('data', '')
                        if response_data.startswith('ACK:'):
                            print(f"[Client] Server acknowledged TUN packet #{i+1}")
                except socket.timeout:
                    print("[Client] ⚠️  No acknowledgment received (timeout)")
                except Exception as e:
                    print(f"[Client] ⚠️  Error receiving acknowledgment: {e}")
                
                # Small delay between packets
                time.sleep(1)
            
            # Send one dummy packet for metadata resistance testing
            print(f"\n[Client][Session {self.session_id}] User {self.username} - 📤 Sending dummy packet for metadata resistance...")
            dummy_packet = self.crypto.encrypt_packet("DUMMY_DATA", is_dummy=True)
            send_with_length(client_socket, dummy_packet)
            print(f"[Client] Sent dummy packet ({len(dummy_packet)} bytes)")
            
            print(f"\n[Client][Session {self.session_id}] User {self.username} - ✅ Successfully sent {packets_to_send} TUN packets + 1 dummy packet!")
            
        except Exception as e:
            print(f"[Client] ❌ Error during communication: {e}")
        finally:
            # Clean up TUN interface
            if self.tun_fd and self.tun_interface:
                self.tun_interface.close_tun(self.tun_fd)
                print(f"[Client][Session {self.session_id}] Closed TUN interface")
            client_socket.settimeout(None)  # Remove timeout


def main():
    client = VPNClient()
    
    print("Starting KyberLink VPN client...")
    print("Make sure the KyberLink VPN server is running first!")
    print()
    
    # Default username for testing
    username = "testuser"
    if len(sys.argv) > 1:
        username = sys.argv[1]
    
    print(f"Connecting as user: {username}")
    print()
    
    # Give user a moment to read the message
    time.sleep(2)
    
    try:
        client.connect_to_server(username)
        print("\n🎉 KyberLink VPN client session completed successfully!")
    except Exception as e:
        print(f"\n❌ VPN client session failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()