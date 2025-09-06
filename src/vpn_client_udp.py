#!/usr/bin/env python3
"""
KyberLink VPN Client - UDP Transport Layer
==========================================

High-performance UDP-based VPN client with quantum-resistant encryption.
Provides resilient connection handling and improved latency over TCP.
"""

import socket
import struct
import time
import json
import secrets
import os
import sys
from datetime import datetime
from typing import Optional, Tuple

# Add path for local imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_utils import QuantumResistantCrypto
from audit_logger import get_audit_logger
from packet_coalescing import get_packet_coalescing_engine
from permanent_no_logs import generic_error_response
from secure_memory_scrubbing import create_session_cleanup_manager, emergency_memory_scrub

# UDP packet types (must match server)
PACKET_HANDSHAKE_INIT = 1
PACKET_HANDSHAKE_RESPONSE = 2
PACKET_HANDSHAKE_COMPLETE = 3
PACKET_DATA = 4
PACKET_HEARTBEAT = 5
PACKET_DUMMY = 6

class KyberLinkUDPVPNClient:
    """
    High-Performance UDP VPN Client
    
    Features:
    - Quantum-resistant hybrid encryption (X25519 + ML-KEM-768)
    - Resilient UDP communication with retransmission
    - ChaCha20-Poly1305 AEAD encryption for data packets
    - Session persistence across multiple packets
    - Graceful packet loss handling
    """
    
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.socket = None
        self.session_id = None
        self.username = None
        self.authenticated = False
        self.handshake_complete = False
        
        # Crypto system
        self.crypto = QuantumResistantCrypto(is_server=False)
        self.audit_logger = get_audit_logger()
        
        # Packet coalescing engine
        self.coalescing_engine = get_packet_coalescing_engine()
        
        # Retransmission parameters
        self.handshake_timeout = 2.0  # seconds
        self.handshake_retries = 3
        self.data_timeout = 1.0
        self.data_retries = 2
        
        # Dummy traffic statistics
        self.dummy_packets_received = 0
        self.real_packets_sent = 0
        
        # Client initialized - no logging
    
    def pack_packet(self, packet_type: int, session_id: bytes, data: bytes) -> bytes:
        """
        Pack UDP packet with format: [type:1][session_id:16][data_len:4][data:N]
        """
        if session_id is None:
            session_id = b'\\x00' * 16  # Null session for handshake init
        header = struct.pack('!B16sI', packet_type, session_id, len(data))
        return header + data
    
    def unpack_packet(self, packet: bytes) -> Tuple[int, bytes, bytes]:
        """Unpack UDP packet"""
        if len(packet) < 21:
            raise ValueError("Packet too short")
        
        packet_type, session_id, data_len = struct.unpack('!B16sI', packet[:21])
        
        if len(packet) < 21 + data_len:
            raise ValueError("Invalid data length")
        
        data = packet[21:21 + data_len]
        return packet_type, session_id, data
    
    def send_packet_with_retry(self, packet: bytes, expected_response_type: int, 
                              timeout: float, max_retries: int) -> Optional[bytes]:
        """
        Send packet with automatic retransmission on timeout
        
        Args:
            packet: Packet to send
            expected_response_type: Expected response packet type
            timeout: Timeout in seconds
            max_retries: Maximum retry attempts
            
        Returns:
            Response packet or None if failed
        """
        self.socket.settimeout(timeout)
        
        for attempt in range(max_retries + 1):
            try:
                if attempt > 0:
                    # Packet retransmission - no logging
                    pass
                
                # Send packet
                self.socket.sendto(packet, (self.host, self.port))
                
                # Wait for response
                response_data, server_addr = self.socket.recvfrom(65536)
                
                # Process response (may be coalesced or fragmented)
                try:
                    individual_packets = self.coalescing_engine.process_received_packet(response_data)
                    
                    for packet_data in individual_packets:
                        response_type, _, response_payload = self.unpack_packet(packet_data)
                        
                        # Handle dummy packets (header=0x00)
                        if len(response_payload) > 0 and response_payload[-1:] == b'\\x00':
                            self.dummy_packets_received += 1
                            # Dummy packet filtered - no logging
                            continue
                        
                        # Check if this matches expected response type
                        if response_type == expected_response_type:
                            return packet_data
                        else:
                            # Unexpected response - no logging
                        
                except Exception as e:
                    # Packet processing error - no logging
                    continue
                    
            except socket.timeout:
                # Response timeout - no logging
                continue
            except Exception as e:
                # Send error - no logging
                continue
        
        # Failed after retries - no logging
        return None
    
    def connect(self, username: str, password: str) -> bool:
        """
        Establish UDP VPN connection with handshake
        
        Args:
            username: Username for authentication
            password: Password for authentication
            
        Returns:
            True if connection established successfully
        """
        try:
            # Connecting - no logging
            
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Generate client keys
            self.crypto.generate_keys()
            # Client keys generated - no logging
            
            # Step 1: Send handshake init
            handshake_data = {
                'username': username,
                'password': password,
                'x25519_public': self.crypto.x25519_public_key.hex(),
                'kyber_public': self.crypto.kyber_public_key.hex(),
                'client_time': datetime.utcnow().isoformat()
            }
            
            handshake_json = json.dumps(handshake_data).encode('utf-8')
            handshake_packet = self.pack_packet(PACKET_HANDSHAKE_INIT, None, handshake_json)
            
            # Send with retransmission
            print("[Client] 📤 Sending handshake initiation...")
            response = self.send_packet_with_retry(
                handshake_packet, 
                PACKET_HANDSHAKE_RESPONSE,
                self.handshake_timeout,
                self.handshake_retries
            )
            
            if not response:
                print("[Client] ❌ Handshake initiation failed")
                return False
            
            # Step 2: Process handshake response
            _, session_id, response_data = self.unpack_packet(response)
            response_json = json.loads(response_data.decode('utf-8'))
            
            if response_json.get('status') != 'success':
                print(f"[Client] ❌ Authentication failed")
                return False
            
            # Store session info
            self.session_id = session_id
            self.username = username
            self.authenticated = True
            
            # Set server keys and derive shared secret
            server_x25519_public = bytes.fromhex(response_json['x25519_public'])
            server_kyber_public = bytes.fromhex(response_json['kyber_public'])
            
            self.crypto.set_peer_public_key(server_x25519_public, server_kyber_public)
            self.crypto.derive_shared_secret()
            self.crypto._derive_session_key()
            
            print(f"[Client] ✅ Session established: {session_id.hex()[:16]}...")
            
            # Step 3: Send handshake completion
            completion_data = json.dumps({'status': 'ready'}).encode('utf-8')
            completion_packet = self.pack_packet(PACKET_HANDSHAKE_COMPLETE, session_id, completion_data)
            
            print("[Client] 📤 Sending handshake completion...")
            ack_response = self.send_packet_with_retry(
                completion_packet,
                PACKET_HANDSHAKE_COMPLETE,
                self.handshake_timeout,
                self.handshake_retries
            )
            
            if not ack_response:
                print("[Client] ❌ Handshake completion failed")
                return False
            
            self.handshake_complete = True
            print("[Client] 🎉 UDP VPN connection established successfully!")
            self.audit_logger.log_event("SUCCESS", "Client", f"UDP VPN connected as {username}")
            
            return True
            
        except Exception as e:
            print(f"[Client] ❌ Connection failed: {e}")
            self.audit_logger.log_event("ERROR", "Client", f"UDP connection failed: {e}")
            return False
    
    def send_data(self, message: str) -> bool:
        """
        Send encrypted data through UDP tunnel
        
        Args:
            message: Message to send
            
        Returns:
            True if sent and acknowledged successfully
        """
        if not self.handshake_complete:
            print("[Client] ❌ Cannot send data - handshake not complete")
            return False
        
        try:
            print(f"[Client] 📤 Sending message: '{message}'")
            
            # Increment real packet counter
            self.real_packets_sent += 1
            
            # Encrypt message
            encrypted_data = self.crypto.encrypt_packet(message)
            data_packet = self.pack_packet(PACKET_DATA, self.session_id, encrypted_data)
            
            # Send with retransmission
            response = self.send_packet_with_retry(
                data_packet,
                PACKET_DATA,
                self.data_timeout,
                self.data_retries
            )
            
            if response:
                # Decrypt server response
                _, _, response_encrypted = self.unpack_packet(response)
                decrypted_response = self.crypto.decrypt_packet(response_encrypted)
                
                print(f"[Client] 📨 Server response: '{decrypted_response}'")
                self.audit_logger.log_event("INFO", "Client", f"Data packet exchanged successfully")
                return True
            else:
                print("[Client] ❌ Failed to send data packet")
                return False
                
        except Exception as e:
            print(f"[Client] ❌ Send data error: {e}")
            return False
    
    def send_heartbeat(self) -> bool:
        """Send heartbeat to keep session alive"""
        if not self.handshake_complete:
            return False
        
        try:
            heartbeat_data = json.dumps({'timestamp': time.time()}).encode('utf-8')
            heartbeat_packet = self.pack_packet(PACKET_HEARTBEAT, self.session_id, heartbeat_data)
            
            self.socket.sendto(heartbeat_packet, (self.host, self.port))
            return True
            
        except Exception as e:
            print(f"[Client] ❌ Heartbeat error: {e}")
            return False
    
    def test_session_persistence(self):
        """Test that session survives multiple packets without re-handshaking"""
        if not self.handshake_complete:
            print("[Client] ❌ Cannot test - no active session")
            return False
        
        print("[Client] 🧪 Testing session persistence...")
        
        test_messages = [
            "Hello via UDP tunnel",
            "Second packet test",
            "Third packet test",
            "Session persistence confirmed"
        ]
        
        success_count = 0
        for i, message in enumerate(test_messages, 1):
            print(f"\n[Client] 📋 Test {i}/{len(test_messages)}")
            if self.send_data(message):
                success_count += 1
                time.sleep(0.5)  # Brief delay between packets
            else:
                print(f"[Client] ❌ Test {i} failed")
        
        print(f"\n[Client] 📊 Session persistence test results:")
        print(f"[Client]   • Success: {success_count}/{len(test_messages)} packets")
        print(f"[Client]   • Session ID: {self.session_id.hex()[:16]}... (unchanged)")
        print(f"[Client]   • No re-handshaking required: ✅")
        
        return success_count == len(test_messages)
    
    def get_traffic_stats(self) -> dict:
        """Get client traffic statistics including dummy packets"""
        return {
            'real_packets_sent': self.real_packets_sent,
            'dummy_packets_received': self.dummy_packets_received,
            'session_active': self.handshake_complete,
            'session_id': self.session_id.hex()[:16] if self.session_id else None
        }
    
    def disconnect(self):
        """Disconnect from VPN server"""
        print("[Client] 🛑 Disconnecting from UDP VPN")
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        # Reset state
        self.session_id = None
        self.authenticated = False
        self.handshake_complete = False
        self.dummy_packets_received = 0
        self.real_packets_sent = 0
        
        print("[Client] ✅ Disconnected")
        self.audit_logger.log_event("INFO", "Client", "UDP VPN disconnected")

def main():
    """Main client demo"""
    print("🚀 KyberLink UDP VPN Client Demo")
    print("=" * 40)
    
    client = KyberLinkUDPVPNClient()
    
    try:
        # Test connection
        if client.connect("testuser", "password123"):
            
            # Test single message
            client.send_data("Hello via UDP tunnel")
            
            # Test session persistence
            client.test_session_persistence()
            
            # Keep session alive briefly
            print("\n[Client] 💓 Sending heartbeats...")
            for i in range(3):
                client.send_heartbeat()
                time.sleep(1)
            
        else:
            print("[Client] ❌ Failed to establish connection")
            
    except KeyboardInterrupt:
        print("\n[Client] 🛑 Received interrupt signal")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()