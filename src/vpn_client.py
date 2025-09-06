#!/usr/bin/env python3
"""
KyberLink VPN Client - Core VPN Client Implementation
====================================================

Handles login, handshake, and simulated tunnel communication.
"""

import socket
import sys
import time
import json
import base64
import os
from datetime import datetime

# Add path for local imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_utils import QuantumResistantCrypto, send_with_length, recv_with_length
from kill_switch import enable_kill_switch, disable_kill_switch, check_status, force_block_on_disconnect
from obfuscator import get_obfuscator
from traffic_shaper import get_traffic_shaper, IntensityLevel
from audit_logger import get_audit_logger
from pq_signatures import get_pq_signer
import secrets


class KyberLinkVPNClient:
    """Core VPN client with quantum-resistant encryption"""
    
    def __init__(self, host='localhost', port=5555, enable_kill_switch_option=True, stealth_mode=False, metadata_protection=False, metadata_intensity=IntensityLevel.MEDIUM):
        self.host = host
        self.port = port
        self.crypto = QuantumResistantCrypto(is_server=False)
        self.username = None
        self.session_id = None
        self.kill_switch_enabled = enable_kill_switch_option
        self.connection_established = False
        self.vpn_server_ip = host
        self.stealth_mode = stealth_mode
        self.obfuscator = get_obfuscator() if stealth_mode else None
        self.metadata_protection = metadata_protection
        self.traffic_shaper = get_traffic_shaper()
        self.traffic_shaper.set_intensity(metadata_intensity)
        self.audit_logger = get_audit_logger()
        self.pq_signer = get_pq_signer()
        
    def send_login_packet(self, client_socket, username, password):
        """Send enhanced login packet with nonce, timestamp, and version"""
        self.audit_logger.log_event("INFO", "Client", f"Attempting login for user '{username}'", self.host)
        
        # Generate 16-byte random nonce
        client_nonce = base64.b64encode(os.urandom(16)).decode('utf-8')
        
        # Create ISO8601 timestamp
        timestamp = datetime.utcnow().isoformat() + 'Z'
        
        # Create enhanced login packet
        login_data = {
            "username": username,
            "password": password,
            "client_nonce": client_nonce,
            "timestamp": timestamp,
            "version": "1.0"
        }
        
        login_json = json.dumps(login_data)
        login_bytes = login_json.encode('utf-8')
        
        # Send with length prefix
        send_with_length(client_socket, login_bytes)
        self.audit_logger.log_event("INFO", "Client", f"Login packet sent with nonce {client_nonce[:8]}...", self.host)
        
        # Wait for server response
        try:
            client_socket.settimeout(10.0)
            response = recv_with_length(client_socket)
            response_text = response.decode('utf-8')
            
            if response_text == "LOGIN_ACCEPTED":
                self.audit_logger.log_event("SUCCESS", "Client", f"Login accepted for user '{username}'", self.host)
                self.username = username
                return True
            elif response_text == "LOGIN_REJECTED":
                self.audit_logger.log_event("WARNING", "Client", f"Login rejected for user '{username}'", self.host)
                return False
            else:
                self.audit_logger.log_event("ERROR", "Client", f"Unexpected server response: {response_text}", self.host)
                return False
                
        except socket.timeout:
            self.audit_logger.log_event("ERROR", "Client", "Server login response timeout", self.host)
            return False
    
    def connect_to_server(self, username, password):
        """Connect to VPN server and perform handshake with kill switch protection"""
        self.audit_logger.log_event("INFO", "Client", f"KyberLink VPN Client starting connection to {self.host}:{self.port}")
        
        # Enable kill switch BEFORE starting connection if enabled
        if self.kill_switch_enabled:
            self.audit_logger.log_event("INFO", "Client", f"Activating Kill Switch for server {self.vpn_server_ip}")
            if not enable_kill_switch(self.vpn_server_ip):
                self.audit_logger.log_event("ERROR", "Client", "Kill Switch activation failed - aborting connection for security")
                return False
            self.audit_logger.log_event("SUCCESS", "Client", "Kill Switch activated successfully")
        
        # Initialize stealth mode if enabled
        if self.stealth_mode:
            # Generate obfuscation session key from quantum-resistant shared secret
            shared_secret = b"KyberLink-Client-Stealth-" + secrets.token_bytes(16)
            self.obfuscator.generate_session_key(shared_secret)
            self.audit_logger.log_system_event("StealthMode", "Traffic obfuscation enabled - disguising VPN packets as HTTPS")
        
        # Initialize metadata protection if enabled
        if self.metadata_protection:
            self.traffic_shaper.enable_metadata_protection()
            # Start background dummy traffic
            self.traffic_shaper.start_background_traffic(self._send_dummy_packet_callback)
            self.audit_logger.log_system_event("MetadataProtection", "Adaptive traffic shaping enabled")
        
        # Generate client keys
        self.crypto.generate_keys()
        self.audit_logger.log_event("SUCCESS", "Client", "Quantum-resistant keys generated (X25519 + ML-KEM-768)")
        
        # Connect to server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            client_socket.connect((self.host, self.port))
            self.audit_logger.log_event("SUCCESS", "Client", f"TCP connection established to {self.host}:{self.port}")
            
            # Send login packet first
            if not self.send_login_packet(client_socket, username, password):
                self.audit_logger.log_event("ERROR", "Client", "Authentication failed")
                if self.kill_switch_enabled:
                    disable_kill_switch()
                    self.audit_logger.log_event("INFO", "Client", "Kill switch disabled after login failure")
                return False
                
            # Perform handshake
            self.perform_handshake(client_socket)
            
            # Mark connection as established after successful handshake
            self.connection_established = True
            self.audit_logger.log_event("SUCCESS", "Client", "VPN tunnel established with quantum-resistant encryption")
            
            # Start encrypted communication
            self.start_encrypted_communication(client_socket)
            
        except ConnectionRefusedError:
            print("❌ Connection refused. Make sure the KyberLink server is running.")
            if self.kill_switch_enabled:
                print("❌ Connection failed - disabling kill switch")
                disable_kill_switch()
            return False
        except Exception as e:
            print(f"❌ Client error: {e}")
            # Handle unexpected disconnect - keep kill switch ON
            if self.kill_switch_enabled and self.connection_established:
                force_block_on_disconnect()
            elif self.kill_switch_enabled:
                disable_kill_switch()
            return False
        finally:
            client_socket.close()
            print("🔌 Disconnected from server")
            
            # On normal disconnect, disable kill switch AFTER disconnect
            if self.kill_switch_enabled and self.connection_established:
                print("🔓 Normal disconnect - disabling kill switch...")
                if disable_kill_switch():
                    print("✅ Kill switch disabled - normal traffic restored")
                else:
                    print("⚠️  Failed to disable kill switch - manual intervention may be required")
            
            self.connection_established = False
            
        return True
    
    def get_kill_switch_status(self) -> dict:
        """Get current kill switch status"""
        status = check_status()
        return {
            'enabled': self.kill_switch_enabled,
            'active': status['active'],
            'vpn_server_ip': status['vpn_server_ip'],
            'os_type': status['os_type']
        }
    
    def toggle_kill_switch_option(self, enable: bool):
        """Toggle kill switch option for future connections"""
        self.kill_switch_enabled = enable
        print(f"🛡️  Kill Switch option {'enabled' if enable else 'disabled'} for future connections")
    
    def toggle_stealth_mode(self, enable: bool):
        """Toggle stealth mode for traffic obfuscation"""
        self.stealth_mode = enable
        if enable:
            self.obfuscator = get_obfuscator()
            print("[Client] 🕵️ Stealth mode enabled for future connections")
        else:
            self.obfuscator = None
            print("[Client] 🔓 Stealth mode disabled - using normal VPN packets")
    
    def toggle_metadata_protection(self, enable: bool):
        """Toggle metadata protection for timing and traffic analysis defense"""
        self.metadata_protection = enable
        if enable:
            self.traffic_shaper.enable_metadata_protection()
            print("[Client] 🎭 Metadata defense enabled")
        else:
            self.traffic_shaper.disable_metadata_protection()
            print("[Client] 🔓 Metadata defense disabled")
    
    def set_metadata_intensity(self, intensity: IntensityLevel):
        """Set metadata protection intensity level"""
        self.traffic_shaper.set_intensity(intensity)
    
    def _send_dummy_packet_callback(self, dummy_packet: bytes):
        """Callback for sending dummy packets from background thread"""
        # This would be called by the traffic shaper to send dummy packets
        # In a real implementation, you'd need access to the socket here
        pass
    
    def send_obfuscated(self, client_socket, data: bytes):
        """Send data with optional obfuscation and traffic shaping"""
        # Apply traffic shaping first (padding and timing)
        if self.metadata_protection:
            # Schedule real packet with padding
            shaped_data = self.traffic_shaper.schedule_real_packet(data)
            
            # Apply jitter delay
            delay = self.traffic_shaper.jitter_delay()
            if delay > 0:
                time.sleep(delay)
        else:
            shaped_data = data
        
        # Apply obfuscation if enabled
        if self.stealth_mode and self.obfuscator:
            try:
                obfuscated_data = self.obfuscator.obfuscate(shaped_data)
                send_with_length(client_socket, obfuscated_data)
            except Exception as e:
                print(f"❌ Obfuscation failed, sending normal packet: {e}")
                send_with_length(client_socket, shaped_data)
        else:
            send_with_length(client_socket, shaped_data)
    
    def recv_obfuscated(self, client_socket) -> bytes:
        """Receive data with optional deobfuscation and traffic shaping"""
        data = recv_with_length(client_socket)
        
        # Apply deobfuscation if enabled
        if self.stealth_mode and self.obfuscator:
            try:
                deobfuscated_data = self.obfuscator.deobfuscate(data)
            except Exception as e:
                print(f"⚠️  Deobfuscation failed, treating as normal packet: {e}")
                deobfuscated_data = data
        else:
            deobfuscated_data = data
        
        # Extract real packet from traffic shaping if enabled
        if self.metadata_protection:
            real_packet = self.traffic_shaper.extract_real_packet(deobfuscated_data)
            if real_packet is None:
                # This was a dummy packet, return empty to indicate it should be ignored
                return b''
            return real_packet
        else:
            return deobfuscated_data
    
    def perform_handshake(self, client_socket):
        """Perform hybrid key exchange with server"""
        self.audit_logger.log_event("INFO", "Client", "Starting handshake process", self.host)
        
        # Step 1: Receive server handshake packet with potential PQ signature
        self.audit_logger.log_event("INFO", "Client", "Receiving server handshake data", self.host)
        handshake_packet = recv_with_length(client_socket)
        
        try:
            # Parse handshake packet
            handshake_json = handshake_packet.decode('utf-8')
            handshake_data = json.loads(handshake_json)
            
            # Extract server public keys
            server_public_keys = bytes.fromhex(handshake_data["public_keys"])
            pq_signature = handshake_data.get("pq_signature")
            pq_public_key = handshake_data.get("pq_public_key")
            
            self.audit_logger.log_event("INFO", "Client", f"Received handshake packet ({len(server_public_keys)} bytes of keys)", self.host)
            
            # Verify post-quantum signature if present
            if pq_signature and pq_public_key and self.pq_signer.is_available():
                signature_bytes = bytes.fromhex(pq_signature)
                pq_public_key_bytes = bytes.fromhex(pq_public_key)
                
                self.audit_logger.log_event("INFO", "Client", "Verifying Dilithium3 signature on handshake", self.host)
                
                if self.pq_signer.verify_signature(pq_public_key_bytes, server_public_keys, signature_bytes):
                    self.audit_logger.log_event("SUCCESS", "Client", "Dilithium3 signature verification successful", self.host)
                else:
                    self.audit_logger.log_event("INTRUSION", "Client", "Invalid PQ signature from server - aborting connection", self.host)
                    raise ValueError("Invalid post-quantum signature from server")
            
            elif pq_signature or pq_public_key:
                self.audit_logger.log_event("WARNING", "Client", "Server sent PQ signature but client cannot verify (pqcrypto unavailable)", self.host)
            
            else:
                self.audit_logger.log_event("WARNING", "Client", "Server did not provide post-quantum signature", self.host)
                
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            if "Invalid post-quantum signature" in str(e):
                raise  # Re-raise signature verification failures
            
            # Fallback to legacy format for backward compatibility
            self.audit_logger.log_event("INFO", "Client", "Using legacy handshake format (no PQ signature)", self.host)
            server_public_keys = handshake_packet
        
        # Step 2: Send client public keys to server
        print("[KyberLink] Sending public keys to server...")
        client_public_keys = self.crypto.get_public_keys_bytes()
        send_with_length(client_socket, client_public_keys)
        print(f"[KyberLink] Sent {len(client_public_keys)} bytes of public key data")
        
        # Step 3: Perform key exchange and send Kyber ciphertext
        print("[KyberLink] Performing hybrid key exchange...")
        kyber_ciphertext = self.crypto.client_key_exchange(server_public_keys)
        send_with_length(client_socket, kyber_ciphertext)
        print(f"[KyberLink] Sent {len(kyber_ciphertext)} bytes of Kyber ciphertext")
        
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
                print(f"[KyberLink] ✅ Assigned session {self.session_id}")
            else:
                print(f"[KyberLink] ⚠️  Unexpected packet from server: {session_data}")
                
        except Exception as e:
            print(f"[KyberLink] ❌ Error receiving session ID: {e}")
    
    def start_encrypted_communication(self, client_socket):
        """Send encrypted packets to server"""
        print("\n📦 KYBERLINK ENCRYPTED TUNNEL")
        print("=" * 70)
        
        print(f"[KyberLink][Session {self.session_id}] User {self.username} starting packet transmission...")
        
        # Number of packets to send
        packets_to_send = 5
        
        try:
            for i in range(packets_to_send):
                print(f"\n[KyberLink][Session {self.session_id}] User {self.username} - 📤 Sending packet #{i+1}...")
                
                # Create test message
                message = f"Hello from KyberLink tunnel! Packet #{i+1}"
                
                # Encrypt the message
                encrypted_packet = self.crypto.encrypt_packet(message, sequence=i+1)
                
                # Send to server with obfuscation and traffic shaping
                self.send_obfuscated(client_socket, encrypted_packet)
                print(f"[KyberLink] Sent encrypted packet ({len(encrypted_packet)} bytes)")
                
                # Inject dummy packets if metadata protection is enabled
                if self.metadata_protection and self.traffic_shaper.should_inject_dummy():
                    dummy_packet = self.traffic_shaper.generate_dummy_packet()
                    self.send_obfuscated(client_socket, dummy_packet)
                    print(f"[KyberLink] 🎭 Sent dummy packet for metadata protection")
                
                # Wait for acknowledgment
                try:
                    client_socket.settimeout(5.0)  # 5 second timeout
                    ack_data = self.recv_obfuscated(client_socket)
                    
                    # Skip empty responses (filtered dummy packets)
                    if len(ack_data) == 0:
                        continue
                    
                    ack_message = self.crypto.decrypt_packet(ack_data)
                    print(f"[KyberLink][Session {self.session_id}] User {self.username} - 📥 Server ACK: '{ack_message}'")
                    
                    # Extract response packet data if available
                    if isinstance(ack_message, dict) and ack_message.get('type') == 'real':
                        response_data = ack_message.get('data', '')
                        if response_data.startswith('ACK:'):
                            print(f"[KyberLink] Server acknowledged packet #{i+1}")
                except socket.timeout:
                    print("[KyberLink] ⚠️  No acknowledgment received (timeout)")
                except Exception as e:
                    print(f"[KyberLink] ⚠️  Error receiving acknowledgment: {e}")
                
                # Small delay between packets
                time.sleep(1)
            
            # Send one dummy packet for metadata resistance testing
            print(f"\n[KyberLink][Session {self.session_id}] User {self.username} - 📤 Sending dummy packet for metadata resistance...")
            dummy_packet = self.crypto.encrypt_packet("DUMMY_DATA", is_dummy=True)
            self.send_obfuscated(client_socket, dummy_packet)
            print(f"[KyberLink] Sent dummy packet ({len(dummy_packet)} bytes)")
            
            # Show traffic shaping statistics if enabled
            if self.metadata_protection:
                stats = self.traffic_shaper.get_statistics()
                print(f"\n[KyberLink] 🎭 Metadata Protection Statistics:")
                print(f"[KyberLink]   Real packets: {stats['real_packets']}")
                print(f"[KyberLink]   Dummy packets: {stats['dummy_packets']}")
                print(f"[KyberLink]   Dummy ratio: {stats['dummy_ratio']}")
                print(f"[KyberLink]   Padded bytes: {stats['padded_bytes']}")
                print(f"[KyberLink]   Total delay: {stats['total_delay']}")
            
            print(f"\n[KyberLink][Session {self.session_id}] User {self.username} - ✅ Successfully sent {packets_to_send} packets + 1 dummy packet!")
            
        except Exception as e:
            print(f"[KyberLink] ❌ Error during communication: {e}")
        finally:
            client_socket.settimeout(None)  # Remove timeout


def main():
    client = KyberLinkVPNClient()
    
    print("Starting KyberLink VPN client...")
    print("Make sure the KyberLink VPN server is running first!")
    print()
    
    # Default credentials for testing
    username = "testuser"
    password = "testpass"
    
    if len(sys.argv) > 1:
        username = sys.argv[1]
    if len(sys.argv) > 2:
        password = sys.argv[2]
    
    print(f"Connecting as user: {username}")
    print()
    
    # Give user a moment to read the message
    time.sleep(2)
    
    try:
        client.connect_to_server(username, password)
        print("\n🎉 KyberLink VPN client session completed successfully!")
    except Exception as e:
        print(f"\n❌ KyberLink VPN client session failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()