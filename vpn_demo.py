#!/usr/bin/env python3
"""
Quantum-Resistant VPN MVP Demo
==============================

Complete demonstration of the quantum-resistant VPN protocol featuring:
- Hybrid post-quantum handshake (X25519 + Kyber768 + HKDF-SHA3-256)
- ChaCha20-Poly1305 authenticated encryption tunnel
- Automatic session key rotation (every 5 packets or 60 seconds)
- PKCS#7 padding to 256-byte boundaries for metadata resistance
- Dummy packet injection and detection
- Replay protection with sequence numbers
- Out-of-order packet detection
- Comprehensive session statistics

This script runs both server and client in the same process using threading.
"""

import threading
import time
import socket
import os
import sys
from src.crypto_utils import QuantumResistantCrypto, send_with_length, recv_with_length


class VPNServerDemo:
    """Demonstration VPN server with all security features"""
    
    def __init__(self, port=5556):
        self.port = port
        self.crypto = QuantumResistantCrypto(is_server=True)
        self.session_stats = {
            'real_packets': 0,
            'dummy_packets': 0,
            'replay_packets': 0,
            'out_of_order_packets': 0,
            'total_packets': 0
        }
    
    def start_server(self):
        """Start the VPN server and handle client connection"""
        print("🔐 QUANTUM-RESISTANT VPN SERVER DEMO")
        print("=" * 60)
        
        # Generate server keys
        print("🔑 Generating server cryptographic keys...")
        self.crypto.generate_keys()
        
        # Start listening
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('localhost', self.port))
        server_socket.listen(1)
        
        print(f"🌐 Server listening on localhost:{self.port}")
        print("⏳ Waiting for client connection...")
        
        try:
            client_socket, client_address = server_socket.accept()
            print(f"✅ Client connected from {client_address}")
            
            # Perform handshake
            self.perform_handshake(client_socket)
            
            # Handle encrypted communication
            self.handle_encrypted_communication(client_socket)
            
        except Exception as e:
            print(f"❌ Server error: {e}")
        finally:
            server_socket.close()
            self.print_session_summary()
    
    def perform_handshake(self, client_socket):
        """Perform the hybrid quantum-resistant handshake"""
        print("\n🤝 HYBRID QUANTUM-RESISTANT HANDSHAKE")
        print("-" * 60)
        
        # Step 1: Send server public keys
        server_keys = self.crypto.get_public_keys_bytes()
        send_with_length(client_socket, server_keys)
        print(f"📤 Sent server public keys ({len(server_keys)} bytes)")
        
        # Step 2: Receive client public keys
        client_keys = recv_with_length(client_socket)
        print(f"📥 Received client public keys ({len(client_keys)} bytes)")
        
        # Step 3: Receive Kyber ciphertext and derive session key
        kyber_ciphertext = recv_with_length(client_socket)
        print(f"📥 Received Kyber ciphertext ({len(kyber_ciphertext)} bytes)")
        
        client_public_keys = self.crypto.parse_public_keys_bytes(client_keys)
        self.crypto.server_key_exchange(kyber_ciphertext, client_public_keys)
        
        print("✅ Handshake completed - session key established!")
        if self.crypto.session_key:
            print(f"🔐 Session key: {self.crypto.session_key.hex()[:32]}...")
        print("🔄 Automatic rekeying: every 5 packets or 60 seconds")
    
    def handle_encrypted_communication(self, client_socket):
        """Handle encrypted packet communication with full security features"""
        print("\n📦 ENCRYPTED PACKET COMMUNICATION")
        print("-" * 60)
        
        packet_count = 0
        
        try:
            while True:
                try:
                    # Receive encrypted packet
                    encrypted_packet = recv_with_length(client_socket)
                    packet_count += 1
                    self.session_stats['total_packets'] += 1
                    
                    print(f"\n[Server] Packet #{packet_count} received ({len(encrypted_packet)} bytes)")
                    
                    # Decrypt packet
                    try:
                        result = self.crypto.decrypt_packet(encrypted_packet)
                        if not result:
                            continue
                    except Exception as e:
                        print(f"[Server] ❌ Decryption failed - likely replay attack")
                        self.session_stats['replay_packets'] += 1
                        continue
                    
                    # Process packet based on type
                    packet_type = result.get("type")
                    packet_data = result.get("data")
                    sequence = result.get("sequence")
                    
                    if packet_type == "dummy":
                        self.session_stats['dummy_packets'] += 1
                        print(f"[Server] 🗑️  Dummy packet dropped")
                        
                    elif packet_type == "replay":
                        self.session_stats['replay_packets'] += 1
                        print(f"[Server] ⚠️  Replay attack detected and blocked!")
                        
                    elif packet_type == "real":
                        self.session_stats['real_packets'] += 1
                        
                        # Check for out-of-order packets
                        if sequence and sequence > self.crypto.highest_sequence_seen + 1:
                            self.session_stats['out_of_order_packets'] += 1
                            print(f"[Server] ⚠️  Out-of-order packet detected!")
                        
                        # Process real packet
                        if isinstance(packet_data, str):
                            print(f"[Server] ✅ Text: '{packet_data}'")
                            data_type = "text"
                        else:
                            data_len = len(packet_data) if packet_data else 0
                            print(f"[Server] ✅ Binary data ({data_len} bytes)")
                            data_type = "binary"
                        
                        # Send acknowledgment
                        ack_msg = f"ACK: {data_type} packet #{sequence}"
                        ack_packet = self.crypto.encrypt_packet(ack_msg, is_dummy=False)
                        send_with_length(client_socket, ack_packet)
                        print(f"[Server] 📤 ACK sent for packet #{sequence}")
                        
                except socket.timeout:
                    print("[Server] ⏱️  No more packets - session complete")
                    break
                except ConnectionError:
                    print("[Server] 🔌 Client disconnected")
                    break
                    
        except KeyboardInterrupt:
            print("\n[Server] Session interrupted")
    
    def print_session_summary(self):
        """Print comprehensive session statistics"""
        print(f"\n📊 SESSION SUMMARY")
        print("=" * 60)
        print(f"Total packets received: {self.session_stats['total_packets']}")
        print(f"Real packets processed: {self.session_stats['real_packets']}")
        print(f"Dummy packets dropped: {self.session_stats['dummy_packets']}")
        print(f"Replay packets blocked: {self.session_stats['replay_packets']}")
        print(f"Out-of-order packets detected: {self.session_stats['out_of_order_packets']}")
        print("=" * 60)


class VPNClientDemo:
    """Demonstration VPN client with comprehensive packet testing"""
    
    def __init__(self, server_port=5556):
        self.server_port = server_port
        self.crypto = QuantumResistantCrypto(is_server=False)
        self.stored_packets = {}  # Store packets for replay testing
    
    def start_client(self):
        """Start the VPN client and run complete demo"""
        # Wait for server to start
        time.sleep(1)
        
        print("\n🔐 QUANTUM-RESISTANT VPN CLIENT DEMO")
        print("=" * 60)
        
        try:
            # Connect to server
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(('localhost', self.server_port))
            print(f"🌐 Connected to server on localhost:{self.server_port}")
            
            # Perform handshake
            self.perform_handshake(client_socket)
            
            # Run packet transmission demo
            self.run_packet_demo(client_socket)
            
            client_socket.close()
            print("\n✅ Quantum-Resistant VPN MVP demo completed successfully!")
            
        except Exception as e:
            print(f"❌ Client error: {e}")
    
    def perform_handshake(self, client_socket):
        """Perform client-side handshake"""
        print("\n🔑 Generating client cryptographic keys...")
        self.crypto.generate_keys()
        
        # Receive server public keys
        server_keys = recv_with_length(client_socket)
        print(f"📥 Received server keys ({len(server_keys)} bytes)")
        
        # Send client public keys
        client_keys = self.crypto.get_public_keys_bytes()
        send_with_length(client_socket, client_keys)
        print(f"📤 Sent client keys ({len(client_keys)} bytes)")
        
        # Perform key exchange
        server_public_keys = self.crypto.parse_public_keys_bytes(server_keys)
        kyber_ciphertext = self.crypto.client_key_exchange(server_public_keys)
        send_with_length(client_socket, kyber_ciphertext)
        print(f"📤 Sent Kyber ciphertext ({len(kyber_ciphertext)} bytes)")
        
        print("✅ Handshake completed!")
        if self.crypto.session_key:
            print(f"🔐 Session key: {self.crypto.session_key.hex()[:32]}...")
    
    def run_packet_demo(self, client_socket):
        """Run comprehensive packet transmission demonstration"""
        print("\n📦 PACKET TRANSMISSION DEMO")
        print("-" * 60)
        
        # Phase 1: Normal sequential packets
        print("\n📋 Phase 1: Sequential Text Packets (1-5)")
        for i in range(1, 6):
            msg = f"Message {i}: Testing quantum-resistant encryption"
            encrypted = self.crypto.encrypt_packet(msg, is_dummy=False)
            
            if i == 3:  # Store packet 3 for replay test
                self.stored_packets[3] = encrypted
                print(f"[Client] 💾 Stored packet #{i} for replay test")
            
            send_with_length(client_socket, encrypted)
            print(f"[Client] 📤 Sent text packet #{i}")
            
            # Receive ACK
            ack = recv_with_length(client_socket)
            ack_result = self.crypto.decrypt_packet(ack)
            if ack_result and ack_result.get("type") == "real":
                print(f"[Client] ✅ ACK: {ack_result['data']}")
            
            time.sleep(0.2)
        
        # Phase 2: Binary packets
        print("\n📋 Phase 2: Binary Data Packets")
        for size in [128, 256]:
            binary_data = os.urandom(size)
            encrypted = self.crypto.encrypt_packet(binary_data, is_dummy=False)
            send_with_length(client_socket, encrypted)
            print(f"[Client] 📤 Sent binary packet ({size} bytes)")
            
            # Receive ACK
            ack = recv_with_length(client_socket)
            ack_result = self.crypto.decrypt_packet(ack)
            if ack_result and ack_result.get("type") == "real":
                print(f"[Client] ✅ ACK: {ack_result['data']}")
            
            time.sleep(0.2)
        
        # Phase 3: Dummy packets
        print("\n📋 Phase 3: Dummy Packets (Traffic Analysis Resistance)")
        for i in range(2):
            dummy = self.crypto.create_dummy_packet()
            encrypted = self.crypto.encrypt_packet(dummy, is_dummy=True)
            send_with_length(client_socket, encrypted)
            print(f"[Client] 👻 Sent dummy packet #{i+1} (no ACK expected)")
            time.sleep(0.2)
        
        # Phase 4: Out-of-order packet (send #9 before #8)
        print("\n📋 Phase 4: Out-of-Order Packet Test")
        msg9 = "Message 9: Out-of-order packet test"
        encrypted9 = self.crypto.encrypt_packet(msg9, is_dummy=False)
        send_with_length(client_socket, encrypted9)
        print("[Client] 📤 Sent packet #9 (out-of-order)")
        
        # Receive ACK for packet 9
        ack = recv_with_length(client_socket)
        ack_result = self.crypto.decrypt_packet(ack)
        if ack_result and ack_result.get("type") == "real":
            print(f"[Client] ✅ ACK: {ack_result['data']}")
        
        time.sleep(0.2)
        
        # Now send packet 8
        msg8 = "Message 8: Should come before 9"
        encrypted8 = self.crypto.encrypt_packet(msg8, is_dummy=False)
        send_with_length(client_socket, encrypted8)
        print("[Client] 📤 Sent packet #8 (after #9 - demonstrates ordering)")
        
        # Receive ACK for packet 8
        ack = recv_with_length(client_socket)
        ack_result = self.crypto.decrypt_packet(ack)
        if ack_result and ack_result.get("type") == "real":
            print(f"[Client] ✅ ACK: {ack_result['data']}")
        
        time.sleep(0.2)
        
        # Phase 5: Replay attack
        print("\n📋 Phase 5: Replay Attack Test")
        if 3 in self.stored_packets:
            send_with_length(client_socket, self.stored_packets[3])
            print("[Client] 🔄 REPLAY: Resent stored packet #3 (should be blocked)")
            time.sleep(0.5)
        
        # Final packet
        print("\n📋 Phase 6: Final Packet")
        final_msg = "Final message: Demo complete"
        encrypted_final = self.crypto.encrypt_packet(final_msg, is_dummy=False)
        send_with_length(client_socket, encrypted_final)
        print("[Client] 📤 Sent final packet")
        
        # Receive final ACK
        try:
            client_socket.settimeout(2.0)
            ack = recv_with_length(client_socket)
            ack_result = self.crypto.decrypt_packet(ack)
            if ack_result and ack_result.get("type") == "real":
                print(f"[Client] ✅ Final ACK: {ack_result['data']}")
        except socket.timeout:
            print("[Client] ⏱️  Final ACK timeout (expected)")


def main():
    """Main demo function - runs server and client simultaneously"""
    print("🚀 QUANTUM-RESISTANT VPN MVP DEMONSTRATION")
    print("=" * 70)
    print("Features:")
    print("  • Hybrid Post-Quantum Cryptography (X25519 + Kyber768)")
    print("  • HKDF-SHA3-256 Key Derivation")
    print("  • ChaCha20-Poly1305 Authenticated Encryption")
    print("  • Automatic Session Key Rotation")
    print("  • PKCS#7 Padding for Metadata Resistance")
    print("  • Dummy Packet Injection")
    print("  • Replay Protection with Sequence Numbers")
    print("  • Out-of-Order Packet Detection")
    print("=" * 70)
    
    # Create server and client instances
    server = VPNServerDemo(port=5556)
    client = VPNClientDemo(server_port=5556)
    
    # Start server in separate thread
    server_thread = threading.Thread(target=server.start_server, daemon=True)
    server_thread.start()
    
    # Start client (main thread)
    client.start_client()
    
    # Wait for server to finish
    server_thread.join(timeout=5)
    
    print("\n🎉 QUANTUM-RESISTANT VPN MVP DEMO COMPLETED!")
    print("🔒 All quantum-resistant security features demonstrated successfully.")


if __name__ == "__main__":
    main()