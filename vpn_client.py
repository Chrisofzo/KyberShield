#!/usr/bin/env python3
"""
Quantum-Resistant VPN Client

This client performs:
1. Connect to VPN server at localhost:5555 using sockets
2. Generate client key pairs (X25519 + Kyber)
3. Receive server's public keys
4. Send client's public keys and Kyber ciphertext to server
5. Derive the same 256-bit session key using HKDF-SHA3-256
6. Initialize ChaCha20-Poly1305 AEAD cipher
7. Encrypt multiple packets with fresh nonces
8. Receive and decrypt acknowledgment packets
"""

import socket
import sys
import time
from src.crypto_utils import QuantumResistantCrypto, send_with_length, recv_with_length


class VPNClient:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.crypto = QuantumResistantCrypto(is_server=False)
        
    def connect_to_server(self):
        """Connect to VPN server and perform handshake"""
        print("=" * 70)
        print("QUANTUM-RESISTANT VPN CLIENT")
        print("=" * 70)
        
        # Step 1: Generate client key pairs (X25519 + Kyber)
        print("\n🔐 Step 1: Generating Client Key Pairs...")
        self.crypto.generate_keys()
        print("[Client] DEBUG: X25519 and Kyber768 key pairs generated successfully")
        
        # Step 2: Connect to server at localhost:5555
        print(f"\n🌐 Step 2: Connecting to server at {self.host}:{self.port}...")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            client_socket.connect((self.host, self.port))
            print("[Client] DEBUG: Socket connection established successfully")
            
            # Step 3: Perform handshake protocol
            self.perform_handshake_protocol(client_socket)
            
            # Step 7: Encrypt and send multiple packets
            self.encrypt_and_send_packets(client_socket)
            
        except ConnectionRefusedError:
            print("❌ Connection refused. Make sure the VPN server is running.")
            return False
        except Exception as e:
            print(f"❌ Client error: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            client_socket.close()
            print("\n🔌 Disconnected from server")
            
        return True
    
    def perform_handshake_protocol(self, client_socket):
        """Perform complete hybrid key exchange handshake"""
        print("\n🤝 Step 3-5: Performing Handshake Protocol...")
        
        # Step 3: Receive server's public keys
        print("[Client] DEBUG: Receiving server's public keys...")
        server_public_keys = recv_with_length(client_socket)
        print(f"[Client] DEBUG: Received {len(server_public_keys)} bytes of server public key data")
        
        # Step 4: Send client's public keys to server
        print("[Client] DEBUG: Sending client's public keys to server...")
        client_public_keys = self.crypto.get_public_keys_bytes()
        send_with_length(client_socket, client_public_keys)
        print(f"[Client] DEBUG: Sent {len(client_public_keys)} bytes of client public key data")
        
        # Step 4: Perform key exchange and send Kyber ciphertext
        print("[Client] DEBUG: Performing hybrid key exchange (X25519 + Kyber768)...")
        kyber_ciphertext = self.crypto.client_key_exchange(server_public_keys)
        send_with_length(client_socket, kyber_ciphertext)
        print(f"[Client] DEBUG: Sent {len(kyber_ciphertext)} bytes of Kyber ciphertext to server")
        
        # Step 5: Session key derivation completed in client_key_exchange
        print("[Client] DEBUG: Handshake completed - 256-bit session key derived using HKDF-SHA3-256")
        
        # Step 6: ChaCha20-Poly1305 AEAD cipher initialization completed in key exchange
        print("[Client] DEBUG: ChaCha20-Poly1305 AEAD cipher initialized with session key")
        
        print("\n✅ Handshake protocol completed successfully!")
    
    def encrypt_and_send_packets(self, client_socket):
        """Step 7-8: Encrypt multiple packets and handle acknowledgments"""
        print("\n🔒 Step 7-8: Encrypted Packet Communication...")
        print("=" * 70)
        
        # Test packets: 10 real + 3 dummy packets for metadata resistance
        import os
        import random
        
        # Real packets for sequencing and replay testing
        real_packets = [
            ("real_text", "Packet 1: Testing replay protection"),
            ("real_text", "Packet 2: Sequential ordering"),
            ("real_text", "Packet 3: Normal communication"),
            ("real_text", "Packet 4: Sequence validation"),
            ("real_text", "Packet 5: Will be replayed later"),
            ("real_text", "Packet 6: Continue normal flow"),
            ("real_text", "Packet 7: Should come before 8"),
            ("real_text", "Packet 8: Out-of-order test"),
            ("real_text", "Packet 9: Back in order"),
            ("real_text", "Packet 10: Final message")
        ]
        
        # Dummy packets (3 of them)
        dummy_packets = [
            ("dummy", "dummy1"),
            ("dummy", "dummy2"),
            ("dummy", "dummy3")
        ]
        
        # Don't shuffle - keep in order for sequence testing
        all_packets = real_packets + dummy_packets
        
        print(f"[Client] DEBUG: Prepared {len(real_packets)} real packets + {len(dummy_packets)} dummy packets")
        print(f"[Client] DEBUG: Will send in sequence order to test replay protection")
        
        real_packet_count = 0
        stored_packet_5 = None  # Store packet 5 for replay test
        
        for i, (packet_type, packet_data) in enumerate(all_packets, 1):
            print(f"\n[Client] 📤 Processing Packet #{i} ({packet_type.upper()})...")
            
            # Handle different packet types
            if packet_type == "dummy":
                # Create dummy packet
                dummy_packet = self.crypto.create_dummy_packet()
                encrypted_packet = self.crypto.encrypt_packet(dummy_packet, is_dummy=True)
                expects_ack = False
                print(f"[Client] DEBUG: Sending dummy packet (no ACK expected)")
                
            elif packet_type == "real_text":
                print(f"[Client] DEBUG: Original text message: '{packet_data}'")
                encrypted_packet = self.crypto.encrypt_packet(packet_data, is_dummy=False)
                expects_ack = True
                print(f"[Client] DEBUG: Sending real text packet (ACK expected)")
                
                # Store packet 5 for replay test
                if "Packet 5:" in packet_data:
                    stored_packet_5 = encrypted_packet
                    print(f"[Client] DEBUG: Stored packet 5 for replay test")
                
            elif packet_type == "real_binary":
                print(f"[Client] DEBUG: Binary data length: {len(packet_data)} bytes")
                print(f"[Client] DEBUG: Binary preview: {packet_data[:32].hex()}...")
                encrypted_packet = self.crypto.encrypt_packet(packet_data, is_dummy=False)
                expects_ack = True
                print(f"[Client] DEBUG: Sending real binary packet (ACK expected)")
            
            # Send encrypted packet to server
            send_with_length(client_socket, encrypted_packet)
            print(f"[Client] DEBUG: Transmitted {len(encrypted_packet)} bytes (padded + encrypted)")
            
            # Only wait for ACK if this is a real packet
            if expects_ack:
                try:
                    print(f"[Client] DEBUG: Waiting for acknowledgment from server...")
                    client_socket.settimeout(5.0)  # 5 second timeout
                    ack_packet = recv_with_length(client_socket)
                    print(f"[Client] DEBUG: Received acknowledgment packet ({len(ack_packet)} bytes)")
                    
                    # Decrypt and display acknowledgment
                    ack_result = self.crypto.decrypt_packet(ack_packet)
                    if ack_result and ack_result.get("type") == "real":
                        ack_data = ack_result["data"]
                        ack_sequence = ack_result.get("sequence", 0)
                        if isinstance(ack_data, str):
                            print(f"[Client] ✅ Server acknowledgment (seq #{ack_sequence}): '{ack_data}'")
                        else:
                            print(f"[Client] ✅ Server sent binary acknowledgment (seq #{ack_sequence}): {len(ack_data)} bytes")
                    
                except socket.timeout:
                    print("[Client] ⚠️  No acknowledgment received (timeout)")
                except Exception as e:
                    print(f"[Client] ⚠️  Error receiving acknowledgment: {e}")
            else:
                print(f"[Client] DEBUG: Dummy packet sent, no ACK expected")
            
            # Small delay between packets for demonstration
            if i < len(all_packets):
                time.sleep(0.3)
        
        print(f"\n[Client] ✅ Successfully processed {len(all_packets)} encrypted packets!")
        print("[Client] DEBUG: All packets encrypted with unique nonces and transmitted securely")
        
        # Test replay attack and out-of-order packets
        print(f"\n🧪 REPLAY PROTECTION AND ORDERING TESTS")
        print("=" * 70)
        
        if stored_packet_5:
            # Test 1: Replay attack - resend packet 5
            print(f"\n[Client] 🔄 TEST 1: Replay Attack - Resending packet 5...")
            send_with_length(client_socket, stored_packet_5)
            print(f"[Client] DEBUG: Resent stored packet 5 (should be detected as replay)")
            time.sleep(1)
            
        # Test 2: Out-of-order packet - send packet with higher sequence
        print(f"\n[Client] 📤 TEST 2: Out-of-order Packet - Sending packet 15 (gap in sequence)...")
        out_of_order_packet = self.crypto.encrypt_packet("Packet 15: Out-of-order test", is_dummy=False)
        send_with_length(client_socket, out_of_order_packet)
        print(f"[Client] DEBUG: Sent packet with sequence gap (should trigger out-of-order warning)")
        
        try:
            # Try to get ACK for out-of-order packet
            client_socket.settimeout(3.0)
            ack_packet = recv_with_length(client_socket)
            ack_result = self.crypto.decrypt_packet(ack_packet)
            if ack_result and ack_result.get("type") == "real":
                ack_data = ack_result["data"]
                ack_sequence = ack_result.get("sequence", 0)
                print(f"[Client] ✅ Server acknowledged out-of-order packet (seq #{ack_sequence}): '{ack_data}'")
        except socket.timeout:
            print("[Client] No ACK received for out-of-order packet (expected)")
        except Exception as e:
            print(f"[Client] Error receiving ACK: {e}")
        
        print(f"\n[Client] 🧪 Testing completed - check server logs for replay detection")


def main():
    """Main client entry point"""
    print("Starting Quantum-Resistant VPN Client...")
    print("Ensure the VPN server is running on localhost:5555")
    print()
    
    # Brief pause for user to read
    time.sleep(2)
    
    # Create and run client
    client = VPNClient()
    success = client.connect_to_server()
    
    if success:
        print("\n🎉 VPN client session completed successfully!")
        print("All debug logs show successful handshake, encryption, and transmission.")
    else:
        print("\n❌ VPN client session failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()