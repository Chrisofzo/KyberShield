#!/usr/bin/env python3
"""
KyberLink VPN Server - UDP Transport Layer
==========================================

High-performance UDP-based VPN server with quantum-resistant encryption.
Provides stateless session management and improved latency over TCP.
"""

import socket
import struct
import threading
import time
import json
import secrets
import os
import sys
from datetime import datetime, timezone
from typing import Dict, Tuple, Optional, Any

# Add path for local imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_utils import QuantumResistantCrypto
from user_manager import UserManager
from session_manager import SessionManager
from audit_logger import get_audit_logger
from adaptive_dummy_traffic import get_dummy_traffic_manager, MetadataDefenseLevel
from packet_coalescing import get_packet_coalescing_engine
from permanent_no_logs import generic_error_response, startup_message
from secure_memory_scrubbing import create_session_cleanup_manager, secure_erase_object, emergency_memory_scrub

# UDP packet types
PACKET_HANDSHAKE_INIT = 1
PACKET_HANDSHAKE_RESPONSE = 2
PACKET_HANDSHAKE_COMPLETE = 3
PACKET_DATA = 4
PACKET_HEARTBEAT = 5
PACKET_DUMMY = 6

class UDPSession:
    """Represents a client session for stateless UDP handling with secure cleanup"""
    
    def __init__(self, session_id: bytes, client_addr: Tuple[str, int]):
        self.session_id = session_id
        self.client_addr = client_addr
        self.crypto = QuantumResistantCrypto(is_server=True)
        self.username = None
        self.authenticated = False
        self.last_activity = time.time()
        self.handshake_complete = False
        self.sequence_numbers = set()  # For replay protection
        
        # Secure cleanup manager
        self.cleanup_manager = create_session_cleanup_manager()
        
        # Packet buffers for secure erasure
        self.packet_buffer = bytearray()
        self.temp_buffer = bytearray()
        self.nonces_used = set()
        
    def is_expired(self, timeout: int = 300) -> bool:
        """Check if session has expired (default 5 minutes)"""
        return time.time() - self.last_activity > timeout
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = time.time()
    
    def secure_disconnect_cleanup(self):
        """Securely erase all sensitive session data on disconnect"""
        # Perform comprehensive secure cleanup
        self.cleanup_manager.cleanup_complete_session(self)
        
        # Additional manual cleanup for session-specific data
        if hasattr(self, 'packet_buffer') and self.packet_buffer:
            from secure_memory_scrubbing import secure_erase
            secure_erase(self.packet_buffer)
            self.packet_buffer.clear()
            
        if hasattr(self, 'temp_buffer') and self.temp_buffer:
            secure_erase(self.temp_buffer)
            self.temp_buffer.clear()
            
        # Clear sequence numbers and nonces
        if hasattr(self, 'sequence_numbers'):
            self.sequence_numbers.clear()
            
        if hasattr(self, 'nonces_used'):
            self.nonces_used.clear()
            
        # Force garbage collection
        self.cleanup_manager.force_garbage_collection()

class KyberLinkUDPVPNServer:
    """
    High-Performance UDP VPN Server
    
    Features:
    - Quantum-resistant hybrid encryption (X25519 + ML-KEM-768)
    - Stateless session management with client mapping
    - Improved latency and reduced TCP-over-TCP overhead  
    - ChaCha20-Poly1305 AEAD encryption for data packets
    - Session rekeying every 60 seconds for perfect forward secrecy
    """
    
    def __init__(self, host='0.0.0.0', port=5555, metadata_defense_level='medium'):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        
        # Session management
        self.sessions: Dict[bytes, UDPSession] = {}  # session_id -> UDPSession
        self.client_sessions: Dict[Tuple[str, int], bytes] = {}  # client_addr -> session_id
        self.sessions_lock = threading.RLock()
        
        # System components
        self.user_manager = UserManager()
        self.session_manager = SessionManager()
        self.audit_logger = get_audit_logger()
        
        # Adaptive dummy traffic management
        self.dummy_traffic_manager = get_dummy_traffic_manager()
        self.dummy_traffic_manager.set_send_callback(self.send_dummy_packet)
        
        # Packet coalescing engine
        self.coalescing_engine = get_packet_coalescing_engine()
        self.coalescing_engine.set_send_callback(self.send_coalesced_packet)
        
        # Set metadata defense level
        level_map = {'low': MetadataDefenseLevel.LOW, 'medium': MetadataDefenseLevel.MEDIUM, 'high': MetadataDefenseLevel.HIGH}
        if metadata_defense_level.lower() in level_map:
            self.dummy_traffic_manager.set_defense_level(level_map[metadata_defense_level.lower()])
        
        # Server keys for handshake
        self.server_crypto = QuantumResistantCrypto(is_server=True)
        
        # Secure memory cleanup manager
        self.global_cleanup_manager = create_session_cleanup_manager()
        
        # NO LOGGING - Permanent no-logs mode active
    
    def generate_session_id(self) -> bytes:
        """Generate unique 16-byte session ID"""
        while True:
            session_id = secrets.token_bytes(16)
            if session_id not in self.sessions:
                return session_id
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions (runs in background thread)"""
        while self.running:
            try:
                with self.sessions_lock:
                    expired_sessions = []
                    for session_id, session in self.sessions.items():
                        if session.is_expired():
                            expired_sessions.append(session_id)
                    
                    for session_id in expired_sessions:
                        session = self.sessions[session_id]
                        client_addr = session.client_addr
                        
                        # Perform secure memory scrubbing before removal
                        session.secure_disconnect_cleanup()
                        
                        # Remove from both mappings
                        del self.sessions[session_id]
                        if client_addr in self.client_sessions:
                            del self.client_sessions[client_addr]
                            
                        # Remove from dummy traffic manager
                        self.dummy_traffic_manager.remove_session(session_id)
                        
                        # Session cleanup - no logging
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                print(f"[Server] ❌ Session cleanup error: {e}")
                time.sleep(30)
    
    def pack_packet(self, packet_type: int, session_id: bytes, data: bytes) -> bytes:
        """
        Pack UDP packet with format: [type:1][session_id:16][data_len:4][data:N]
        
        Args:
            packet_type: Packet type identifier
            session_id: 16-byte session identifier
            data: Packet payload
            
        Returns:
            Packed packet bytes
        """
        header = struct.pack('!B16sI', packet_type, session_id, len(data))
        return header + data
    
    def unpack_packet(self, packet: bytes) -> Tuple[int, bytes, bytes]:
        """
        Unpack UDP packet
        
        Args:
            packet: Raw packet bytes
            
        Returns:
            Tuple of (packet_type, session_id, data)
        """
        if len(packet) < 21:  # Minimum header size
            raise ValueError("Packet too short")
        
        packet_type, session_id, data_len = struct.unpack('!B16sI', packet[:21])
        
        if len(packet) < 21 + data_len:
            raise ValueError("Invalid data length")
        
        data = packet[21:21 + data_len]
        return packet_type, session_id, data
    
    def handle_handshake_init(self, client_addr: Tuple[str, int], data: bytes) -> bytes:
        """
        Handle initial handshake request from client
        
        Args:
            client_addr: Client IP and port
            data: Handshake data (login credentials + client keys)
            
        Returns:
            Response packet or None if failed
        """
        try:
            # Parse handshake data
            handshake_data = json.loads(data.decode('utf-8'))
            username = handshake_data.get('username')
            password = handshake_data.get('password')
            client_x25519_public = bytes.fromhex(handshake_data.get('x25519_public', ''))
            client_kyber_public = bytes.fromhex(handshake_data.get('kyber_public', ''))
            
            # Handshake processing - no logging
            
            # Authenticate user
            if not self.user_manager.authenticate_user(username, password):
                # Authentication failed - no logging
                return None
            
            # Generate session
            session_id = self.generate_session_id()
            session = UDPSession(session_id, client_addr)
            session.username = username
            session.authenticated = True
            
            # Perform hybrid key exchange
            session.crypto.generate_keys()
            session.crypto.set_peer_public_key(client_x25519_public, client_kyber_public)
            session.crypto.derive_shared_secret()
            session.crypto._derive_session_key()
            
            # Store session
            with self.sessions_lock:
                self.sessions[session_id] = session
                self.client_sessions[client_addr] = session_id
                
                # Add session to dummy traffic manager
                self.dummy_traffic_manager.add_session(session_id, client_addr)
            
            # Prepare response
            response_data = {
                'status': 'success',
                'session_id': session_id.hex(),
                'x25519_public': session.crypto.x25519_public_key.hex(),
                'kyber_public': session.crypto.kyber_public_key.hex(),
                'server_time': datetime.now(timezone.utc).isoformat()
            }
            
            response_json = json.dumps(response_data).encode('utf-8')
            response_packet = self.pack_packet(PACKET_HANDSHAKE_RESPONSE, session_id, response_json)
            
            # Session established - no logging
            
            return response_packet
            
        except Exception as e:
            # Handshake failed - no logging
            return None
    
    def handle_handshake_complete(self, session: UDPSession, data: bytes) -> bool:
        """
        Handle handshake completion from client
        
        Args:
            session: Client session
            data: Completion confirmation
            
        Returns:
            True if handshake completed successfully
        """
        try:
            completion_data = json.loads(data.decode('utf-8'))
            if completion_data.get('status') == 'ready':
                session.handshake_complete = True
                session.update_activity()
                
                # Handshake complete - no logging
                return True
                
        except Exception as e:
            # Handshake completion failed - no logging
            pass
            
        return False
    
    def handle_data_packet(self, session: UDPSession, data: bytes) -> Optional[bytes]:
        """
        Handle encrypted data packet from client
        
        Args:
            session: Client session
            data: Encrypted packet data
            
        Returns:
            Response packet or None
        """
        try:
            if not session.handshake_complete:
                # Data packet before handshake - no logging
                return None
            
            # Decrypt packet
            decrypted_data = session.crypto.decrypt_packet(data)
            if not decrypted_data:
                # Packet decryption failed - no logging
                return None
            
            session.update_activity()
            
            # Record real packet for dummy traffic analysis
            self.dummy_traffic_manager.record_real_packet(session.session_id)
            
            # Data packet processed - no logging
            
            # Echo response for testing
            response_text = f"Server received: {decrypted_data}"
            encrypted_response = session.crypto.encrypt_packet(response_text)
            
            response_packet = self.pack_packet(PACKET_DATA, session.session_id, encrypted_response)
            
            # Queue response for coalescing instead of immediate send
            self.coalescing_engine.queue_packet(response_packet, session.client_addr)
            return None  # Packet will be sent via coalescing
            
        except Exception as e:
            # Data packet handling failed - no logging
            pass
            return None
    
    def handle_packet(self, packet: bytes, client_addr: Tuple[str, int]) -> Optional[bytes]:
        """
        Main packet handler - routes packets based on type
        
        Args:
            packet: Raw UDP packet
            client_addr: Client address
            
        Returns:
            Response packet or None
        """
        try:
            packet_type, session_id, data = self.unpack_packet(packet)
            
            if packet_type == PACKET_HANDSHAKE_INIT:
                # New handshake - no existing session required
                return self.handle_handshake_init(client_addr, data)
                
            # All other packet types require existing session
            with self.sessions_lock:
                session = self.sessions.get(session_id)
                if not session:
                    # Unknown session - no logging
                    return None
                
                if session.client_addr != client_addr:
                    # Session address mismatch - no logging
                    return None
            
            if packet_type == PACKET_HANDSHAKE_COMPLETE:
                if self.handle_handshake_complete(session, data):
                    # Send acknowledgment
                    ack_data = json.dumps({'status': 'acknowledged'}).encode('utf-8')
                    return self.pack_packet(PACKET_HANDSHAKE_COMPLETE, session_id, ack_data)
                    
            elif packet_type == PACKET_DATA:
                return self.handle_data_packet(session, data)
                
            elif packet_type == PACKET_HEARTBEAT:
                session.update_activity()
                # Echo heartbeat
                return self.pack_packet(PACKET_HEARTBEAT, session_id, data)
            
            return None
            
        except Exception as e:
            # Packet handling error - no logging
            pass
            return None
    
    def send_dummy_packet(self, dummy_packet: bytes, client_addr: Tuple[str, int]):
        """Send dummy packet to client (callback for dummy traffic manager)"""
        try:
            if self.socket and self.running:
                # Queue dummy packets for coalescing too
                self.coalescing_engine.queue_packet(dummy_packet, client_addr)
                
        except Exception as e:
            # Dummy packet transmission failed - no logging
            pass
    
    def send_coalesced_packet(self, coalesced_data: bytes, client_addr: Tuple[str, int]):
        """Send coalesced packet to client (callback for coalescing engine)"""
        try:
            if self.socket and self.running:
                self.socket.sendto(coalesced_data, client_addr)
                
        except Exception as e:
            # Coalesced packet transmission failed - no logging
            pass
    
    def get_dummy_traffic_stats(self) -> dict:
        """Get dummy traffic statistics"""
        return self.dummy_traffic_manager.get_statistics()
    
    def get_coalescing_stats(self) -> dict:
        """Get packet coalescing performance statistics"""
        return self.coalescing_engine.get_performance_stats()
    
    def set_metadata_defense_level(self, level: str) -> bool:
        """Set metadata defense level"""
        level_map = {
            'low': MetadataDefenseLevel.LOW,
            'medium': MetadataDefenseLevel.MEDIUM,
            'high': MetadataDefenseLevel.HIGH
        }
        
        if level.lower() in level_map:
            self.dummy_traffic_manager.set_defense_level(level_map[level.lower()])
            # Metadata defense level updated - no logging
            return True
        return False
    
    def start_server(self):
        """Start the UDP VPN server"""
        try:
            # Display minimal startup message
            startup_message()
            
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.running = True
            
            # Generate server keys
            self.server_crypto.generate_keys()
            # Server keys generated - no logging
            
            # Start session cleanup thread
            cleanup_thread = threading.Thread(target=self.cleanup_expired_sessions, daemon=True)
            cleanup_thread.start()
            
            # Start dummy traffic manager
            self.dummy_traffic_manager.start()
            
            # UDP server listening - no logging
            
            # Main server loop
            while self.running:
                try:
                    # Receive packet (up to 64KB)
                    packet, client_addr = self.socket.recvfrom(65536)
                    
                    # Handle in separate thread for concurrency
                    threading.Thread(
                        target=self._handle_client_packet_coalesced,
                        args=(packet, client_addr),
                        daemon=True
                    ).start()
                    
                except socket.error as e:
                    if self.running:
                        # Network socket error - no logging
                        pass
                        time.sleep(0.1)
                        
        except Exception as e:
            # Server startup failed - no logging
            pass
        finally:
            self.stop_server()
    
    def _handle_client_packet_coalesced(self, packet: bytes, client_addr: Tuple[str, int]):
        """Handle client packet with coalescing support"""
        try:
            # Process received packet (may be coalesced or fragmented)
            individual_packets = self.coalescing_engine.process_received_packet(packet)
            
            for individual_packet in individual_packets:
                # Handle each individual packet
                response = self.handle_packet(individual_packet, client_addr)
                # Response is None because packets are queued for coalescing
                
        except Exception as e:
            # Coalesced packet handling error - no logging
            pass
    
    def _handle_client_packet(self, packet: bytes, client_addr: Tuple[str, int]):
        """Handle client packet in separate thread (legacy method)"""
        try:
            response = self.handle_packet(packet, client_addr)
            if response:
                self.socket.sendto(response, client_addr)
                
        except Exception as e:
            # Client packet handling error - no logging
            pass
    
    def stop_server(self):
        """Stop the UDP VPN server"""
        # Stopping server - no logging
        self.running = False
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        # Stop dummy traffic manager
        self.dummy_traffic_manager.stop()
        
        # Clear sessions
        with self.sessions_lock:
            self.sessions.clear()
            self.client_sessions.clear()
        
        # Server stopped - no logging

def main():
    """Main server entry point"""
    server = KyberLinkUDPVPNServer()
    
    try:
        server.start_server()
    except KeyboardInterrupt:
        # Interrupt signal - no logging
        pass
    finally:
        server.stop_server()

if __name__ == "__main__":
    main()