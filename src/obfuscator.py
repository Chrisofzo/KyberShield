#!/usr/bin/env python3
"""
KyberLink VPN Traffic Obfuscation Module (Stealth Mode)
======================================================

Advanced traffic disguising to make VPN packets appear as normal HTTPS/TLS web traffic.
Uses AES-CTR encryption with fake HTTP/2 headers and variable padding to evade DPI detection.

Security Features:
- AES-256-CTR encryption with random session keys
- Fake HTTP/2 frame headers for traffic camouflage  
- Variable padding (32-128 bytes) to mimic TLS record sizes
- Random stream cipher initialization per session
- Deep Packet Inspection (DPI) evasion techniques
"""

import os
import secrets
import struct
import time
import random
import threading
import asyncio
from typing import Tuple, Optional, List, Dict, Any, Callable
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


class TrafficObfuscator:
    """Advanced traffic obfuscation for stealth VPN operation"""
    
    def __init__(self, stealth_mode: bool = False, max_mtu: int = 1500):
        self.session_key = None
        self.counter = 0
        self.backend = default_backend()
        self.stealth_mode = stealth_mode
        self.max_mtu = max_mtu
        
        # XOR + ChaCha20 keys for enhanced obfuscation
        self.xor_key = secrets.token_bytes(32)
        self.chacha_key = secrets.token_bytes(32)
        
        # Fragment reassembly buffer
        self.fragment_id = 0
        self.reassembly_buffer = {}
        
        # Statistics tracking
        self.stats = {
            "packets_obfuscated": 0,
            "packets_fragmented": 0,
            "dummy_packets_sent": 0,
            "total_padding_added": 0,
            "avg_packet_size": 0,
            "xor_chacha_packets": 0
        }
        
        # HTTP/2 frame type constants for disguising
        self.HTTP2_FRAME_TYPES = {
            'DATA': 0x0,
            'HEADERS': 0x1,
            'PRIORITY': 0x2,
            'RST_STREAM': 0x3,
            'SETTINGS': 0x4,
            'PUSH_PROMISE': 0x5,
            'PING': 0x6,
            'GOAWAY': 0x7,
            'WINDOW_UPDATE': 0x8,
            'CONTINUATION': 0x9
        }
        
        # Common HTTP/2 headers for realistic traffic patterns
        self.FAKE_HEADERS = [
            b':method: GET',
            b':scheme: https',
            b':authority: cdn.example.com',
            b':path: /api/v2/data.json',
            b'user-agent: Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0',
            b'accept: application/json, text/plain, */*',
            b'accept-encoding: gzip, deflate, br',
            b'accept-language: en-US,en;q=0.9',
            b'cache-control: no-cache',
            b'sec-fetch-dest: empty',
            b'sec-fetch-mode: cors',
            b'sec-fetch-site: cross-site'
        ]
        
        print(f"🕵️  Traffic Obfuscator initialized - Stealth Mode {'ON' if stealth_mode else 'OFF'}")
    
    def generate_session_key(self, shared_secret: bytes = None) -> bytes:
        """
        Generate AES-256 session key for obfuscation
        
        Args:
            shared_secret: Optional shared secret for key derivation
            
        Returns:
            32-byte AES-256 key
        """
        if shared_secret:
            # Derive key from shared secret using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit key
                salt=b"KyberLink-Obfuscation-Salt-v1.0",
                info=b"stealth-mode-session-key",
                backend=self.backend
            )
            self.session_key = hkdf.derive(shared_secret)
        else:
            # Generate random session key
            self.session_key = secrets.token_bytes(32)
        
        print(f"🔑 Obfuscation session key generated ({len(self.session_key)} bytes)")
        return self.session_key
    
    def _create_fake_http2_header(self, data_length: int) -> bytes:
        """
        Create realistic HTTP/2 frame header to disguise VPN packets
        
        Args:
            data_length: Length of the actual data payload
            
        Returns:
            Fake HTTP/2 frame header bytes
        """
        # HTTP/2 frame format:
        # Length (24 bits) | Type (8 bits) | Flags (8 bits) | Stream ID (31 bits)
        
        # Choose random frame type (mostly DATA and HEADERS for realism)
        frame_types = ['DATA', 'HEADERS', 'SETTINGS', 'PING']
        frame_type = secrets.choice(frame_types)
        type_value = self.HTTP2_FRAME_TYPES[frame_type]
        
        # Random but realistic flags
        flags = secrets.randbits(8) & 0x0F  # Keep flags realistic
        
        # Random stream ID (must be odd for client-initiated)
        stream_id = (secrets.randbits(30) | 1) & 0x7FFFFFFF
        
        # Pack as HTTP/2 frame header (9 bytes)
        header = struct.pack('>I', data_length)[1:] + struct.pack('>BBL', type_value, flags, stream_id)
        
        return header
    
    def _add_variable_padding(self, data: bytes) -> bytes:
        """
        Add variable padding to mimic TLS record size variations
        
        Args:
            data: Original data to pad
            
        Returns:
            Data with random padding (32-128 bytes)
        """
        # Random padding length between 32-128 bytes
        padding_length = secrets.randbelow(97) + 32  # 32-128 bytes
        
        # Generate random padding data
        padding = secrets.token_bytes(padding_length)
        
        # Prepend padding length as 2 bytes, then padding, then original data
        padded_data = struct.pack('>H', padding_length) + padding + data
        
        return padded_data
    
    def _remove_padding(self, padded_data: bytes) -> bytes:
        """
        Remove variable padding from padded data
        
        Args:
            padded_data: Data with padding
            
        Returns:
            Original data without padding
        """
        if len(padded_data) < 2:
            raise ValueError("Invalid padded data - too short")
        
        # Extract padding length
        padding_length = struct.unpack('>H', padded_data[:2])[0]
        
        # Validate padding length
        if padding_length < 32 or padding_length > 128:
            raise ValueError(f"Invalid padding length: {padding_length}")
        
        if len(padded_data) < 2 + padding_length:
            raise ValueError("Invalid padded data - shorter than expected")
        
        # Extract original data (skip length + padding)
        original_data = padded_data[2 + padding_length:]
        
        return original_data
    
    def _add_fake_http_headers(self, data: bytes) -> bytes:
        """
        Add fake HTTP-like headers to make traffic look like web requests
        
        Args:
            data: Data to disguise
            
        Returns:
            Data with fake HTTP headers prepended
        """
        # Select random subset of fake headers
        num_headers = secrets.randbelow(5) + 3  # 3-7 headers
        selected_headers = random.sample(self.FAKE_HEADERS, num_headers)
        
        # Add timestamp and content-length for realism
        timestamp = int(time.time())
        content_length = len(data)
        
        # Construct fake HTTP-like header block
        fake_headers = b'\r\n'.join(selected_headers)
        fake_headers += f'\r\ncontent-length: {content_length}'.encode()
        fake_headers += f'\r\nx-timestamp: {timestamp}'.encode()
        fake_headers += b'\r\n\r\n'  # End of headers
        
        # Prepend header length and headers
        header_length = len(fake_headers)
        header_block = struct.pack('>H', header_length) + fake_headers + data
        
        return header_block
    
    def _strip_fake_headers(self, data_with_headers: bytes) -> bytes:
        """
        Strip fake HTTP headers from disguised data
        
        Args:
            data_with_headers: Data with fake headers
            
        Returns:
            Original data without headers
        """
        if len(data_with_headers) < 2:
            raise ValueError("Invalid header data - too short")
        
        # Extract header length
        header_length = struct.unpack('>H', data_with_headers[:2])[0]
        
        # Validate header length
        if header_length > len(data_with_headers) - 2:
            raise ValueError(f"Invalid header length: {header_length}")
        
        # Extract original data (skip length + headers)
        original_data = data_with_headers[2 + header_length:]
        
        return original_data
    
    def _xor_mask(self, data: bytes, key: bytes) -> bytes:
        """Apply XOR masking to data"""
        key_len = len(key)
        return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))
    
    def _chacha20_stream(self, data: bytes, nonce: bytes) -> bytes:
        """Apply ChaCha20 stream cipher masking"""
        cipher = Cipher(
            algorithms.ChaCha20(self.chacha_key, nonce),
            mode=None,
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        return encryptor.update(data)
    
    def _should_fragment(self, data: bytes) -> bool:
        """Decide whether to fragment packet for stealth"""
        if not self.stealth_mode:
            return False
        
        # Fragment 30% of packets randomly for analysis resistance
        return len(data) > 800 and random.random() < 0.3
    
    def _fragment_packet(self, packet: bytes) -> List[bytes]:
        """Fragment packet into smaller pieces"""
        fragment_size = random.randint(400, 800)  # Variable fragment sizes
        fragments = []
        
        self.fragment_id += 1
        total_fragments = (len(packet) + fragment_size - 1) // fragment_size
        
        for i in range(0, len(packet), fragment_size):
            fragment_data = packet[i:i+fragment_size]
            fragment_header = struct.pack('!HHH', 
                                        0xF4A9,  # Fragment marker
                                        self.fragment_id, 
                                        i // fragment_size)  # Fragment index
            fragments.append(fragment_header + fragment_data)
        
        return fragments
    
    def _is_fragment(self, data: bytes) -> bool:
        """Check if data is a fragment"""
        return len(data) >= 6 and struct.unpack('!H', data[:2])[0] == 0xF4A9
    
    def _reassemble_fragment(self, fragment: bytes) -> Tuple[Optional[bytes], int]:
        """Reassemble fragmented packet"""
        if len(fragment) < 6:
            return None, -1
        
        marker, frag_id, frag_index = struct.unpack('!HHH', fragment[:6])
        fragment_data = fragment[6:]
        
        # Store fragment
        if frag_id not in self.reassembly_buffer:
            self.reassembly_buffer[frag_id] = {}
        
        self.reassembly_buffer[frag_id][frag_index] = fragment_data
        
        # Check if we can reassemble (simple heuristic)
        fragments = self.reassembly_buffer[frag_id]
        if len(fragments) > 1 and max(fragments.keys()) == len(fragments) - 1:
            # All fragments received
            reassembled = b""
            for i in sorted(fragments.keys()):
                reassembled += fragments[i]
            
            del self.reassembly_buffer[frag_id]
            return reassembled, 0x01  # Assume real packet
        
        return None, -1
    
    def _generate_mtu_padding(self, current_size: int) -> bytes:
        """Generate random padding up to MTU size"""
        if not self.stealth_mode:
            return b""
        
        # Random padding between 0 and (MTU - current_size - 100)
        max_padding = max(0, self.max_mtu - current_size - 100)
        if max_padding <= 0:
            return b""
        
        padding_size = random.randint(0, min(max_padding, 512))
        padding = secrets.token_bytes(padding_size)
        
        self.stats["total_padding_added"] += padding_size
        return padding
    
    def obfuscate(self, packet: bytes) -> bytes:
        """
        Obfuscate VPN packet with layered protection (legacy method)
        """
        return self.obfuscate_advanced(packet, packet_type=0x01)[0]
    
    def obfuscate_advanced(self, packet_data: bytes, packet_type: int = 0x01) -> List[bytes]:
        """
        Advanced obfuscation with XOR + ChaCha20 masking and fragmentation
        
        Args:
            packet_data: Original packet data
            packet_type: 0x01 = real packet, 0x00 = dummy packet
            
        Returns:
            List of obfuscated packet fragments
        """
        if not packet_data and packet_type != 0x00:
            return []
        
        try:
            # Step 1: Add packet header with type and length
            header = struct.pack('!BH', packet_type, len(packet_data))
            full_packet = header + packet_data
            
            # Step 2: Add MTU-based random padding if in stealth mode
            if self.stealth_mode:
                mtu_padding = self._generate_mtu_padding(len(full_packet))
                if mtu_padding:
                    full_packet += struct.pack('!H', len(mtu_padding)) + mtu_padding
                else:
                    full_packet += struct.pack('!H', 0)
            
            # Step 3: Fragment if needed (stealth mode only)
            fragments = []
            if self._should_fragment(full_packet):
                fragments = self._fragment_packet(full_packet)
                self.stats["packets_fragmented"] += 1
            else:
                fragments = [full_packet]
            
            # Step 4: Apply enhanced obfuscation layers
            obfuscated_fragments = []
            for fragment in fragments:
                if self.stealth_mode:
                    # Enhanced stealth obfuscation: XOR + ChaCha20
                    obfuscated_fragment = self._apply_xor_chacha_obfuscation(fragment)
                    self.stats["xor_chacha_packets"] += 1
                else:
                    # Standard HTTPS mimicry obfuscation
                    obfuscated_fragment = self._apply_https_obfuscation(fragment)
                
                obfuscated_fragments.append(obfuscated_fragment)
            
            self.stats["packets_obfuscated"] += 1
            self._update_avg_packet_size(sum(len(f) for f in obfuscated_fragments))
            
            return obfuscated_fragments
            
        except Exception as e:
            print(f"❌ Advanced obfuscation failed: {e}")
            # Fallback: simple obfuscation
            return [b"HTTPS/1.1" + secrets.token_bytes(8) + packet_data]
    
    def _apply_xor_chacha_obfuscation(self, data: bytes) -> bytes:
        """Apply XOR + ChaCha20 stream masking"""
        # Layer 1: XOR masking
        xor_masked = self._xor_mask(data, self.xor_key)
        
        # Layer 2: ChaCha20 stream masking
        nonce = secrets.token_bytes(12)
        chacha_masked = self._chacha20_stream(xor_masked, nonce)
        
        # Add nonce prefix for deobfuscation
        return nonce + chacha_masked
    
    def _apply_https_obfuscation(self, data: bytes) -> bytes:
        """Apply standard HTTPS mimicry obfuscation"""
        if not self.session_key:
            self.generate_session_key()
        
        # Step 1: Add variable padding to mimic TLS record variations
        padded_packet = self._add_variable_padding(data)
        
        # Step 2: Encrypt with AES-256-CTR using session key
        nonce = secrets.token_bytes(16)
        
        cipher = Cipher(
            algorithms.AES(self.session_key),
            modes.CTR(nonce),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_packet) + encryptor.finalize()
        
        # Step 3: Add fake HTTP headers for web traffic camouflage
        data_with_headers = self._add_fake_http_headers(encrypted_data)
        
        # Step 4: Create fake HTTP/2 frame header
        http2_header = self._create_fake_http2_header(len(data_with_headers))
        
        # Step 5: Combine everything
        return nonce + http2_header + data_with_headers
    
    def deobfuscate(self, obfuscated_packet: bytes) -> bytes:
        """
        Deobfuscate disguised packet to recover original VPN data
        
        Args:
            obfuscated_packet: Obfuscated packet data
            
        Returns:
            Original VPN packet data
        """
        if not self.session_key:
            raise ValueError("Session key not generated - call generate_session_key() first")
        
        try:
            # Validate minimum packet size (nonce + HTTP/2 header + some data)
            if len(obfuscated_packet) < 16 + 9 + 10:  # nonce + header + minimal data
                raise ValueError("Packet too short for deobfuscation")
            
            # Step 1: Extract nonce (first 16 bytes)
            nonce = obfuscated_packet[:16]
            remaining_data = obfuscated_packet[16:]
            
            # Step 2: Skip HTTP/2 frame header (next 9 bytes)
            if len(remaining_data) < 9:
                raise ValueError("Invalid packet - missing HTTP/2 header")
            
            # Extract HTTP/2 header for validation (optional)
            http2_header = remaining_data[:9]
            data_with_headers = remaining_data[9:]
            
            # Step 3: Strip fake HTTP headers
            encrypted_data = self._strip_fake_headers(data_with_headers)
            
            # Step 4: Decrypt with AES-256-CTR
            cipher = Cipher(
                algorithms.AES(self.session_key),
                modes.CTR(nonce),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            padded_packet = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Step 5: Remove variable padding
            original_packet = self._remove_padding(padded_packet)
            
            print(f"🔓 Packet deobfuscated: {len(obfuscated_packet)} → {len(original_packet)} bytes")
            
            return original_packet
            
        except Exception as e:
            print(f"❌ Deobfuscation failed: {e}")
            raise ValueError(f"Failed to deobfuscate packet: {e}")
    
    def create_dummy_packet(self) -> List[bytes]:
        """Create dummy packet for traffic analysis resistance"""
        dummy_size = random.randint(100, 1200)
        dummy_data = secrets.token_bytes(dummy_size)
        
        self.stats["dummy_packets_sent"] += 1
        return self.obfuscate_advanced(dummy_data, packet_type=0x00)
    
    def _update_avg_packet_size(self, size: int):
        """Update average packet size statistics"""
        total_packets = self.stats["packets_obfuscated"]
        if total_packets > 1:
            self.stats["avg_packet_size"] = (
                (self.stats["avg_packet_size"] * (total_packets - 1) + size) 
                / total_packets
            )
        else:
            self.stats["avg_packet_size"] = size
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive obfuscation statistics"""
        total_packets = self.stats["packets_obfuscated"] + self.stats["dummy_packets_sent"]
        dummy_percentage = (self.stats["dummy_packets_sent"] / max(total_packets, 1)) * 100
        
        return {
            **self.stats,
            "stealth_mode": self.stealth_mode,
            "dummy_packet_percentage": round(dummy_percentage, 2),
            "fragmentation_rate": round(
                (self.stats["packets_fragmented"] / max(self.stats["packets_obfuscated"], 1)) * 100, 2
            ),
            "xor_chacha_usage": round(
                (self.stats["xor_chacha_packets"] / max(self.stats["packets_obfuscated"], 1)) * 100, 2
            )
        }
    
    def enable_stealth_mode(self):
        """Enable stealth mode"""
        self.stealth_mode = True
        print("🎭 Stealth mode ENABLED")
    
    def disable_stealth_mode(self):
        """Disable stealth mode"""
        self.stealth_mode = False
        print("🎭 Stealth mode DISABLED")


class DummyTrafficScheduler:
    """Background scheduler for dummy traffic generation"""
    
    def __init__(self, obfuscator: TrafficObfuscator, interval_range: Tuple[int, int] = (5, 10)):
        self.obfuscator = obfuscator
        self.interval_range = interval_range
        self.running = False
        self.thread = None
        self.send_callback = None
    
    def set_send_callback(self, callback: Callable[[bytes], None]):
        """Set callback function for sending dummy packets"""
        self.send_callback = callback
    
    def start(self):
        """Start dummy traffic scheduler"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.thread.start()
        print("📡 Dummy traffic scheduler started")
    
    def stop(self):
        """Stop dummy traffic scheduler"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)
        print("📡 Dummy traffic scheduler stopped")
    
    def _scheduler_loop(self):
        """Main scheduler loop"""
        while self.running:
            try:
                # Wait for random interval
                interval = random.randint(*self.interval_range)
                time.sleep(interval)
                
                if not self.running:
                    break
                
                # Generate and send dummy packet if in stealth mode
                if self.obfuscator.stealth_mode and self.send_callback:
                    dummy_packets = self.obfuscator.create_dummy_packet()
                    for packet in dummy_packets:
                        self.send_callback(packet)
                        print("📡 Dummy packet sent for traffic analysis resistance")
                
            except Exception as e:
                print(f"❌ Dummy traffic scheduler error: {e}")
                time.sleep(5)  # Error recovery


# Global obfuscator instance
_global_obfuscator = None


def get_obfuscator() -> TrafficObfuscator:
    """Get global obfuscator instance (singleton)"""
    global _global_obfuscator
    if _global_obfuscator is None:
        _global_obfuscator = TrafficObfuscator()
    return _global_obfuscator


def obfuscate(packet: bytes) -> bytes:
    """Global function to obfuscate packet"""
    return get_obfuscator().obfuscate(packet)


def deobfuscate(packet: bytes) -> bytes:
    """Global function to deobfuscate packet"""
    return get_obfuscator().deobfuscate(packet)


def generate_session_key(shared_secret: bytes = None) -> bytes:
    """Global function to generate session key"""
    return get_obfuscator().generate_session_key(shared_secret)


if __name__ == "__main__":
    # Test traffic obfuscation functionality
    print("🧪 Testing KyberLink Traffic Obfuscation (Stealth Mode)...")
    
    # Create obfuscator instance
    obfuscator = TrafficObfuscator()
    
    # Generate session key
    session_key = obfuscator.generate_session_key()
    print(f"Session key: {session_key.hex()[:16]}...")
    
    # Test packet obfuscation
    test_packet = b"Hello from KyberLink VPN! This is a test encrypted packet with quantum-resistant security."
    print(f"\n📦 Original packet: {len(test_packet)} bytes")
    print(f"Content: {test_packet[:50]}...")
    
    # Obfuscate packet
    obfuscated = obfuscator.obfuscate(test_packet)
    print(f"\n🕵️  Obfuscated packet: {len(obfuscated)} bytes")
    print(f"Disguised content: {obfuscated[:50]}...")
    print(f"Hex dump: {obfuscated[:32].hex()}")
    
    # Deobfuscate packet
    try:
        deobfuscated = obfuscator.deobfuscate(obfuscated)
        print(f"\n🔓 Deobfuscated packet: {len(deobfuscated)} bytes")
        print(f"Recovered content: {deobfuscated[:50]}...")
        
        # Verify integrity
        if deobfuscated == test_packet:
            print("✅ Obfuscation/Deobfuscation successful - data integrity maintained!")
        else:
            print("❌ Data integrity check failed!")
            
    except Exception as e:
        print(f"❌ Deobfuscation test failed: {e}")
    
    # Test multiple packets with different sizes
    print(f"\n🔄 Testing variable packet sizes...")
    for size in [64, 256, 512, 1024, 1500]:
        test_data = secrets.token_bytes(size)
        obfuscated = obfuscator.obfuscate(test_data)
        deobfuscated = obfuscator.deobfuscate(obfuscated)
        
        if deobfuscated == test_data:
            print(f"✅ Size {size} bytes: OK (obfuscated to {len(obfuscated)} bytes)")
        else:
            print(f"❌ Size {size} bytes: FAILED")
    
    print("\n🎉 Traffic obfuscation testing completed!")