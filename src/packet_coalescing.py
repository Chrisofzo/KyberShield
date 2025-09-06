#!/usr/bin/env python3
"""
KyberLink VPN - Packet Coalescing Engine
========================================

High-performance packet coalescing and fragmentation system for UDP optimization.
Reduces network overhead and improves latency through intelligent packet merging.
"""

import struct
import time
import threading
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict

@dataclass
class CoalescedPacket:
    """Represents a packet ready for coalescing"""
    data: bytes
    timestamp: float
    client_addr: Tuple[str, int]
    packet_id: int

@dataclass
class FragmentInfo:
    """Information about a fragmented packet"""
    fragment_id: bytes
    total_fragments: int
    received_fragments: Dict[int, bytes]
    timestamp: float
    complete: bool = False

class PacketCoalescingEngine:
    """
    High-Performance Packet Coalescing Engine
    
    Features:
    - 5ms coalescing window for optimal batching
    - MTU-aware fragmentation (1200 byte safe limit)
    - Application-level reassembly with timeout
    - Performance metrics and statistics tracking
    - Thread-safe operation for concurrent clients
    """
    
    def __init__(self, coalescing_window_ms=5, max_mtu=1200, fragment_timeout=30):
        self.coalescing_window_ms = coalescing_window_ms
        self.max_mtu = max_mtu
        self.fragment_timeout = fragment_timeout
        
        # Coalescing queues per client
        self.pending_packets: Dict[Tuple[str, int], List[CoalescedPacket]] = defaultdict(list)
        self.client_timers: Dict[Tuple[str, int], threading.Timer] = {}
        self.packet_id_counter = 0
        
        # Fragmentation management
        self.fragments: Dict[bytes, FragmentInfo] = {}  # fragment_id -> FragmentInfo
        self.fragment_lock = threading.RLock()
        
        # Performance statistics
        self.stats = {
            'total_packets_received': 0,
            'packets_coalesced': 0,
            'coalesced_datagrams_sent': 0,
            'fragments_created': 0,
            'fragments_reassembled': 0,
            'average_packet_size': 0,
            'coalescing_ratio': 0,
            'fragmentation_ratio': 0,
            'timeout_fragments': 0
        }
        
        self.lock = threading.RLock()
        
        # Callback for sending coalesced packets
        self.send_callback = None
        
        print("[Coalescing] 🚀 Packet Coalescing Engine initialized")
        print(f"[Coalescing]   • Coalescing window: {coalescing_window_ms}ms")
        print(f"[Coalescing]   • MTU limit: {max_mtu} bytes")
        print(f"[Coalescing]   • Fragment timeout: {fragment_timeout}s")
    
    def set_send_callback(self, callback):
        """Set callback function for sending coalesced packets"""
        self.send_callback = callback
    
    def get_next_packet_id(self) -> int:
        """Get next packet ID for coalescing"""
        with self.lock:
            self.packet_id_counter += 1
            return self.packet_id_counter
    
    def queue_packet(self, packet_data: bytes, client_addr: Tuple[str, int]):
        """
        Queue packet for coalescing
        
        Args:
            packet_data: Raw packet bytes to queue
            client_addr: Client address for routing
        """
        with self.lock:
            packet_id = self.get_next_packet_id()
            coalesced_packet = CoalescedPacket(
                data=packet_data,
                timestamp=time.time(),
                client_addr=client_addr,
                packet_id=packet_id
            )
            
            self.pending_packets[client_addr].append(coalesced_packet)
            self.stats['total_packets_received'] += 1
            
            # Set or reset timer for this client
            if client_addr in self.client_timers:
                self.client_timers[client_addr].cancel()
            
            timer = threading.Timer(
                self.coalescing_window_ms / 1000.0,
                self._flush_client_packets,
                args=[client_addr]
            )
            timer.start()
            self.client_timers[client_addr] = timer
    
    def _flush_client_packets(self, client_addr: Tuple[str, int]):
        """Flush all pending packets for a client"""
        with self.lock:
            packets = self.pending_packets.get(client_addr, [])
            if not packets:
                return
            
            # Clear pending packets
            self.pending_packets[client_addr] = []
            if client_addr in self.client_timers:
                del self.client_timers[client_addr]
            
            # Create coalesced datagram
            coalesced_data = self._create_coalesced_datagram(packets)
            
            # Check if fragmentation needed
            if len(coalesced_data) > self.max_mtu:
                fragments = self._fragment_packet(coalesced_data)
                for fragment in fragments:
                    if self.send_callback:
                        self.send_callback(fragment, client_addr)
                self.stats['fragments_created'] += len(fragments)
            else:
                # Send as single datagram
                if self.send_callback:
                    self.send_callback(coalesced_data, client_addr)
            
            # Update statistics
            self.stats['packets_coalesced'] += len(packets)
            self.stats['coalesced_datagrams_sent'] += 1
            self._update_statistics()
    
    def _create_coalesced_datagram(self, packets: List[CoalescedPacket]) -> bytes:
        """
        Create coalesced datagram with format: [count:2][len1:2][packet1][len2:2][packet2]...
        
        Args:
            packets: List of packets to coalesce
            
        Returns:
            Coalesced datagram bytes
        """
        if not packets:
            return b''
        
        # Header: packet count (2 bytes)
        datagram = struct.pack('!H', len(packets))
        
        # Add each packet with length prefix
        for packet in packets:
            packet_len = len(packet.data)
            datagram += struct.pack('!H', packet_len)  # Length (2 bytes)
            datagram += packet.data  # Packet data
        
        return datagram
    
    def _fragment_packet(self, data: bytes) -> List[bytes]:
        """
        Fragment large packet at application level
        
        Args:
            data: Large packet to fragment
            
        Returns:
            List of fragment packets
        """
        if len(data) <= self.max_mtu:
            return [data]
        
        # Generate unique fragment ID
        import secrets
        fragment_id = secrets.token_bytes(8)
        
        # Calculate fragment size (accounting for headers)
        header_size = 8 + 2 + 2  # fragment_id + fragment_num + total_fragments
        fragment_payload_size = self.max_mtu - header_size
        
        fragments = []
        offset = 0
        fragment_num = 0
        total_fragments = (len(data) + fragment_payload_size - 1) // fragment_payload_size
        
        while offset < len(data):
            # Extract fragment payload
            end_offset = min(offset + fragment_payload_size, len(data))
            payload = data[offset:end_offset]
            
            # Create fragment: [fragment_id:8][fragment_num:2][total_fragments:2][payload]
            fragment = (
                fragment_id + 
                struct.pack('!H', fragment_num) +
                struct.pack('!H', total_fragments) +
                payload
            )
            
            fragments.append(fragment)
            offset = end_offset
            fragment_num += 1
        
        return fragments
    
    def process_received_packet(self, packet_data: bytes) -> List[bytes]:
        """
        Process received packet - handle coalesced datagrams and fragments
        
        Args:
            packet_data: Raw received packet
            
        Returns:
            List of individual packets (empty if fragment incomplete)
        """
        # Check if this is a fragment
        if len(packet_data) >= 12:  # Minimum fragment header size
            try:
                fragment_id = packet_data[:8]
                fragment_num = struct.unpack('!H', packet_data[8:10])[0]
                total_fragments = struct.unpack('!H', packet_data[10:12])[0]
                payload = packet_data[12:]
                
                # This looks like a fragment
                if fragment_num < total_fragments:
                    reassembled = self._reassemble_fragment(
                        fragment_id, fragment_num, total_fragments, payload
                    )
                    if reassembled:
                        # Fragment is complete, process as coalesced datagram
                        return self._split_coalesced_datagram(reassembled)
                    else:
                        return []  # Fragment incomplete
            except:
                pass  # Not a fragment, continue to coalesced processing
        
        # Process as coalesced datagram
        return self._split_coalesced_datagram(packet_data)
    
    def _reassemble_fragment(self, fragment_id: bytes, fragment_num: int, 
                           total_fragments: int, payload: bytes) -> Optional[bytes]:
        """
        Reassemble fragmented packet
        
        Returns:
            Complete packet if all fragments received, None otherwise
        """
        with self.fragment_lock:
            if fragment_id not in self.fragments:
                self.fragments[fragment_id] = FragmentInfo(
                    fragment_id=fragment_id,
                    total_fragments=total_fragments,
                    received_fragments={},
                    timestamp=time.time()
                )
            
            fragment_info = self.fragments[fragment_id]
            fragment_info.received_fragments[fragment_num] = payload
            
            # Check if complete
            if len(fragment_info.received_fragments) == total_fragments:
                # Reassemble in order
                reassembled = b''
                for i in range(total_fragments):
                    if i in fragment_info.received_fragments:
                        reassembled += fragment_info.received_fragments[i]
                    else:
                        return None  # Missing fragment
                
                # Mark complete and clean up
                fragment_info.complete = True
                del self.fragments[fragment_id]
                
                self.stats['fragments_reassembled'] += 1
                return reassembled
            
            return None
    
    def _split_coalesced_datagram(self, datagram: bytes) -> List[bytes]:
        """
        Split coalesced datagram back into individual packets
        
        Args:
            datagram: Coalesced datagram to split
            
        Returns:
            List of individual packet bytes
        """
        if len(datagram) < 2:
            return [datagram]  # Too small to be coalesced
        
        try:
            # Read packet count
            packet_count = struct.unpack('!H', datagram[:2])[0]
            offset = 2
            packets = []
            
            for _ in range(packet_count):
                if offset + 2 > len(datagram):
                    break
                
                # Read packet length
                packet_len = struct.unpack('!H', datagram[offset:offset+2])[0]
                offset += 2
                
                if offset + packet_len > len(datagram):
                    break
                
                # Extract packet
                packet = datagram[offset:offset+packet_len]
                packets.append(packet)
                offset += packet_len
            
            return packets if packets else [datagram]
            
        except:
            # Not a coalesced datagram, return as-is
            return [datagram]
    
    def _update_statistics(self):
        """Update performance statistics"""
        total_packets = self.stats['total_packets_received']
        if total_packets > 0:
            self.stats['coalescing_ratio'] = self.stats['packets_coalesced'] / total_packets
            
        fragments_created = self.stats['fragments_created']
        datagrams_sent = self.stats['coalesced_datagrams_sent']
        if datagrams_sent > 0:
            self.stats['fragmentation_ratio'] = fragments_created / datagrams_sent
    
    def cleanup_expired_fragments(self):
        """Remove expired fragment reassembly attempts"""
        with self.fragment_lock:
            current_time = time.time()
            expired_fragments = []
            
            for fragment_id, fragment_info in self.fragments.items():
                if current_time - fragment_info.timestamp > self.fragment_timeout:
                    expired_fragments.append(fragment_id)
            
            for fragment_id in expired_fragments:
                del self.fragments[fragment_id]
                self.stats['timeout_fragments'] += 1
    
    def get_performance_stats(self) -> dict:
        """Get comprehensive performance statistics"""
        with self.lock:
            # Calculate average packet size
            total_received = self.stats['total_packets_received']
            total_coalesced = self.stats['packets_coalesced']
            
            stats = self.stats.copy()
            stats.update({
                'pending_packets': sum(len(packets) for packets in self.pending_packets.values()),
                'active_fragment_reassemblies': len(self.fragments),
                'coalescing_efficiency': f"{stats['coalescing_ratio']:.2%}" if total_received > 0 else "0%",
                'fragmentation_rate': f"{stats['fragmentation_ratio']:.2%}" if stats['coalesced_datagrams_sent'] > 0 else "0%"
            })
            
            return stats

# Global packet coalescing engine instance
_coalescing_engine = None

def get_packet_coalescing_engine() -> PacketCoalescingEngine:
    """Get global packet coalescing engine (singleton)"""
    global _coalescing_engine
    if _coalescing_engine is None:
        _coalescing_engine = PacketCoalescingEngine()
    return _coalescing_engine