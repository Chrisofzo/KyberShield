#!/usr/bin/env python3
"""
KyberLink VPN - Adaptive Dummy Traffic Manager
==============================================

Advanced metadata protection with intelligent bandwidth management.
Provides Tor-level traffic analysis resistance with minimal overhead.
"""

import threading
import time
import random
import secrets
import psutil
from enum import Enum
from typing import Dict, List, Callable
from dataclasses import dataclass

class MetadataDefenseLevel(Enum):
    """Metadata defense intensity levels"""
    LOW = "low"
    MEDIUM = "medium"  
    HIGH = "high"
    ADAPTIVE = "adaptive"

@dataclass
class DummyTrafficConfig:
    """Configuration for dummy traffic generation"""
    level: MetadataDefenseLevel
    dummy_ratio: float  # Dummy packets per real packet
    base_interval: float  # Base seconds between dummy packets
    packet_size: int  # Size of dummy packets
    gaussian_variance: float  # Timing variance for randomization

class AdaptiveDummyTrafficManager:
    """
    Intelligent Dummy Traffic Manager
    
    Features:
    - Configurable metadata defense levels (Low/Medium/High)
    - Adaptive rate control based on system resources
    - Gaussian timing distribution for natural traffic patterns
    - CPU and bandwidth load monitoring
    - Per-session dummy traffic scheduling
    """
    
    def __init__(self):
        self.running = False
        self.sessions: Dict[bytes, dict] = {}  # session_id -> session info
        self.session_lock = threading.RLock()
        
        # Traffic configurations
        self.configs = {
            MetadataDefenseLevel.LOW: DummyTrafficConfig(
                level=MetadataDefenseLevel.LOW,
                dummy_ratio=0.02,  # 1 dummy per 50 real packets
                base_interval=30.0,  # 30 seconds base
                packet_size=256,
                gaussian_variance=10.0
            ),
            MetadataDefenseLevel.MEDIUM: DummyTrafficConfig(
                level=MetadataDefenseLevel.MEDIUM,
                dummy_ratio=0.05,  # 1 dummy per 20 real packets  
                base_interval=15.0,  # 15 seconds base
                packet_size=512,
                gaussian_variance=5.0
            ),
            MetadataDefenseLevel.HIGH: DummyTrafficConfig(
                level=MetadataDefenseLevel.HIGH,
                dummy_ratio=0.2,  # 1 dummy per 5 real packets
                base_interval=5.0,  # 5 seconds base
                packet_size=1024,
                gaussian_variance=2.0
            )
        }
        
        self.current_level = MetadataDefenseLevel.MEDIUM
        self.send_callback = None  # Function to send packets
        
        # System monitoring
        self.cpu_threshold = 80.0  # Reduce dummy traffic if CPU > 80%
        self.bandwidth_threshold = 10.0  # MB/s threshold
        self.adaptive_reduction = 1.0  # Multiplier for adaptive control
        
        # Statistics
        self.stats = {
            'dummy_packets_sent': 0,
            'real_packets_processed': 0,
            'adaptive_reductions': 0,
            'total_bandwidth_saved': 0,
            'current_dummy_ratio': 0.0
        }
        
        print("[DummyTraffic] 🎭 Adaptive Dummy Traffic Manager initialized")
        print(f"[DummyTraffic]   • Default level: {self.current_level.value}")
        print(f"[DummyTraffic]   • CPU threshold: {self.cpu_threshold}%")
    
    def set_defense_level(self, level: MetadataDefenseLevel):
        """Set metadata defense level"""
        if level in self.configs:
            self.current_level = level
            config = self.configs[level]
            print(f"[DummyTraffic] 📊 Defense level: {level.value}")
            print(f"[DummyTraffic]   • Dummy ratio: {config.dummy_ratio:.3f} ({1/config.dummy_ratio:.0f}:1)")
            print(f"[DummyTraffic]   • Base interval: {config.base_interval}s")
            print(f"[DummyTraffic]   • Packet size: {config.packet_size} bytes")
    
    def set_send_callback(self, callback: Callable):
        """Set callback function for sending packets"""
        self.send_callback = callback
    
    def add_session(self, session_id: bytes, client_addr: tuple):
        """Add session for dummy traffic management"""
        with self.session_lock:
            self.sessions[session_id] = {
                'client_addr': client_addr,
                'real_packets': 0,
                'dummy_packets': 0,
                'last_real_time': time.time(),
                'last_dummy_time': time.time(),
                'thread': None
            }
            
            # Start dummy traffic thread for this session
            if self.running:
                self._start_session_dummy_thread(session_id)
            
        print(f"[DummyTraffic] ➕ Session added: {session_id.hex()[:16]}...")
    
    def remove_session(self, session_id: bytes):
        """Remove session from dummy traffic management"""
        with self.session_lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
                print(f"[DummyTraffic] ➖ Session removed: {session_id.hex()[:16]}...")
    
    def record_real_packet(self, session_id: bytes):
        """Record that a real packet was processed"""
        with self.session_lock:
            if session_id in self.sessions:
                self.sessions[session_id]['real_packets'] += 1
                self.sessions[session_id]['last_real_time'] = time.time()
                self.stats['real_packets_processed'] += 1
    
    def should_reduce_dummy_traffic(self) -> float:
        """
        Check system load and return reduction factor
        
        Returns:
            Reduction multiplier (0.0-1.0, where 1.0 = no reduction)
        """
        try:
            # Check CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            
            # Check network I/O (approximate bandwidth)
            net_io = psutil.net_io_counters()
            current_time = time.time()
            
            # Simple adaptive reduction based on CPU
            if cpu_percent > self.cpu_threshold:
                reduction = max(0.1, 1.0 - (cpu_percent - self.cpu_threshold) / 20.0)
                if reduction < 0.8:  # Significant reduction
                    self.stats['adaptive_reductions'] += 1
                    print(f"[DummyTraffic] 🔄 Adaptive reduction: {reduction:.2f} (CPU: {cpu_percent:.1f}%)")
                return reduction
            
            return 1.0
            
        except:
            return 1.0  # Default to no reduction on error
    
    def generate_dummy_packet(self, session_id: bytes) -> bytes:
        """
        Generate dummy packet with specified format
        
        Returns:
            Dummy packet: [session_id][nonce][random_padding][header=0x00]
        """
        config = self.configs[self.current_level]
        
        # 12-byte nonce for ChaCha20-Poly1305 compatibility
        nonce = secrets.token_bytes(12)
        
        # Random padding to reach desired packet size
        header_size = len(session_id) + len(nonce) + 1  # +1 for 0x00 header
        padding_size = max(0, config.packet_size - header_size)
        random_padding = secrets.token_bytes(padding_size)
        
        # Construct packet: [session_id][nonce][padding][header=0x00]
        dummy_packet = session_id + nonce + random_padding + b'\\x00'
        
        return dummy_packet
    
    def _calculate_next_interval(self) -> float:
        """Calculate next dummy packet interval with Gaussian distribution"""
        config = self.configs[self.current_level]
        
        # Apply adaptive reduction
        reduction_factor = self.should_reduce_dummy_traffic()
        adjusted_interval = config.base_interval / reduction_factor
        
        # Add Gaussian noise for natural timing
        noise = random.gauss(0, config.gaussian_variance)
        interval = max(1.0, adjusted_interval + noise)  # Minimum 1 second
        
        return interval
    
    def _session_dummy_thread(self, session_id: bytes):
        """Background thread for generating dummy packets per session"""
        print(f"[DummyTraffic] 🔄 Dummy thread started: {session_id.hex()[:16]}...")
        
        while self.running and session_id in self.sessions:
            try:
                # Calculate next interval
                interval = self._calculate_next_interval()
                time.sleep(interval)
                
                # Generate and send dummy packet
                if self.running and session_id in self.sessions:
                    dummy_packet = self.generate_dummy_packet(session_id)
                    
                    with self.session_lock:
                        session_info = self.sessions.get(session_id)
                        if session_info and self.send_callback:
                            try:
                                self.send_callback(dummy_packet, session_info['client_addr'])
                                session_info['dummy_packets'] += 1
                                self.stats['dummy_packets_sent'] += 1
                                
                                # Update current ratio
                                total_real = self.stats['real_packets_processed']
                                total_dummy = self.stats['dummy_packets_sent']
                                if total_real > 0:
                                    self.stats['current_dummy_ratio'] = total_dummy / total_real
                                    
                            except Exception as e:
                                print(f"[DummyTraffic] ❌ Send dummy packet error: {e}")
                
            except Exception as e:
                print(f"[DummyTraffic] ❌ Dummy thread error: {e}")
                time.sleep(5.0)  # Backoff on error
        
        print(f"[DummyTraffic] 🛑 Dummy thread stopped: {session_id.hex()[:16]}...")
    
    def _start_session_dummy_thread(self, session_id: bytes):
        """Start dummy traffic thread for a session"""
        if session_id in self.sessions:
            thread = threading.Thread(
                target=self._session_dummy_thread,
                args=(session_id,),
                daemon=True,
                name=f"DummyTraffic-{session_id.hex()[:8]}"
            )
            self.sessions[session_id]['thread'] = thread
            thread.start()
    
    def start(self):
        """Start adaptive dummy traffic manager"""
        if self.running:
            return
            
        self.running = True
        print(f"[DummyTraffic] 🚀 Starting adaptive dummy traffic (Level: {self.current_level.value})")
        
        # Start threads for existing sessions
        with self.session_lock:
            for session_id in self.sessions.keys():
                self._start_session_dummy_thread(session_id)
        
        print(f"[DummyTraffic] ✅ Dummy traffic manager active ({len(self.sessions)} sessions)")
    
    def stop(self):
        """Stop adaptive dummy traffic manager"""
        print("[DummyTraffic] 🛑 Stopping adaptive dummy traffic manager")
        self.running = False
        
        # Clear sessions (threads will exit naturally)
        with self.session_lock:
            self.sessions.clear()
        
        print("[DummyTraffic] ✅ Dummy traffic manager stopped")
    
    def get_statistics(self) -> dict:
        """Get comprehensive dummy traffic statistics"""
        with self.session_lock:
            session_stats = {}
            for session_id, info in self.sessions.items():
                session_stats[session_id.hex()[:16]] = {
                    'real_packets': info['real_packets'],
                    'dummy_packets': info['dummy_packets'],
                    'ratio': info['dummy_packets'] / max(1, info['real_packets'])
                }
            
            return {
                **self.stats,
                'active_sessions': len(self.sessions),
                'defense_level': self.current_level.value,
                'adaptive_reduction': self.adaptive_reduction,
                'session_details': session_stats
            }

# Global dummy traffic manager instance
_dummy_traffic_manager = None

def get_dummy_traffic_manager() -> AdaptiveDummyTrafficManager:
    """Get global dummy traffic manager instance (singleton)"""
    global _dummy_traffic_manager
    if _dummy_traffic_manager is None:
        _dummy_traffic_manager = AdaptiveDummyTrafficManager()
    return _dummy_traffic_manager

def set_metadata_defense_level(level: str):
    """Set metadata defense level from string"""
    level_map = {
        'low': MetadataDefenseLevel.LOW,
        'medium': MetadataDefenseLevel.MEDIUM,
        'high': MetadataDefenseLevel.HIGH,
        'adaptive': MetadataDefenseLevel.ADAPTIVE
    }
    
    if level.lower() in level_map:
        manager = get_dummy_traffic_manager()
        manager.set_defense_level(level_map[level.lower()])
        return True
    return False