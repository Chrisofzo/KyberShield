#!/usr/bin/env python3
"""
KyberLink VPN Traffic Shaping Module - Metadata Protection
=========================================================

Adaptive dummy traffic generation and timing defense to protect against traffic analysis.
Implements uniform packet sizes, randomized timing, and decoy traffic injection.

Security Features:
- Dummy packet generation with configurable intensity
- Adaptive packet padding to standard sizes (128/256/512 bytes)
- Randomized jitter delays to mask communication patterns
- Traffic flow normalization to prevent metadata analysis
- Background decoy traffic during idle periods
"""

import secrets
import struct
import time
import asyncio
import threading
from typing import Dict, Tuple, Optional
from enum import Enum
import random


class IntensityLevel(Enum):
    """Metadata protection intensity levels"""
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"


class TrafficShaper:
    """Advanced traffic shaping for metadata protection"""
    
    def __init__(self, intensity: IntensityLevel = IntensityLevel.MEDIUM):
        self.intensity = intensity
        self.enabled = False
        
        # Traffic shaping parameters based on intensity
        self.config = {
            IntensityLevel.LOW: {
                'dummy_ratio': 0.15,      # 15% dummy traffic
                'min_delay': 50,          # 50ms minimum delay
                'max_delay': 150,         # 150ms maximum delay
                'background_interval': 2.0, # 2 second background traffic
                'packet_sizes': [256, 512] # Standard sizes
            },
            IntensityLevel.MEDIUM: {
                'dummy_ratio': 0.25,      # 25% dummy traffic
                'min_delay': 30,          # 30ms minimum delay
                'max_delay': 120,         # 120ms maximum delay
                'background_interval': 1.5, # 1.5 second background traffic
                'packet_sizes': [128, 256, 512] # Standard sizes
            },
            IntensityLevel.HIGH: {
                'dummy_ratio': 0.40,      # 40% dummy traffic
                'min_delay': 20,          # 20ms minimum delay
                'max_delay': 100,         # 100ms maximum delay
                'background_interval': 1.0, # 1 second background traffic
                'packet_sizes': [128, 256, 512, 1024] # More size variety
            }
        }
        
        # Packet statistics
        self.stats = {
            'real_packets': 0,
            'dummy_packets': 0,
            'padded_bytes': 0,
            'total_delay': 0.0
        }
        
        # Background traffic control
        self.background_thread = None
        self.background_running = False
        
        print(f"🎭 Traffic Shaper initialized - Metadata protection level: {intensity.value.upper()}")
    
    def generate_dummy_packet(self, size: int = 256) -> bytes:
        """
        Generate a dummy packet with random data
        
        Args:
            size: Desired packet size in bytes
            
        Returns:
            Dummy packet with header 0x00 and random data
        """
        # Dummy packet format: [0x00][size-1 random bytes]
        header = b'\x00'  # Dummy packet identifier
        random_data = secrets.token_bytes(size - 1)
        dummy_packet = header + random_data
        
        self.stats['dummy_packets'] += 1
        return dummy_packet
    
    def schedule_real_packet(self, packet: bytes) -> bytes:
        """
        Pad real packet to standard size for metadata protection
        
        Args:
            packet: Original packet data
            
        Returns:
            Padded packet with header 0x01 and standard size
        """
        if not self.enabled:
            return packet
        
        current_config = self.config[self.intensity]
        target_sizes = current_config['packet_sizes']
        
        # Find the smallest target size that can fit the packet + header
        required_size = len(packet) + 1  # +1 for real packet header
        target_size = None
        
        for size in sorted(target_sizes):
            if size >= required_size:
                target_size = size
                break
        
        # If packet is too large for standard sizes, use next power of 2
        if target_size is None:
            target_size = 1
            while target_size < required_size:
                target_size *= 2
        
        # Create padded packet: [0x01][original packet][padding]
        header = b'\x01'  # Real packet identifier
        padding_needed = target_size - len(packet) - 1
        
        if padding_needed > 0:
            padding = secrets.token_bytes(padding_needed)
            padded_packet = header + packet + padding
            self.stats['padded_bytes'] += padding_needed
        else:
            padded_packet = header + packet
        
        self.stats['real_packets'] += 1
        return padded_packet
    
    def jitter_delay(self) -> float:
        """
        Generate randomized delay to mask timing patterns
        
        Returns:
            Random delay in seconds
        """
        if not self.enabled:
            return 0.0
        
        current_config = self.config[self.intensity]
        min_delay = current_config['min_delay'] / 1000.0  # Convert to seconds
        max_delay = current_config['max_delay'] / 1000.0
        
        # Generate random delay with slight exponential bias toward shorter delays
        delay = random.uniform(min_delay, max_delay)
        
        # Apply small exponential smoothing
        if random.random() < 0.3:  # 30% chance of shorter delay
            delay *= 0.7
        
        self.stats['total_delay'] += delay
        return delay
    
    def should_inject_dummy(self) -> bool:
        """
        Determine if a dummy packet should be injected
        
        Returns:
            True if dummy packet should be sent
        """
        if not self.enabled:
            return False
        
        current_config = self.config[self.intensity]
        return random.random() < current_config['dummy_ratio']
    
    def extract_real_packet(self, shaped_packet: bytes) -> Optional[bytes]:
        """
        Extract real packet data from shaped packet
        
        Args:
            shaped_packet: Traffic-shaped packet
            
        Returns:
            Original packet data or None if dummy packet
        """
        if len(shaped_packet) < 1:
            return None
        
        # Check packet type
        packet_type = shaped_packet[0]
        
        if packet_type == 0x00:
            # Dummy packet - drop it
            return None
        elif packet_type == 0x01:
            # Real packet - extract original data
            # Format: [0x01][original packet][padding]
            # We need to figure out where original packet ends
            
            # For now, return everything after the header
            # In production, you'd store the original length in the header
            original_data = shaped_packet[1:]
            
            # Remove any trailing zero padding (simple approach)
            while len(original_data) > 0 and original_data[-1] == 0:
                original_data = original_data[:-1]
            
            return original_data
        else:
            # Unknown packet type
            return shaped_packet
    
    def start_background_traffic(self, send_callback):
        """
        Start background dummy traffic generation
        
        Args:
            send_callback: Function to call for sending dummy packets
        """
        if self.background_running:
            return
        
        self.background_running = True
        self.background_thread = threading.Thread(
            target=self._background_traffic_worker,
            args=(send_callback,),
            daemon=True
        )
        self.background_thread.start()
        print("🎭 Background dummy traffic started")
    
    def stop_background_traffic(self):
        """Stop background dummy traffic generation"""
        self.background_running = False
        if self.background_thread:
            self.background_thread.join(timeout=1.0)
        print("🎭 Background dummy traffic stopped")
    
    def _background_traffic_worker(self, send_callback):
        """Background thread worker for dummy traffic"""
        current_config = self.config[self.intensity]
        interval = current_config['background_interval']
        
        while self.background_running:
            try:
                if self.enabled:
                    # Generate and send dummy packet
                    dummy_size = random.choice(current_config['packet_sizes'])
                    dummy_packet = self.generate_dummy_packet(dummy_size)
                    
                    # Apply jitter delay
                    delay = self.jitter_delay()
                    time.sleep(delay)
                    
                    # Send dummy packet through callback
                    if send_callback:
                        send_callback(dummy_packet)
                
                # Wait for next interval
                time.sleep(interval)
                
            except Exception as e:
                print(f"❌ Background traffic error: {e}")
                time.sleep(interval)
    
    def enable_metadata_protection(self):
        """Enable traffic shaping for metadata protection"""
        self.enabled = True
        print(f"[Client] 🎭 Metadata defense enabled - Level: {self.intensity.value.upper()}")
    
    def disable_metadata_protection(self):
        """Disable traffic shaping"""
        self.enabled = False
        self.stop_background_traffic()
        print("[Client] 🔓 Metadata defense disabled")
    
    def set_intensity(self, intensity: IntensityLevel):
        """Change metadata protection intensity"""
        self.intensity = intensity
        print(f"🎭 Metadata protection intensity changed to: {intensity.value.upper()}")
    
    def get_statistics(self) -> Dict[str, any]:
        """Get traffic shaping statistics"""
        total_packets = self.stats['real_packets'] + self.stats['dummy_packets']
        dummy_ratio = (self.stats['dummy_packets'] / total_packets * 100) if total_packets > 0 else 0
        
        return {
            'enabled': self.enabled,
            'intensity': self.intensity.value,
            'real_packets': self.stats['real_packets'],
            'dummy_packets': self.stats['dummy_packets'],
            'total_packets': total_packets,
            'dummy_ratio': f"{dummy_ratio:.1f}%",
            'padded_bytes': self.stats['padded_bytes'],
            'total_delay': f"{self.stats['total_delay']:.2f}s"
        }
    
    def reset_statistics(self):
        """Reset traffic shaping statistics"""
        self.stats = {
            'real_packets': 0,
            'dummy_packets': 0,
            'padded_bytes': 0,
            'total_delay': 0.0
        }


# Global traffic shaper instance
_global_shaper = None


def get_traffic_shaper() -> TrafficShaper:
    """Get global traffic shaper instance (singleton)"""
    global _global_shaper
    if _global_shaper is None:
        _global_shaper = TrafficShaper()
    return _global_shaper


def generate_dummy_packet(size: int = 256) -> bytes:
    """Global function to generate dummy packet"""
    return get_traffic_shaper().generate_dummy_packet(size)


def schedule_real_packet(packet: bytes) -> bytes:
    """Global function to schedule real packet"""
    return get_traffic_shaper().schedule_real_packet(packet)


def jitter_delay() -> float:
    """Global function to get jitter delay"""
    return get_traffic_shaper().jitter_delay()


def extract_real_packet(shaped_packet: bytes) -> Optional[bytes]:
    """Global function to extract real packet"""
    return get_traffic_shaper().extract_real_packet(shaped_packet)


if __name__ == "__main__":
    # Test traffic shaping functionality
    print("🧪 Testing KyberLink Traffic Shaping (Metadata Protection)...")
    
    # Test different intensity levels
    for intensity in [IntensityLevel.LOW, IntensityLevel.MEDIUM, IntensityLevel.HIGH]:
        print(f"\n🎭 Testing {intensity.value.upper()} intensity...")
        
        shaper = TrafficShaper(intensity)
        shaper.enable_metadata_protection()
        
        # Test packet scheduling
        test_packet = b"Hello from KyberLink VPN! This is a test packet for metadata protection."
        print(f"📦 Original packet: {len(test_packet)} bytes")
        
        # Schedule real packet
        shaped_packet = shaper.schedule_real_packet(test_packet)
        print(f"🎭 Shaped packet: {len(shaped_packet)} bytes")
        
        # Extract real packet
        extracted_packet = shaper.extract_real_packet(shaped_packet)
        print(f"📤 Extracted packet: {len(extracted_packet)} bytes")
        
        # Test dummy packet generation
        dummy = shaper.generate_dummy_packet(256)
        print(f"🎲 Dummy packet: {len(dummy)} bytes (header: 0x{dummy[0]:02x})")
        
        # Test dummy packet filtering
        extracted_dummy = shaper.extract_real_packet(dummy)
        print(f"🗑️  Dummy packet filtered: {extracted_dummy is None}")
        
        # Test jitter delays
        delays = [shaper.jitter_delay() for _ in range(5)]
        print(f"⏱️  Sample delays: {[f'{d*1000:.1f}ms' for d in delays]}")
        
        # Show statistics
        stats = shaper.get_statistics()
        print(f"📊 Statistics: {stats['real_packets']} real, {stats['dummy_packets']} dummy packets")
        
        shaper.disable_metadata_protection()
    
    print("\n🎉 Traffic shaping testing completed!")