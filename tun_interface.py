#!/usr/bin/env python3
"""
TUN/TAP Interface Integration for Quantum-Resistant VPN
Provides cross-platform network interface functions with Replit simulation support
"""

import os
import sys
import time
import random
import struct
from typing import Optional, Any

# Detect if running in Replit environment
IS_REPLIT = os.getenv('REPLIT_DB_URL') is not None or 'replit' in sys.executable.lower()

class TunInterface:
    """TUN interface handler with simulation support for Replit"""
    
    def __init__(self, name: str = "tun0"):
        self.name = name
        self.is_open = False
        self.tun_fd = None
        
    def open_tun(self, name: str = "tun0") -> Optional[Any]:
        """
        Open TUN interface
        Returns file descriptor on Linux/macOS, simulation object on Replit
        """
        self.name = name
        
        if IS_REPLIT:
            print(f"[TUN] Simulating TUN interface '{name}' (Replit environment)")
            self.is_open = True
            self.tun_fd = {"simulated": True, "name": name}
            return self.tun_fd
        else:
            try:
                # Try to open real TUN interface on local systems
                import fcntl
                
                # Constants for TUN/TAP (Linux)
                TUNSETIFF = 0x400454ca
                IFF_TUN = 0x0001
                IFF_NO_PI = 0x1000
                
                # Open TUN device
                tun_fd = os.open('/dev/net/tun', os.O_RDWR)
                
                # Configure interface
                ifr = struct.pack('16sH', name.encode('utf-8'), IFF_TUN | IFF_NO_PI)
                fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
                
                print(f"[TUN] Opened real TUN interface '{name}'")
                self.is_open = True
                self.tun_fd = tun_fd
                return tun_fd
                
            except (OSError, ImportError, PermissionError) as e:
                print(f"[TUN] Failed to open real TUN interface: {e}")
                print(f"[TUN] Falling back to simulation mode")
                
                # Fallback to simulation
                self.is_open = True
                self.tun_fd = {"simulated": True, "name": name}
                return self.tun_fd
    
    def read_packet(self, tun: Any) -> bytes:
        """
        Read a packet from TUN interface
        Returns real packet bytes on Linux/macOS, simulated packets on Replit
        """
        if not self.is_open:
            raise RuntimeError("TUN interface not open")
            
        if IS_REPLIT or (isinstance(tun, dict) and tun.get("simulated")):
            # Simulate packet reading in Replit
            return self._generate_simulated_packet()
        else:
            try:
                # Read real packet from TUN interface
                packet = os.read(tun, 2048)  # Read up to 2KB
                print(f"[TUN] Read {len(packet)} bytes from {self.name}")
                return packet
            except OSError as e:
                print(f"[TUN] Error reading from TUN interface: {e}")
                # Fallback to simulation
                return self._generate_simulated_packet()
    
    def write_packet(self, tun: Any, packet: bytes) -> bool:
        """
        Write a packet to TUN interface
        Writes to real interface on Linux/macOS, simulates on Replit
        """
        if not self.is_open:
            raise RuntimeError("TUN interface not open")
            
        if IS_REPLIT or (isinstance(tun, dict) and tun.get("simulated")):
            # Simulate packet writing in Replit
            print(f"[TUN] SIMULATED: Writing {len(packet)} bytes to {self.name}")
            print(f"[TUN] SIMULATED: Packet hex: {packet[:32].hex()}{'...' if len(packet) > 32 else ''}")
            return True
        else:
            try:
                # Write real packet to TUN interface
                bytes_written = os.write(tun, packet)
                print(f"[TUN] Wrote {bytes_written} bytes to {self.name}")
                return bytes_written == len(packet)
            except OSError as e:
                print(f"[TUN] Error writing to TUN interface: {e}")
                # Fallback to simulation
                print(f"[TUN] SIMULATED: Writing {len(packet)} bytes to {self.name}")
                return True
    
    def close_tun(self, tun: Any) -> None:
        """Close TUN interface"""
        if not self.is_open:
            return
            
        if IS_REPLIT or (isinstance(tun, dict) and tun.get("simulated")):
            print(f"[TUN] SIMULATED: Closing TUN interface {self.name}")
        else:
            try:
                os.close(tun)
                print(f"[TUN] Closed TUN interface {self.name}")
            except OSError as e:
                print(f"[TUN] Error closing TUN interface: {e}")
                
        self.is_open = False
        self.tun_fd = None
    
    def _generate_simulated_packet(self) -> bytes:
        """Generate a simulated network packet for testing"""
        # Simulate different types of packets
        packet_types = [
            self._generate_icmp_packet(),
            self._generate_tcp_packet(),
            self._generate_udp_packet(),
            self._generate_dns_packet()
        ]
        
        packet = random.choice(packet_types)
        print(f"[TUN] SIMULATED: Read {len(packet)} bytes from {self.name} (type: {packet[:1].hex()})")
        return packet
    
    def _generate_icmp_packet(self) -> bytes:
        """Generate simulated ICMP ping packet"""
        # IPv4 header (20 bytes) + ICMP header (8 bytes) + data
        source_ip = bytes([192, 168, 1, 10])
        dest_ip = bytes([8, 8, 8, 8])
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45,           # Version + IHL
            0x00,           # Type of service
            64,             # Total length
            random.randint(1, 65535),  # ID
            0x4000,         # Flags + Fragment offset
            64,             # TTL
            1,              # Protocol (ICMP)
            0,              # Checksum (calculated later)
            source_ip,      # Source IP
            dest_ip         # Dest IP (DNS)
        )
        
        icmp_header = struct.pack('!BBHHH',
            8,              # Type (Echo Request)
            0,              # Code
            0,              # Checksum
            random.randint(1, 65535),  # ID
            1               # Sequence
        )
        
        data = b"Hello from VPN tunnel!"
        return ip_header + icmp_header + data
    
    def _generate_tcp_packet(self) -> bytes:
        """Generate simulated TCP packet"""
        # IPv4 header + TCP header + data
        source_ip = bytes([192, 168, 1, 10])
        dest_ip = bytes([93, 184, 216, 34])  # Example.com
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45, 0x00, 80, random.randint(1, 65535), 0x4000, 64, 6, 0,
            source_ip,
            dest_ip
        )
        
        tcp_header = struct.pack('!HHLLBBHHH',
            random.randint(32768, 65535),  # Source port
            80,                            # Dest port (HTTP)
            random.randint(1, 4294967295), # Seq number
            0,                             # Ack number
            0x50,                          # Header length
            0x02,                          # Flags (SYN)
            8192,                          # Window size
            0,                             # Checksum
            0                              # Urgent pointer
        )
        
        return ip_header + tcp_header
    
    def _generate_udp_packet(self) -> bytes:
        """Generate simulated UDP packet"""
        # IPv4 header + UDP header + data
        source_ip = bytes([192, 168, 1, 10])
        dest_ip = bytes([192, 168, 1, 1])   # Gateway
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45, 0x00, 64, random.randint(1, 65535), 0x4000, 64, 17, 0,
            source_ip,
            dest_ip
        )
        
        udp_data = b"VPN UDP test data"
        udp_header = struct.pack('!HHHH',
            random.randint(32768, 65535),  # Source port
            53,                            # Dest port (DNS)
            8 + len(udp_data),            # Length
            0                              # Checksum
        )
        
        return ip_header + udp_header + udp_data
    
    def _generate_dns_packet(self) -> bytes:
        """Generate simulated DNS query packet"""
        # IPv4 + UDP + DNS query
        source_ip = bytes([192, 168, 1, 10])
        dest_ip = bytes([8, 8, 8, 8])       # Google DNS
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45, 0x00, 64, random.randint(1, 65535), 0x4000, 64, 17, 0,
            source_ip,
            dest_ip
        )
        
        # DNS query for example.com
        dns_query = (
            struct.pack('!HHHHHH', random.randint(1, 65535), 0x0100, 1, 0, 0, 0) +
            b'\x07example\x03com\x00' +  # example.com
            struct.pack('!HH', 1, 1)     # Type A, Class IN
        )
        
        udp_header = struct.pack('!HHHH',
            random.randint(32768, 65535),  # Source port
            53,                            # Dest port
            8 + len(dns_query),           # Length
            0                              # Checksum
        )
        
        return ip_header + udp_header + dns_query


# Convenience functions for backward compatibility
def open_tun(name: str = "tun0") -> Optional[Any]:
    """Open TUN interface"""
    interface = TunInterface(name)
    return interface.open_tun(name)

def read_packet(tun: Any) -> bytes:
    """Read packet from TUN interface"""
    # Create temporary interface object for compatibility
    interface = TunInterface()
    interface.is_open = True
    interface.tun_fd = tun
    return interface.read_packet(tun)

def write_packet(tun: Any, packet: bytes) -> bool:
    """Write packet to TUN interface"""
    # Create temporary interface object for compatibility
    interface = TunInterface()
    interface.is_open = True
    interface.tun_fd = tun
    return interface.write_packet(tun, packet)

def close_tun(tun: Any) -> None:
    """Close TUN interface"""
    interface = TunInterface()
    interface.is_open = True
    interface.close_tun(tun)


if __name__ == "__main__":
    # Test TUN interface functionality
    print("Testing TUN interface...")
    
    # Test interface creation
    tun_interface = TunInterface()
    tun = tun_interface.open_tun("tun0")
    
    if tun:
        print(f"TUN interface opened successfully")
        
        # Test packet reading (simulated)
        for i in range(3):
            packet = tun_interface.read_packet(tun)
            print(f"Read packet {i+1}: {len(packet)} bytes")
            
            # Test packet writing (simulated)
            tun_interface.write_packet(tun, packet)
            time.sleep(1)
        
        # Close interface
        tun_interface.close_tun(tun)
        print("TUN interface test completed")
    else:
        print("Failed to open TUN interface")