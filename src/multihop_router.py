#!/usr/bin/env python3
"""
KyberLink VPN Multi-Hop Routing System
Enterprise-grade onion routing with quantum-resistant encryption
"""

import json
import socket
import struct
import secrets
import time
from typing import List, Dict, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, asdict

from .crypto_utils import QuantumResistantCrypto

class RoutingMode(Enum):
    SINGLE = "single"
    DOUBLE = "double"  
    TRIPLE = "triple"

@dataclass
class HopServer:
    """Represents a server in the routing path"""
    address: str
    port: int
    country: str
    is_relay: bool = True
    is_exit: bool = False

@dataclass
class RoutingPath:
    """Complete routing path configuration"""
    mode: RoutingMode
    hops: List[HopServer]
    session_keys: Dict[str, bytes]
    
    def __post_init__(self):
        if not hasattr(self, 'session_keys') or self.session_keys is None:
            self.session_keys = {}

class MultiHopRouter:
    """
    KyberLink Multi-Hop Routing System
    
    Implements onion-style routing with quantum-resistant encryption:
    - Single-hop: Direct connection to exit server
    - Double-hop: Client → Relay → Exit
    - Triple-hop: Client → Relay1 → Relay2 → Exit
    
    Each hop uses independent X25519 + ML-KEM-768 session keys
    """
    
    def __init__(self, routing_mode: RoutingMode = RoutingMode.SINGLE):
        self.routing_mode = routing_mode
        self.current_path: Optional[RoutingPath] = None
        self.hop_cryptos: Dict[str, QuantumResistantCrypto] = {}
        self.available_servers = self._load_server_list()
        
        print(f"[Client] 🌐 Multi-hop router initialized - Mode: {routing_mode.value}")
    
    def _load_server_list(self) -> List[HopServer]:
        """Load available KyberLink servers for routing"""
        # Production servers would be loaded from config/API
        return [
            HopServer("germany.kyberlink.vpn", 5555, "Germany", is_relay=True),
            HopServer("uk.kyberlink.vpn", 5555, "UK", is_relay=True),
            HopServer("usa.kyberlink.vpn", 5555, "USA", is_exit=True),
            HopServer("japan.kyberlink.vpn", 5555, "Japan", is_relay=True),
            HopServer("canada.kyberlink.vpn", 5555, "Canada", is_exit=True),
        ]
    
    def select_routing_path(self, exit_country: Optional[str] = None) -> RoutingPath:
        """
        Select optimal routing path based on mode and preferences
        
        Args:
            exit_country: Preferred exit server country
            
        Returns:
            RoutingPath with selected hops
        """
        available_relays = [s for s in self.available_servers if s.is_relay]
        available_exits = [s for s in self.available_servers if s.is_exit]
        
        # Select exit server
        if exit_country:
            exit_server = next((s for s in available_exits if s.country.lower() == exit_country.lower()), None)
            if not exit_server:
                exit_server = secrets.choice(available_exits)
        else:
            exit_server = secrets.choice(available_exits)
        
        # Build path based on routing mode
        if self.routing_mode == RoutingMode.SINGLE:
            hops = [exit_server]
        elif self.routing_mode == RoutingMode.DOUBLE:
            relay = secrets.choice([r for r in available_relays if r.country != exit_server.country])
            hops = [relay, exit_server]
        elif self.routing_mode == RoutingMode.TRIPLE:
            import random
            candidates = [r for r in available_relays if r.country != exit_server.country]
            relays = random.sample(candidates, min(2, len(candidates)))
            hops = [relays[0], relays[1], exit_server]
        else:
            raise ValueError(f"Invalid routing mode: {self.routing_mode}")
        
        # Mark final hop as exit
        hops[-1].is_exit = True
        for hop in hops[:-1]:
            hop.is_relay = True
            hop.is_exit = False
            
        path = RoutingPath(mode=self.routing_mode, hops=hops, session_keys={})
        
        # Log path selection
        path_str = " → ".join([f"{hop.country}" for hop in hops])
        print(f"[Client] Multi-hop path: {path_str}")
        
        return path
    
    def establish_path(self, path: RoutingPath) -> bool:
        """
        Establish encrypted sessions with all hops in the path
        
        Args:
            path: Selected routing path
            
        Returns:
            True if all hops successfully established
        """
        print(f"[Client] 🔐 Establishing {len(path.hops)}-hop encrypted path...")
        
        # Establish session with each hop
        for i, hop in enumerate(path.hops):
            hop_id = f"{hop.address}:{hop.port}"
            
            try:
                # Create quantum-resistant crypto for this hop
                crypto = QuantumResistantCrypto(is_server=False)
                
                # Simulate handshake (in production, would negotiate over network)
                # Each hop gets independent X25519 + ML-KEM-768 keys
                crypto.x25519_shared_secret = secrets.token_bytes(32)
                crypto.kyber_shared_secret = secrets.token_bytes(32)
                crypto._derive_session_key()
                
                self.hop_cryptos[hop_id] = crypto
                if crypto.session_key:
                    path.session_keys[hop_id] = crypto.session_key
                
                print(f"[Client]   ✅ Hop {i+1} ({hop.country}): Session established")
                
            except Exception as e:
                print(f"[Client]   ❌ Hop {i+1} ({hop.country}): Failed - {e}")
                return False
        
        self.current_path = path
        print(f"[Client] 🎉 Multi-hop path established successfully!")
        return True
    
    def create_onion_packet(self, data: bytes) -> bytes:
        """
        Create onion-encrypted packet for multi-hop routing
        
        Encrypts data in layers (onion encryption):
        1. Encrypt for exit server (innermost layer)
        2. Encrypt for relay servers (middle layers) 
        3. Encrypt for entry server (outermost layer)
        
        Args:
            data: Original packet data
            
        Returns:
            Onion-encrypted packet ready for transmission
        """
        if not self.current_path:
            raise ValueError("No routing path established")
        
        packet = data
        
        # Encrypt in reverse order (exit to entry)
        for i, hop in enumerate(reversed(self.current_path.hops)):
            hop_id = f"{hop.address}:{hop.port}"
            crypto = self.hop_cryptos[hop_id]
            
            # Add routing header for non-exit hops
            if not hop.is_exit:
                next_hop = self.current_path.hops[-(i)]  # Next hop in forward direction
                routing_header = struct.pack('>II', len(next_hop.address), next_hop.port)
                routing_header += next_hop.address.encode('utf-8')
                packet = routing_header + packet
            
            # Encrypt layer
            encrypted = crypto.encrypt_packet(packet.decode('utf-8') if isinstance(packet, bytes) else packet)
            packet = encrypted
            
            layer_num = len(self.current_path.hops) - i
            print(f"[Client] 🧅 Onion layer {layer_num}: Encrypted for {hop.country} ({len(encrypted)} bytes)")
        
        return packet
    
    def send_packet(self, data: bytes) -> bool:
        """
        Send packet through established multi-hop path
        
        Args:
            data: Data to send through the path
            
        Returns:
            True if packet sent successfully
        """
        if not self.current_path:
            print("[Client] ❌ No routing path established")
            return False
        
        try:
            # Create onion-encrypted packet
            onion_packet = self.create_onion_packet(data)
            
            # Send to first hop (entry server)
            entry_hop = self.current_path.hops[0]
            print(f"[Client] 📤 Sending onion packet to entry server: {entry_hop.country}")
            print(f"[Client]   Packet size: {len(onion_packet)} bytes")
            print(f"[Client]   Path: {' → '.join([h.country for h in self.current_path.hops])}")
            
            # In production, would send over actual network socket
            # For demo, simulate successful transmission
            return True
            
        except Exception as e:
            print(f"[Client] ❌ Failed to send packet: {e}")
            return False
    
    def get_routing_stats(self) -> Dict:
        """Get current routing statistics"""
        if not self.current_path:
            return {"status": "no_path"}
        
        return {
            "status": "active",
            "mode": self.current_path.mode.value,
            "hops": len(self.current_path.hops),
            "path": [{"country": h.country, "role": "exit" if h.is_exit else "relay"} 
                    for h in self.current_path.hops],
            "encryption_layers": len(self.hop_cryptos),
            "session_keys_active": len(self.current_path.session_keys)
        }

class MultiHopServer:
    """
    KyberLink Multi-Hop Server (Relay/Exit functionality)
    
    Handles:
    - Relay mode: Decrypt one layer and forward to next hop
    - Exit mode: Decrypt final layer and route to destination
    """
    
    def __init__(self, is_relay: bool = True, is_exit: bool = False):
        self.is_relay = is_relay
        self.is_exit = is_exit
        self.crypto = QuantumResistantCrypto(is_server=True)
        self.relay_stats = {"forwarded_packets": 0, "dropped_packets": 0}
        
        mode = "exit" if is_exit else "relay"
        print(f"[Server] 🌐 Multi-hop server initialized - Mode: {mode}")
    
    def process_onion_packet(self, packet: bytes) -> Tuple[Optional[bytes], Optional[Tuple[str, int]]]:
        """
        Process incoming onion packet
        
        Args:
            packet: Encrypted onion packet
            
        Returns:
            Tuple of (decrypted_data, next_hop_address) or (None, None) if error
        """
        try:
            # Decrypt outer layer
            decrypted_str = self.crypto.decrypt_packet(packet)
            if not decrypted_str:
                return None, None
            
            decrypted = decrypted_str.encode('utf-8') if isinstance(decrypted_str, str) else decrypted_str
            
            if self.is_exit:
                # Exit server: return final decrypted data
                print("[Server] 🎯 Exit server: Final decryption complete")
                return decrypted, None
            else:
                # Relay server: extract next hop info and forward
                if len(decrypted) < 8:
                    print("[Server] ❌ Invalid relay packet format")
                    self.relay_stats["dropped_packets"] += 1
                    return None, None
                
                # Parse routing header
                addr_len, port = struct.unpack('>II', decrypted[:8])
                if len(decrypted) < 8 + addr_len:
                    print("[Server] ❌ Incomplete routing header")
                    self.relay_stats["dropped_packets"] += 1
                    return None, None
                
                next_address = decrypted[8:8+addr_len].decode('utf-8')
                next_hop = (next_address, port)
                remaining_packet = decrypted[8+addr_len:]
                
                print(f"[Server] Forwarded encrypted packet to next hop: {next_address}:{port}")
                self.relay_stats["forwarded_packets"] += 1
                
                return remaining_packet, next_hop
                
        except Exception as e:
            print(f"[Server] ❌ Failed to process onion packet: {e}")
            self.relay_stats["dropped_packets"] += 1
            return None, None
    
    def get_relay_stats(self) -> Dict:
        """Get relay server statistics"""
        return {
            "mode": "exit" if self.is_exit else "relay",
            "forwarded_packets": self.relay_stats["forwarded_packets"],
            "dropped_packets": self.relay_stats["dropped_packets"],
            "total_packets": sum(self.relay_stats.values())
        }

def demo_multihop_routing():
    """Demonstrate multi-hop routing functionality"""
    print("🌐 KyberLink Multi-Hop Routing Demo")
    print("==================================")
    
    # Test all routing modes
    for mode in [RoutingMode.SINGLE, RoutingMode.DOUBLE, RoutingMode.TRIPLE]:
        print(f"\n🔄 Testing {mode.value.upper()} routing:")
        
        # Create router
        router = MultiHopRouter(routing_mode=mode)
        
        # Select and establish path
        path = router.select_routing_path(exit_country="USA")
        if router.establish_path(path):
            # Send test data
            test_data = b"KyberLink VPN multi-hop test packet"
            success = router.send_packet(test_data)
            
            # Show stats
            stats = router.get_routing_stats()
            print(f"   📊 Stats: {stats['hops']} hops, {stats['encryption_layers']} layers")
        
        time.sleep(1)
    
    print("\n🎉 Multi-hop routing demonstration complete!")

if __name__ == "__main__":
    demo_multihop_routing()