#!/usr/bin/env python3
"""
KyberLink VPN Pluggable Transport Layer
=======================================

Implements multiple transport protocols for VPN traffic:
- TCP: Standard TCP connection
- QUIC: Fast UDP-based protocol (simulated)  
- WebSocket (WSS): HTTPS mimicry over port 443
- Auto-fallback mechanism with audit logging
"""

import asyncio
import websockets
import ssl
import socket
import json
from typing import Optional, Dict, Any, Callable, Tuple
from enum import Enum
import secrets
import time

class TransportProtocol(Enum):
    """Supported transport protocols"""
    QUIC = "quic"
    TCP = "tcp" 
    WSS = "wss"  # WebSocket Secure

class PluggableTransport:
    """Pluggable transport system with fallback support"""
    
    def __init__(self, audit_callback: Optional[Callable] = None):
        self.current_protocol = None
        self.connection = None
        self.stats = {
            "connections_attempted": 0,
            "successful_connections": 0,
            "fallback_count": 0,
            "current_transport": None,
            "bytes_sent": 0,
            "bytes_received": 0
        }
        self.audit_callback = audit_callback
        
        # WebSocket server for WSS transport
        self.wss_server = None
        self.wss_clients = {}
        
        print("🔌 Pluggable Transport Layer initialized")
    
    async def connect_with_fallback(self, host: str, port: int = None, 
                                  preferred_protocol: TransportProtocol = TransportProtocol.QUIC,
                                  user_id: str = "unknown") -> bool:
        """
        Attempt connection with automatic fallback
        Order: QUIC → TCP → WebSocket-443
        """
        protocols_to_try = [
            TransportProtocol.QUIC,
            TransportProtocol.TCP, 
            TransportProtocol.WSS
        ]
        
        # Move preferred protocol to front
        if preferred_protocol in protocols_to_try:
            protocols_to_try.remove(preferred_protocol)
            protocols_to_try.insert(0, preferred_protocol)
        
        for protocol in protocols_to_try:
            try:
                self.stats["connections_attempted"] += 1
                
                if await self._try_connect(host, port, protocol):
                    self.current_protocol = protocol
                    self.stats["successful_connections"] += 1
                    self.stats["current_transport"] = protocol.value
                    
                    self._log_audit(user_id, "transport_connected", {
                        "protocol": protocol.value,
                        "host": host,
                        "port": port,
                        "fallback_attempts": self.stats["fallback_count"]
                    })
                    
                    print(f"🔌 Connected via {protocol.value.upper()} transport")
                    return True
                else:
                    self.stats["fallback_count"] += 1
                    self._log_audit(user_id, "transport_fallback", {
                        "failed_protocol": protocol.value,
                        "reason": "connection_failed"
                    })
                    
            except Exception as e:
                self.stats["fallback_count"] += 1
                self._log_audit(user_id, "transport_error", {
                    "protocol": protocol.value,
                    "error": str(e)
                })
                print(f"❌ {protocol.value.upper()} transport failed: {e}")
                continue
        
        print("❌ All transport protocols failed")
        return False
    
    async def _try_connect(self, host: str, port: Optional[int], 
                          protocol: TransportProtocol) -> bool:
        """Try connecting with specific protocol"""
        
        if protocol == TransportProtocol.QUIC:
            return await self._connect_quic(host, port or 443)
        elif protocol == TransportProtocol.TCP:
            return await self._connect_tcp(host, port or 5555)
        elif protocol == TransportProtocol.WSS:
            return await self._connect_wss(host, port or 443)
        
        return False
    
    async def _connect_quic(self, host: str, port: int) -> bool:
        """
        Attempt QUIC connection (simulated - would use aioquic in production)
        """
        try:
            # Simulate QUIC connection attempt
            await asyncio.sleep(0.1)  # Simulate connection time
            
            # For demo purposes, QUIC "fails" 70% of the time to show fallback
            import random
            if random.random() < 0.7:
                raise ConnectionError("QUIC not supported by network")
            
            # In production, would establish actual QUIC connection here
            self.connection = f"quic://{host}:{port}"
            return True
            
        except Exception as e:
            print(f"QUIC connection failed: {e}")
            return False
    
    async def _connect_tcp(self, host: str, port: int) -> bool:
        """Attempt TCP connection"""
        try:
            # Create TCP socket connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0
            )
            
            self.connection = {
                "type": "tcp",
                "reader": reader,
                "writer": writer,
                "host": host,
                "port": port
            }
            return True
            
        except Exception as e:
            print(f"TCP connection failed: {e}")
            return False
    
    async def _connect_wss(self, host: str, port: int) -> bool:
        """Attempt WebSocket Secure connection (HTTPS mimicry)"""
        try:
            # Create WSS connection URI
            uri = f"wss://{host}:{port}/kyberlink-tunnel"
            
            # SSL context for HTTPS mimicry
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE  # For development
            
            # Connect via WebSocket
            websocket = await asyncio.wait_for(
                websockets.connect(
                    uri,
                    ssl=ssl_context,
                    extra_headers={
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0",
                        "Origin": f"https://{host}",
                        "Sec-WebSocket-Protocol": "kyberlink-v1"
                    }
                ),
                timeout=10.0
            )
            
            self.connection = {
                "type": "wss",
                "websocket": websocket,
                "host": host,
                "port": port
            }
            return True
            
        except Exception as e:
            print(f"WebSocket connection failed: {e}")
            return False
    
    async def send_data(self, data: bytes) -> bool:
        """Send data through current transport"""
        if not self.connection:
            return False
        
        try:
            if self.current_protocol == TransportProtocol.TCP:
                writer = self.connection["writer"]
                # Send length prefix + data
                length = len(data)
                writer.write(length.to_bytes(4, 'big') + data)
                await writer.drain()
                
            elif self.current_protocol == TransportProtocol.WSS:
                websocket = self.connection["websocket"]
                await websocket.send(data)
                
            elif self.current_protocol == TransportProtocol.QUIC:
                # In production, would send via QUIC stream
                print(f"📡 QUIC send: {len(data)} bytes (simulated)")
            
            self.stats["bytes_sent"] += len(data)
            return True
            
        except Exception as e:
            print(f"❌ Send failed via {self.current_protocol.value}: {e}")
            return False
    
    async def receive_data(self) -> Optional[bytes]:
        """Receive data from current transport"""
        if not self.connection:
            return None
        
        try:
            if self.current_protocol == TransportProtocol.TCP:
                reader = self.connection["reader"]
                # Read length prefix
                length_data = await reader.readexactly(4)
                length = int.from_bytes(length_data, 'big')
                # Read actual data
                data = await reader.readexactly(length)
                
            elif self.current_protocol == TransportProtocol.WSS:
                websocket = self.connection["websocket"]
                data = await websocket.recv()
                if isinstance(data, str):
                    data = data.encode()
                
            elif self.current_protocol == TransportProtocol.QUIC:
                # In production, would receive via QUIC stream
                data = b"QUIC_DATA_PLACEHOLDER"
            
            self.stats["bytes_received"] += len(data)
            return data
            
        except Exception as e:
            print(f"❌ Receive failed via {self.current_protocol.value}: {e}")
            return None
    
    async def start_wss_server(self, port: int = 443):
        """Start WebSocket server for incoming WSS connections"""
        try:
            # SSL context for HTTPS mimicry
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain("kyberlink.crt", "kyberlink.key")
            
            # Start WebSocket server
            self.wss_server = await websockets.serve(
                self._handle_wss_client,
                "0.0.0.0",
                port,
                ssl=ssl_context,
                subprotocols=["kyberlink-v1"]
            )
            
            print(f"🔌 WebSocket server started on port {port} (HTTPS mimicry)")
            return True
            
        except FileNotFoundError:
            print("⚠️  SSL certificates not found, WSS server disabled")
            return False
        except Exception as e:
            print(f"❌ WSS server failed to start: {e}")
            return False
    
    async def _handle_wss_client(self, websocket, path):
        """Handle incoming WSS client connections"""
        client_id = secrets.token_hex(8)
        self.wss_clients[client_id] = websocket
        
        self._log_audit("server", "wss_client_connected", {
            "client_id": client_id,
            "path": path,
            "remote_addr": websocket.remote_address
        })
        
        try:
            async for message in websocket:
                # Handle incoming WSS messages
                if isinstance(message, str):
                    message = message.encode()
                
                # Process VPN packet (placeholder)
                print(f"📡 WSS received from {client_id}: {len(message)} bytes")
                
                # Echo back for testing (in production, route to VPN core)
                await websocket.send(f"ACK:{len(message)}".encode())
                
        except websockets.exceptions.ConnectionClosed:
            print(f"🔌 WSS client {client_id} disconnected")
        except Exception as e:
            print(f"❌ WSS client {client_id} error: {e}")
        finally:
            if client_id in self.wss_clients:
                del self.wss_clients[client_id]
            
            self._log_audit("server", "wss_client_disconnected", {
                "client_id": client_id
            })
    
    def disconnect(self):
        """Disconnect current transport"""
        if not self.connection:
            return
        
        try:
            if self.current_protocol == TransportProtocol.TCP:
                writer = self.connection["writer"]
                writer.close()
                
            elif self.current_protocol == TransportProtocol.WSS:
                websocket = self.connection["websocket"]
                asyncio.create_task(websocket.close())
                
            self.connection = None
            self.current_protocol = None
            print("🔌 Transport disconnected")
            
        except Exception as e:
            print(f"❌ Disconnect error: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get transport statistics"""
        return {
            **self.stats,
            "success_rate": round(
                (self.stats["successful_connections"] / max(self.stats["connections_attempted"], 1)) * 100, 2
            )
        }
    
    def _log_audit(self, user: str, action: str, details: Dict[str, Any]):
        """Log transport events to audit system"""
        if self.audit_callback:
            self.audit_callback(user, action, "transport", details)


# Global transport instance
transport = PluggableTransport()


def get_transport() -> PluggableTransport:
    """Get global transport instance"""
    return transport


async def test_transport_fallback():
    """Test transport fallback mechanism"""
    print("🧪 Testing KyberLink Transport Fallback...")
    
    transport_test = PluggableTransport()
    
    # Test connection with fallback
    success = await transport_test.connect_with_fallback(
        host="127.0.0.1",
        port=5555,
        preferred_protocol=TransportProtocol.QUIC
    )
    
    if success:
        print(f"✅ Connected via {transport_test.current_protocol.value}")
        
        # Test data transmission
        test_data = b"Hello from KyberLink VPN!"
        if await transport_test.send_data(test_data):
            print("✅ Data sent successfully")
        
        # Show stats
        stats = transport_test.get_stats()
        print(f"📊 Transport Stats: {stats}")
        
        # Disconnect
        transport_test.disconnect()
    else:
        print("❌ All transport protocols failed")


if __name__ == "__main__":
    # Run transport tests
    asyncio.run(test_transport_fallback())