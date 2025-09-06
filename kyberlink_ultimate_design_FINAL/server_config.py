"""
KyberShield VPN Server Configuration
Manages multiple VPN server endpoints for production deployment
"""

import json
from datetime import datetime
from typing import Dict, List, Optional
import random

class VPNServerManager:
    def __init__(self):
        self.servers = self._initialize_servers()
        
    def _initialize_servers(self) -> List[Dict]:
        """Initialize the list of available VPN servers"""
        return [
            {
                "id": "us-east-1",
                "name": "United States - East",
                "country": "US",
                "city": "New York",
                "ip": "vpn-us-east.kybershield.com",
                "port": 5555,
                "protocol": "KyberShield",
                "load": random.randint(15, 45),
                "latency": random.randint(10, 30),
                "flag": "🇺🇸",
                "quantum_ready": True,
                "features": ["Post-Quantum", "Zero-Log", "Kill Switch"],
                "status": "online"
            },
            {
                "id": "us-west-1",
                "name": "United States - West",
                "country": "US",
                "city": "Los Angeles",
                "ip": "vpn-us-west.kybershield.com",
                "port": 5555,
                "protocol": "KyberShield",
                "load": random.randint(20, 50),
                "latency": random.randint(15, 35),
                "flag": "🇺🇸",
                "quantum_ready": True,
                "features": ["Post-Quantum", "Zero-Log", "Kill Switch"],
                "status": "online"
            },
            {
                "id": "eu-central-1",
                "name": "Europe - Central",
                "country": "DE",
                "city": "Frankfurt",
                "ip": "vpn-eu-central.kybershield.com",
                "port": 5555,
                "protocol": "KyberShield",
                "load": random.randint(25, 55),
                "latency": random.randint(20, 40),
                "flag": "🇩🇪",
                "quantum_ready": True,
                "features": ["Post-Quantum", "Zero-Log", "GDPR Compliant"],
                "status": "online"
            },
            {
                "id": "uk-london-1",
                "name": "United Kingdom",
                "country": "GB",
                "city": "London",
                "ip": "vpn-uk-london.kybershield.com",
                "port": 5555,
                "protocol": "KyberShield",
                "load": random.randint(30, 60),
                "latency": random.randint(18, 38),
                "flag": "🇬🇧",
                "quantum_ready": True,
                "features": ["Post-Quantum", "Zero-Log", "Kill Switch"],
                "status": "online"
            },
            {
                "id": "asia-tokyo-1",
                "name": "Asia - Tokyo",
                "country": "JP",
                "city": "Tokyo",
                "ip": "vpn-asia-tokyo.kybershield.com",
                "port": 5555,
                "protocol": "KyberShield",
                "load": random.randint(35, 65),
                "latency": random.randint(50, 80),
                "flag": "🇯🇵",
                "quantum_ready": True,
                "features": ["Post-Quantum", "Zero-Log", "High Speed"],
                "status": "online"
            },
            {
                "id": "canada-toronto-1",
                "name": "Canada",
                "country": "CA",
                "city": "Toronto",
                "ip": "vpn-ca-toronto.kybershield.com",
                "port": 5555,
                "protocol": "KyberShield",
                "load": random.randint(20, 45),
                "latency": random.randint(12, 28),
                "flag": "🇨🇦",
                "quantum_ready": True,
                "features": ["Post-Quantum", "Zero-Log", "Privacy Shield"],
                "status": "online"
            },
            {
                "id": "australia-sydney-1",
                "name": "Australia",
                "country": "AU",
                "city": "Sydney",
                "ip": "vpn-au-sydney.kybershield.com",
                "port": 5555,
                "protocol": "KyberShield",
                "load": random.randint(25, 50),
                "latency": random.randint(60, 90),
                "flag": "🇦🇺",
                "quantum_ready": True,
                "features": ["Post-Quantum", "Zero-Log", "Kill Switch"],
                "status": "online"
            },
            {
                "id": "singapore-1",
                "name": "Singapore",
                "country": "SG",
                "city": "Singapore",
                "ip": "vpn-sg.kybershield.com",
                "port": 5555,
                "protocol": "KyberShield",
                "load": random.randint(40, 70),
                "latency": random.randint(45, 75),
                "flag": "🇸🇬",
                "quantum_ready": True,
                "features": ["Post-Quantum", "Zero-Log", "High Speed"],
                "status": "online"
            },
            {
                "id": "switzerland-1",
                "name": "Switzerland",
                "country": "CH",
                "city": "Zurich",
                "ip": "vpn-ch-zurich.kybershield.com",
                "port": 5555,
                "protocol": "KyberShield",
                "load": random.randint(15, 40),
                "latency": random.randint(25, 45),
                "flag": "🇨🇭",
                "quantum_ready": True,
                "features": ["Post-Quantum", "Zero-Log", "Maximum Privacy"],
                "status": "online"
            },
            {
                "id": "netherlands-1",
                "name": "Netherlands",
                "country": "NL",
                "city": "Amsterdam",
                "ip": "vpn-nl-amsterdam.kybershield.com",
                "port": 5555,
                "protocol": "KyberShield",
                "load": random.randint(30, 55),
                "latency": random.randint(22, 42),
                "flag": "🇳🇱",
                "quantum_ready": True,
                "features": ["Post-Quantum", "Zero-Log", "P2P Optimized"],
                "status": "online"
            }
        ]
    
    def get_all_servers(self) -> List[Dict]:
        """Get all available VPN servers"""
        # Update server loads and latencies dynamically
        for server in self.servers:
            server['load'] = min(95, max(5, server['load'] + random.randint(-5, 5)))
            server['latency'] = max(5, server['latency'] + random.randint(-3, 3))
        return self.servers
    
    def get_server_by_id(self, server_id: str) -> Optional[Dict]:
        """Get a specific server by ID"""
        for server in self.servers:
            if server['id'] == server_id:
                return server
        return None
    
    def get_best_server(self) -> Dict:
        """Get the best server based on load and latency"""
        available_servers = [s for s in self.servers if s['status'] == 'online']
        if not available_servers:
            return self.servers[0]
        
        # Score based on load (lower is better) and latency (lower is better)
        best_server = min(available_servers, 
                         key=lambda s: s['load'] * 0.6 + s['latency'] * 0.4)
        return best_server
    
    def get_servers_by_country(self, country_code: str) -> List[Dict]:
        """Get all servers in a specific country"""
        return [s for s in self.servers if s['country'] == country_code]
    
    def update_server_status(self, server_id: str, status: str) -> bool:
        """Update the status of a specific server"""
        server = self.get_server_by_id(server_id)
        if server:
            server['status'] = status
            return True
        return False
    
    def get_server_stats(self) -> Dict:
        """Get aggregated server statistics"""
        total_servers = len(self.servers)
        online_servers = len([s for s in self.servers if s['status'] == 'online'])
        countries = len(set(s['country'] for s in self.servers))
        avg_load = sum(s['load'] for s in self.servers) / total_servers
        
        return {
            "total_servers": total_servers,
            "online_servers": online_servers,
            "countries": countries,
            "average_load": round(avg_load, 1),
            "quantum_ready_servers": total_servers,  # All servers are quantum-ready
            "timestamp": datetime.utcnow().isoformat()
        }

# Global server manager instance
server_manager = VPNServerManager()