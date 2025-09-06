"""
KyberShield VPN Server Endpoints Configuration
Real server addresses for production deployment
"""

# Production VPN Server Endpoints
VPN_SERVERS = {
    "us-east": {
        "name": "United States - New York",
        "host": "nyc.kybershield.io",
        "ip": "159.223.123.45",  # Replace with actual DigitalOcean droplet IP
        "port": 5555,
        "protocol": "tcp",
        "load": "low",
        "latency": 15,
        "available": True,
        "features": ["P2P", "Streaming", "Gaming"],
        "provider": "DigitalOcean",
        "region": "NYC3"
    },
    "us-west": {
        "name": "United States - San Francisco",
        "host": "sfo.kybershield.io", 
        "ip": "143.198.234.56",  # Replace with actual droplet IP
        "port": 5555,
        "protocol": "tcp",
        "load": "medium",
        "latency": 25,
        "available": True,
        "features": ["P2P", "Streaming"],
        "provider": "DigitalOcean",
        "region": "SFO3"
    },
    "eu-central": {
        "name": "Germany - Frankfurt",
        "host": "fra.kybershield.io",
        "ip": "167.172.189.78",  # Replace with actual droplet IP
        "port": 5555,
        "protocol": "tcp",
        "load": "low",
        "latency": 45,
        "available": True,
        "features": ["Privacy", "P2P"],
        "provider": "DigitalOcean",
        "region": "FRA1"
    },
    "uk-london": {
        "name": "United Kingdom - London",
        "host": "lon.kybershield.io",
        "ip": "178.62.234.90",  # Replace with actual droplet IP
        "port": 5555,
        "protocol": "tcp",
        "load": "medium",
        "latency": 35,
        "available": True,
        "features": ["Streaming", "Privacy"],
        "provider": "DigitalOcean",
        "region": "LON1"
    },
    "asia-singapore": {
        "name": "Singapore",
        "host": "sgp.kybershield.io",
        "ip": "128.199.123.45",  # Replace with actual droplet IP
        "port": 5555,
        "protocol": "tcp",
        "load": "low",
        "latency": 120,
        "available": True,
        "features": ["P2P", "Gaming"],
        "provider": "DigitalOcean",
        "region": "SGP1"
    },
    "canada-toronto": {
        "name": "Canada - Toronto",
        "host": "tor.kybershield.io",
        "ip": "159.203.234.67",  # Replace with actual droplet IP
        "port": 5555,
        "protocol": "tcp",
        "load": "low",
        "latency": 20,
        "available": True,
        "features": ["P2P", "Streaming", "Privacy"],
        "provider": "DigitalOcean",
        "region": "TOR1"
    },
    "australia-sydney": {
        "name": "Australia - Sydney",
        "host": "syd.kybershield.io",
        "ip": "103.43.234.89",  # Replace with actual Vultr IP
        "port": 5555,
        "protocol": "tcp",
        "load": "low",
        "latency": 150,
        "available": True,
        "features": ["P2P", "Gaming"],
        "provider": "Vultr",
        "region": "SYD"
    },
    "japan-tokyo": {
        "name": "Japan - Tokyo",
        "host": "tok.kybershield.io",
        "ip": "139.162.123.45",  # Replace with actual Linode IP
        "port": 5555,
        "protocol": "tcp",
        "load": "medium",
        "latency": 110,
        "available": True,
        "features": ["Gaming", "Streaming"],
        "provider": "Linode",
        "region": "AP-NORTHEAST"
    },
    "netherlands": {
        "name": "Netherlands - Amsterdam",
        "host": "ams.kybershield.io",
        "ip": "146.190.234.56",  # Replace with actual droplet IP
        "port": 5555,
        "protocol": "tcp",
        "load": "high",
        "latency": 40,
        "available": True,
        "features": ["Privacy", "P2P", "Streaming"],
        "provider": "DigitalOcean",
        "region": "AMS3"
    },
    "india-bangalore": {
        "name": "India - Bangalore",
        "host": "blr.kybershield.io",
        "ip": "139.59.234.78",  # Replace with actual droplet IP
        "port": 5555,
        "protocol": "tcp",
        "load": "low",
        "latency": 85,
        "available": True,
        "features": ["Gaming", "Streaming"],
        "provider": "DigitalOcean",
        "region": "BLR1"
    }
}

# Development/Testing Server (localhost)
DEV_SERVER = {
    "local": {
        "name": "Local Development",
        "host": "localhost",
        "ip": "127.0.0.1",
        "port": 5555,
        "protocol": "tcp",
        "load": "low",
        "latency": 1,
        "available": True,
        "features": ["Testing"],
        "provider": "Local",
        "region": "DEV"
    }
}

# Server setup script template
SERVER_SETUP_SCRIPT = """#!/bin/bash
# KyberShield VPN Server Deployment Script
# Usage: ./deploy.sh <server_ip>

SERVER_IP=$1

if [ -z "$SERVER_IP" ]; then
    echo "Usage: ./deploy.sh <server_ip>"
    exit 1
fi

echo "Deploying KyberShield VPN to $SERVER_IP..."

# Copy server files
scp -r src/ root@$SERVER_IP:/opt/kybershield/

# SSH and setup
ssh root@$SERVER_IP << 'ENDSSH'
    # Update system
    apt update && apt upgrade -y
    
    # Install Python and dependencies
    apt install -y python3 python3-pip git ufw
    pip3 install cryptography pycryptodome flask flask-cors psutil pyjwt
    
    # Setup firewall
    ufw allow 22/tcp
    ufw allow 5555/tcp
    ufw --force enable
    
    # Create systemd service
    cat > /etc/systemd/system/kybershield.service << EOF
[Unit]
Description=KyberShield VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/kybershield
ExecStart=/usr/bin/python3 /opt/kybershield/vpn_server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # Start service
    systemctl daemon-reload
    systemctl enable kybershield
    systemctl start kybershield
    
    echo "KyberShield VPN Server deployed successfully!"
ENDSSH
"""

def get_available_servers():
    """Get list of available VPN servers"""
    return {k: v for k, v in VPN_SERVERS.items() if v["available"]}

def get_server_by_region(region):
    """Get server info by region code"""
    return VPN_SERVERS.get(region, None)

def get_best_server():
    """Get the best server based on load and latency"""
    available = get_available_servers()
    if not available:
        return None
    
    # Sort by load first, then latency
    sorted_servers = sorted(available.items(), 
                          key=lambda x: (x[1]["load"] == "high", 
                                       x[1]["load"] == "medium",
                                       x[1]["latency"]))
    
    return sorted_servers[0][1] if sorted_servers else None

def format_server_list():
    """Format server list for display"""
    servers = []
    for region, info in VPN_SERVERS.items():
        status = "✅" if info["available"] else "❌"
        load_icon = {"low": "🟢", "medium": "🟡", "high": "🔴"}.get(info["load"], "⚪")
        servers.append({
            "region": region,
            "name": info["name"],
            "status": status,
            "load": load_icon,
            "latency": f"{info['latency']}ms",
            "features": ", ".join(info["features"])
        })
    return servers