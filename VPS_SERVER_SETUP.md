# KyberShield VPN Server Infrastructure Setup

## VPS Requirements for MVP

### Minimum Server Specifications
- **CPU**: 1 vCPU minimum (2 vCPU recommended)
- **RAM**: 1GB minimum (2GB recommended)
- **Storage**: 25GB SSD
- **Bandwidth**: 1TB minimum per month
- **Network**: 1Gbps connection
- **OS**: Ubuntu 22.04 LTS or Debian 11

### Recommended VPS Providers for MVP

#### 1. **DigitalOcean** (Recommended for MVP)
- **Plan**: Basic Droplet $6/month
- **Specs**: 1 vCPU, 1GB RAM, 25GB SSD, 1TB transfer
- **Locations**: NYC, San Francisco, London, Frankfurt, Singapore, Toronto
- **Pros**: Easy setup, great documentation, reliable
- **Setup Time**: 55 seconds

#### 2. **Vultr**
- **Plan**: Regular Cloud Compute $6/month
- **Specs**: 1 vCPU, 1GB RAM, 25GB SSD, 2TB transfer
- **Locations**: 32 global locations
- **Pros**: More bandwidth, many locations
- **Setup Time**: 1-2 minutes

#### 3. **Linode**
- **Plan**: Nanode 1GB $5/month
- **Specs**: 1 vCPU, 1GB RAM, 25GB SSD, 1TB transfer
- **Locations**: 11 global data centers
- **Pros**: Cheapest option, good performance
- **Setup Time**: 1-2 minutes

## Server Setup Script

```bash
#!/bin/bash
# KyberShield VPN Server Setup Script

# Update system
apt update && apt upgrade -y

# Install required packages
apt install -y python3 python3-pip git ufw fail2ban

# Install Python dependencies
pip3 install cryptography pycryptodome flask flask-cors psutil

# Clone KyberShield server code
git clone https://github.com/kybershield/vpn-server.git /opt/kybershield
cd /opt/kybershield

# Configure firewall
ufw allow 22/tcp
ufw allow 5555/tcp  # VPN port
ufw allow 443/tcp   # HTTPS
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
ExecStart=/usr/bin/python3 /opt/kybershield/src/vpn_server.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable kybershield
systemctl start kybershield

echo "KyberShield VPN Server installed successfully!"
```

## MVP Server Deployment Plan

### Phase 1: Initial MVP (2 Servers)
1. **US East Coast** - DigitalOcean NYC ($6/month)
2. **Europe** - DigitalOcean Frankfurt ($6/month)
**Total Cost**: $12/month

### Phase 2: Expanded Coverage (5 Servers)
Add:
3. **US West Coast** - Vultr Los Angeles ($6/month)
4. **Asia** - Vultr Singapore ($6/month)
5. **UK** - Linode London ($5/month)
**Total Cost**: $29/month

### Phase 3: Full Global Coverage (10 Servers)
Add:
6. **Canada** - DigitalOcean Toronto ($6/month)
7. **Australia** - Vultr Sydney ($6/month)
8. **Japan** - Linode Tokyo ($5/month)
9. **Brazil** - Vultr São Paulo ($6/month)
10. **India** - DigitalOcean Bangalore ($6/month)
**Total Cost**: $59/month

## Server Management

### Monitoring
- Use DigitalOcean/Vultr monitoring dashboards
- Set up Uptime Robot for free monitoring
- Configure alerts for high CPU/memory usage

### Security
- SSH key authentication only
- Fail2ban for brute force protection
- Regular security updates
- UFW firewall configured
- No root SSH access

### Backup
- Weekly server snapshots
- Configuration backups to S3/Spaces
- Database backups if applicable

## Connection Instructions for Client

```python
# Server configuration for clients
SERVERS = {
    "us-east": {
        "name": "United States - East",
        "host": "nyc.kybershield.io",
        "ip": "YOUR_DROPLET_IP",
        "port": 5555,
        "load": "low"
    },
    "eu-central": {
        "name": "Europe - Frankfurt",
        "host": "fra.kybershield.io",
        "ip": "YOUR_DROPLET_IP",
        "port": 5555,
        "load": "low"
    }
}
```

## Quick Start Commands

### Create DigitalOcean Droplet via CLI
```bash
doctl compute droplet create kybershield-nyc \
  --region nyc3 \
  --size s-1vcpu-1gb \
  --image ubuntu-22-04-x64 \
  --ssh-keys YOUR_SSH_KEY_ID
```

### Deploy Server Code
```bash
ssh root@YOUR_SERVER_IP
curl -sSL https://kybershield.io/setup.sh | bash
```

## Cost Summary for MVP

**Minimum Viable Product (2 servers)**: $12/month
- Basic coverage in US and Europe
- Good for testing and initial users
- Can handle ~100 concurrent connections per server

**Recommended MVP (5 servers)**: $29/month
- Good global coverage
- Professional appearance
- Can handle ~500 total concurrent users

**Full Production (10 servers)**: $59/month
- Excellent global coverage
- Enterprise-ready
- Can handle ~1000+ concurrent users