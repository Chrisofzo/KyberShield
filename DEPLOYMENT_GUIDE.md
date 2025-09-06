# KyberLink VPN - VPS Deployment Guide

## Quick Start Deployment

### 1. Extract and Setup
```bash
# Extract the backup
tar -xzf kyberlink_backup.tar.gz
cd kyberlink-vpn/

# Install Python dependencies
pip3 install -r requirements.txt

# Install Node.js dependencies for frontend
cd frontend/kyberlink-frontend/
npm install
npm run build
cd ../../
```

### 2. Production Configuration
```bash
# Set production environment
export FLASK_ENV=production
export NODE_ENV=production

# Generate SSL certificates (replace with your domain)
openssl req -x509 -newkey rsa:4096 -keyout kyberlink.key -out kyberlink.crt -days 365 -nodes
```

### 3. Run Production Server
```bash
# Start Flask API backend (port 8000)
python3 kyberlink_web.py &

# Serve React frontend (you can use nginx or serve built files)
cd frontend/kyberlink-frontend/
npx serve -s build -p 5000
```

### 4. Default Login Credentials
- Username: `demo`
- Password: `demo`
- 2FA: Leave blank (optional)

## Production Security Notes
- Change default credentials immediately
- Use proper SSL certificates from Let's Encrypt
- Configure firewall rules
- Set up proper database backups
- Enable permanent no-logs policy in production

## Architecture
- **Backend**: Flask API on port 8000
- **Frontend**: React SPA on port 5000
- **VPN Server**: Quantum-resistant encryption with hybrid key exchange
- **Database**: SQLite (upgrade to PostgreSQL for production)
- **Security**: X25519 + ML-KEM-768 post-quantum encryption