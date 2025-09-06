#!/usr/bin/env python3
"""
KyberShield VPN - Main Entry Point
Redirects to the production-ready application
"""

import sys
import os

# Add the ultimate design directory to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'kyberlink_ultimate_design_FINAL'))

# Import and run the production app
from kyberlink_golden_master import app

if __name__ == '__main__':
    print("🛡️  Starting KyberShield VPN Production Server...")
    print("🌐  Website: https://kybershield.io")
    print("🔐  Login: admin@kybershield.com / shield2025")
    print("🚀  Quantum-resistant security activated!")
    
    # Run with production settings
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        threaded=True
    )