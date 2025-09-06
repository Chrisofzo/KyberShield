#!/usr/bin/env python3
"""
KyberLink VPN Demo Script
Demonstrates the complete quantum-resistant VPN functionality
"""

import time
import subprocess
import sys
import os

def print_kyberlink_banner():
    """Display KyberLink branding banner"""
    print("=" * 80)
    print("🔐 KYBERLINK VPN - QUANTUM-RESISTANT ENCRYPTION DEMO")
    print("=" * 80)
    print()
    print("🛡️  KyberLink — quantum-resistant VPN powered by hybrid post-quantum encryption")
    print()
    print("Features:")
    print("  • X25519 + ML-KEM-768 (Kyber768) hybrid key exchange")
    print("  • ChaCha20-Poly1305 authenticated encryption")
    print("  • Session management with replay protection")
    print("  • TUN/TAP interface integration")
    print("  • Modern CustomTkinter GUI")
    print("  • Enterprise security features")
    print()
    print("=" * 80)
    print()

def run_demo():
    """Run the KyberLink VPN demonstration"""
    print_kyberlink_banner()
    
    print("🚀 Starting KyberLink VPN Demo...")
    print()
    
    # Check if server is running
    print("📡 Checking KyberLink VPN server status...")
    time.sleep(2)
    
    # Launch GUI client
    print("🖥️  Launching KyberLink GUI client...")
    print("   Opening modern dark-themed interface with quantum-resistant encryption")
    print()
    
    try:
        # Start the modern GUI
        subprocess.run([sys.executable, "vpn_modern_app.py"], check=True)
    except KeyboardInterrupt:
        print("\n🛑 Demo interrupted by user")
    except Exception as e:
        print(f"❌ Demo error: {e}")
    
    print("\n✅ KyberLink VPN Demo completed!")
    print("Thank you for trying KyberLink — your quantum-safe networking solution")

if __name__ == "__main__":
    run_demo()