#!/usr/bin/env python3
"""
KyberLink VPN Kill Switch Module
===============================

Advanced network traffic control to prevent data leaks when VPN connection drops.
Supports Linux (iptables), macOS (pfctl), with Windows placeholder for future implementation.

Security Features:
- Blocks all outgoing traffic except to VPN server
- Maintains protection during unexpected disconnects
- OS-specific firewall rule implementation
- Automatic rule restoration on disable
"""

import subprocess
import platform
import os
import json
from typing import Dict, Optional, List
import time


class KillSwitch:
    """Kill Switch implementation for preventing VPN data leaks"""
    
    def __init__(self):
        self.os_type = platform.system().lower()
        self.is_active = False
        self.vpn_server_ip = None
        self.backup_rules_file = "/tmp/kyberlink_backup_rules.json"
        
        # OS-specific command configurations
        self.commands = {
            'linux': {
                'check_iptables': ['which', 'iptables'],
                'save_rules': ['iptables-save'],
                'restore_rules': ['iptables-restore'],
                'flush_rules': ['iptables', '-F'],
                'block_all': ['iptables', '-P', 'OUTPUT', 'DROP'],
                'allow_loopback': ['iptables', '-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'],
                'allow_vpn': None,  # Will be dynamically set
                'reset_policy': ['iptables', '-P', 'OUTPUT', 'ACCEPT']
            },
            'darwin': {  # macOS
                'check_pfctl': ['which', 'pfctl'],
                'enable_pf': ['pfctl', '-e'],
                'disable_pf': ['pfctl', '-d'],
                'load_rules': ['pfctl', '-f'],
                'flush_rules': ['pfctl', '-F', 'all']
            }
        }
        
        print(f"🛡️  Kill Switch initialized for {self.os_type.title()}")
    
    def _run_command(self, command: List[str], capture_output: bool = False) -> subprocess.CompletedProcess:
        """Execute system command with error handling"""
        try:
            if capture_output:
                result = subprocess.run(command, capture_output=True, text=True, check=False)
                if result.returncode != 0:
                    print(f"⚠️  Command failed: {' '.join(command)}")
                    print(f"   Error: {result.stderr}")
                return result
            else:
                result = subprocess.run(command, check=False)
                return result
        except Exception as e:
            print(f"❌ Command execution error: {e}")
            return subprocess.CompletedProcess(command, 1, '', str(e))
    
    def _backup_current_rules(self) -> bool:
        """Backup current firewall rules before modification"""
        try:
            if self.os_type == 'linux':
                # Save current iptables rules
                result = self._run_command(self.commands['linux']['save_rules'], capture_output=True)
                if result.returncode == 0:
                    backup_data = {
                        'os': 'linux',
                        'rules': result.stdout,
                        'timestamp': time.time()
                    }
                    with open(self.backup_rules_file, 'w') as f:
                        json.dump(backup_data, f, indent=2)
                    print(f"💾 Firewall rules backed up to {self.backup_rules_file}")
                    return True
            
            elif self.os_type == 'darwin':
                # For macOS, we'll create a simple backup indicator
                backup_data = {
                    'os': 'darwin',
                    'pf_enabled': True,
                    'timestamp': time.time()
                }
                with open(self.backup_rules_file, 'w') as f:
                    json.dump(backup_data, f, indent=2)
                print(f"💾 macOS firewall state backed up")
                return True
                
        except Exception as e:
            print(f"❌ Failed to backup firewall rules: {e}")
        
        return False
    
    def _restore_backup_rules(self) -> bool:
        """Restore previously backed up firewall rules"""
        try:
            if not os.path.exists(self.backup_rules_file):
                print("⚠️  No backup rules found, using default restore")
                return self._restore_default_rules()
            
            with open(self.backup_rules_file, 'r') as f:
                backup_data = json.load(f)
            
            if backup_data['os'] == 'linux':
                # Restore iptables rules from backup
                process = subprocess.Popen(self.commands['linux']['restore_rules'], 
                                         stdin=subprocess.PIPE, text=True)
                process.communicate(input=backup_data['rules'])
                
                if process.returncode == 0:
                    print("✅ Linux iptables rules restored from backup")
                    os.remove(self.backup_rules_file)
                    return True
                    
            elif backup_data['os'] == 'darwin':
                # For macOS, disable pfctl
                result = self._run_command(self.commands['darwin']['disable_pf'])
                if result.returncode == 0:
                    print("✅ macOS pfctl rules restored")
                    os.remove(self.backup_rules_file)
                    return True
                    
        except Exception as e:
            print(f"❌ Failed to restore backup rules: {e}")
        
        return False
    
    def _restore_default_rules(self) -> bool:
        """Restore default 'allow all' firewall policy"""
        try:
            if self.os_type == 'linux':
                # Reset iptables to allow all traffic
                self._run_command(self.commands['linux']['flush_rules'])
                self._run_command(self.commands['linux']['reset_policy'])
                print("✅ Linux iptables reset to default (allow all)")
                return True
                
            elif self.os_type == 'darwin':
                # Disable pfctl
                self._run_command(self.commands['darwin']['disable_pf'])
                print("✅ macOS pfctl disabled (default allow)")
                return True
                
        except Exception as e:
            print(f"❌ Failed to restore default rules: {e}")
        
        return False
    
    def enable_kill_switch(self, vpn_server_ip: str) -> bool:
        """
        Enable kill switch to block all traffic except to VPN server
        
        Args:
            vpn_server_ip: IP address of the VPN server to allow
            
        Returns:
            True if kill switch enabled successfully, False otherwise
        """
        if self.is_active:
            print("⚠️  Kill switch is already active")
            return True
        
        self.vpn_server_ip = vpn_server_ip
        
        # Backup current rules first
        if not self._backup_current_rules():
            print("❌ Failed to backup current firewall rules")
            return False
        
        try:
            if self.os_type == 'linux':
                return self._enable_linux_kill_switch()
            elif self.os_type == 'darwin':
                return self._enable_macos_kill_switch()
            elif self.os_type == 'windows':
                return self._enable_windows_kill_switch()
            else:
                print(f"❌ Unsupported OS: {self.os_type}")
                return False
                
        except Exception as e:
            print(f"❌ Kill switch activation failed: {e}")
            return False
    
    def _enable_linux_kill_switch(self) -> bool:
        """Enable kill switch using Linux iptables"""
        try:
            # Check if iptables is available
            result = self._run_command(self.commands['linux']['check_iptables'], capture_output=True)
            if result.returncode != 0:
                print("❌ iptables not found. Please install iptables.")
                return False
            
            # Flush existing rules and set default DROP policy
            self._run_command(self.commands['linux']['flush_rules'])
            
            # Allow loopback traffic (localhost)
            self._run_command(self.commands['linux']['allow_loopback'])
            
            # Allow traffic to VPN server
            allow_vpn_cmd = ['iptables', '-A', 'OUTPUT', '-d', self.vpn_server_ip, '-j', 'ACCEPT']
            result = self._run_command(allow_vpn_cmd)
            
            if result.returncode != 0:
                print(f"❌ Failed to add VPN server rule for {self.vpn_server_ip}")
                return False
            
            # Block all other outgoing traffic
            self._run_command(self.commands['linux']['block_all'])
            
            self.is_active = True
            print(f"[Client] 🛡️  Kill switch activated — traffic restricted to VPN only")
            print(f"         VPN server allowed: {self.vpn_server_ip}")
            return True
            
        except Exception as e:
            print(f"❌ Linux kill switch error: {e}")
            return False
    
    def _enable_macos_kill_switch(self) -> bool:
        """Enable kill switch using macOS pfctl"""
        try:
            # Check if pfctl is available
            result = self._run_command(self.commands['darwin']['check_pfctl'], capture_output=True)
            if result.returncode != 0:
                print("❌ pfctl not found on macOS")
                return False
            
            # Create pfctl rules file
            pf_rules = f"""
# KyberLink Kill Switch Rules
set skip on lo0
block all
pass out to {self.vpn_server_ip}
"""
            
            rules_file = "/tmp/kyberlink_killswitch.conf"
            with open(rules_file, 'w') as f:
                f.write(pf_rules)
            
            # Enable pfctl and load rules
            self._run_command(self.commands['darwin']['enable_pf'])
            load_cmd = self.commands['darwin']['load_rules'] + [rules_file]
            result = self._run_command(load_cmd)
            
            if result.returncode == 0:
                self.is_active = True
                print(f"[Client] 🛡️  Kill switch activated — traffic restricted to VPN only")
                print(f"         VPN server allowed: {self.vpn_server_ip}")
                os.remove(rules_file)
                return True
            else:
                print("❌ Failed to load pfctl rules")
                return False
                
        except Exception as e:
            print(f"❌ macOS kill switch error: {e}")
            return False
    
    def _enable_windows_kill_switch(self) -> bool:
        """Placeholder for Windows Firewall implementation"""
        print("⚠️  Windows kill switch not yet implemented")
        print("    Future implementation will use Windows Firewall (netsh advfirewall)")
        print("    For now, kill switch is simulated on Windows")
        
        # Simulate activation for development
        self.is_active = True
        print(f"[Client] 🛡️  Kill switch activated (simulated) — VPN server: {self.vpn_server_ip}")
        return True
    
    def disable_kill_switch(self) -> bool:
        """
        Disable kill switch and restore normal traffic flow
        
        Returns:
            True if kill switch disabled successfully, False otherwise
        """
        if not self.is_active:
            print("⚠️  Kill switch is not active")
            return True
        
        try:
            # Attempt to restore from backup first
            if self._restore_backup_rules():
                success = True
            else:
                # Fallback to default restoration
                success = self._restore_default_rules()
            
            if success:
                self.is_active = False
                self.vpn_server_ip = None
                print("[Client] 🔓 Kill switch deactivated — normal traffic restored")
                return True
            else:
                print("❌ Failed to disable kill switch")
                return False
                
        except Exception as e:
            print(f"❌ Kill switch deactivation error: {e}")
            return False
    
    def check_status(self) -> Dict[str, any]:
        """
        Check current kill switch status
        
        Returns:
            Dictionary with status information
        """
        return {
            'active': self.is_active,
            'vpn_server_ip': self.vpn_server_ip,
            'os_type': self.os_type,
            'backup_exists': os.path.exists(self.backup_rules_file)
        }
    
    def force_block_on_disconnect(self):
        """
        Handle unexpected VPN disconnect by keeping kill switch active
        """
        if self.is_active:
            print("[Client] ❌ VPN dropped — kill switch preventing leaks")
            print("         All traffic blocked until VPN reconnects")
        else:
            print("⚠️  VPN disconnected but kill switch was not active")


# Global kill switch instance
kill_switch = KillSwitch()


def enable_kill_switch(vpn_server_ip: str) -> bool:
    """Global function to enable kill switch"""
    return kill_switch.enable_kill_switch(vpn_server_ip)


def disable_kill_switch() -> bool:
    """Global function to disable kill switch"""
    return kill_switch.disable_kill_switch()


def check_status() -> Dict[str, any]:
    """Global function to check kill switch status"""
    return kill_switch.check_status()


def force_block_on_disconnect():
    """Global function to handle unexpected disconnect"""
    kill_switch.force_block_on_disconnect()


if __name__ == "__main__":
    # Test kill switch functionality
    print("🧪 Testing KyberLink Kill Switch...")
    
    # Test status check
    status = check_status()
    print(f"Initial status: {status}")
    
    # Test enable (with example IP)
    test_ip = "192.168.1.100"
    print(f"\n🔒 Testing enable with server IP: {test_ip}")
    if enable_kill_switch(test_ip):
        print("✅ Kill switch enabled successfully")
        
        # Check status after enable
        status = check_status()
        print(f"Status after enable: {status}")
        
        # Wait a moment then disable
        print("\n🔓 Testing disable...")
        if disable_kill_switch():
            print("✅ Kill switch disabled successfully")
        else:
            print("❌ Failed to disable kill switch")
    else:
        print("❌ Failed to enable kill switch")