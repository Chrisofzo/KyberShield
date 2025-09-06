"""
KyberShield Download Configuration
Manages desktop application download links and platform detection
"""

import platform
from typing import Dict, Optional

class DownloadManager:
    def __init__(self):
        self.downloads = self._initialize_downloads()
        
    def _initialize_downloads(self) -> Dict:
        """Initialize download links for all platforms"""
        return {
            "windows": {
                "name": "KyberShield for Windows",
                "version": "1.0.0",
                "filename": "KyberShield-Setup-1.0.0.exe",
                "download_url": "/static/downloads/windows/KyberShield-Setup-1.0.0.exe",
                "size": "87.3 MB",
                "requirements": "Windows 10 or later (64-bit)",
                "features": [
                    "Native Windows integration",
                    "System tray support",
                    "Auto-start on boot",
                    "Windows Firewall integration"
                ],
                "installer_type": "NSIS Installer",
                "sha256": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
            },
            "macos": {
                "name": "KyberShield for macOS",
                "version": "1.0.0",
                "filename": "KyberShield-1.0.0.dmg",
                "download_url": "/static/downloads/macos/KyberShield-1.0.0.dmg",
                "size": "92.1 MB",
                "requirements": "macOS 11.0 Big Sur or later",
                "features": [
                    "Native macOS app",
                    "Menu bar integration",
                    "Touch Bar support",
                    "Keychain integration"
                ],
                "installer_type": "DMG Installer",
                "sha256": "b2c3d4e5f67890123456789012345678901234567890abcdef1234567890abcd"
            },
            "linux": {
                "name": "KyberShield for Linux",
                "version": "1.0.0",
                "variants": {
                    "deb": {
                        "filename": "kybershield-vpn_1.0.0_amd64.deb",
                        "download_url": "/static/downloads/kybershield-vpn_1.0.0_amd64.deb",
                        "size": "77.0 MB",
                        "distros": "Ubuntu, Debian, Mint",
                        "command": "sudo dpkg -i kybershield_1.0.0_amd64.deb"
                    },
                    "rpm": {
                        "filename": "kybershield-1.0.0.x86_64.rpm",
                        "download_url": "/downloads/linux/kybershield-1.0.0.x86_64.rpm",
                        "size": "79.2 MB",
                        "distros": "Fedora, CentOS, RHEL",
                        "command": "sudo rpm -i kybershield-1.0.0.x86_64.rpm"
                    },
                    "appimage": {
                        "filename": "KyberShield VPN-1.0.0.AppImage",
                        "download_url": "/static/downloads/KyberShield%20VPN-1.0.0.AppImage",
                        "size": "112.8 MB",
                        "distros": "Any Linux distribution",
                        "command": "chmod +x KyberShield-1.0.0.AppImage && ./KyberShield-1.0.0.AppImage"
                    }
                },
                "requirements": "Linux kernel 5.4 or later",
                "features": [
                    "System tray integration",
                    "NetworkManager support",
                    "Command-line interface",
                    "Auto-connect on startup"
                ]
            },
            "android": {
                "name": "KyberShield for Android",
                "version": "1.0.0",
                "filename": "KyberShield-1.0.0.apk",
                "download_url": "/downloads/android/KyberShield-1.0.0.apk",
                "play_store_url": "https://play.google.com/store/apps/details?id=com.kybershield.vpn",
                "size": "45.2 MB",
                "requirements": "Android 7.0 or later",
                "features": [
                    "Always-on VPN",
                    "Split tunneling",
                    "Battery optimization",
                    "Quick settings tile"
                ],
                "status": "coming_soon"
            },
            "ios": {
                "name": "KyberShield for iOS",
                "version": "1.0.0",
                "app_store_url": "https://apps.apple.com/app/kybershield-vpn/id1234567890",
                "size": "52.8 MB",
                "requirements": "iOS 14.0 or later, iPadOS 14.0 or later",
                "features": [
                    "On-demand VPN",
                    "Widget support",
                    "Siri shortcuts",
                    "iCloud sync"
                ],
                "status": "coming_soon"
            }
        }
    
    def detect_platform(self, user_agent: Optional[str] = None) -> str:
        """Detect the user's platform from User-Agent or system"""
        if user_agent:
            user_agent_lower = user_agent.lower()
            if 'windows' in user_agent_lower or 'win32' in user_agent_lower:
                return 'windows'
            elif 'mac' in user_agent_lower or 'darwin' in user_agent_lower:
                return 'macos'
            elif 'linux' in user_agent_lower:
                return 'linux'
            elif 'android' in user_agent_lower:
                return 'android'
            elif 'iphone' in user_agent_lower or 'ipad' in user_agent_lower:
                return 'ios'
        
        # Fallback to platform detection
        system = platform.system().lower()
        if system == 'windows':
            return 'windows'
        elif system == 'darwin':
            return 'macos'
        elif system == 'linux':
            return 'linux'
        else:
            return 'windows'  # Default fallback
    
    def get_download_info(self, platform_name: str) -> Optional[Dict]:
        """Get download information for a specific platform"""
        return self.downloads.get(platform_name)
    
    def get_all_downloads(self) -> Dict:
        """Get all available downloads"""
        return self.downloads
    
    def get_latest_version(self) -> str:
        """Get the latest version number"""
        return "1.0.0"
    
    def get_release_notes(self) -> Dict:
        """Get release notes for the latest version"""
        return {
            "version": "1.0.0",
            "date": "2025-09-06",
            "highlights": [
                "Initial release with quantum-resistant encryption",
                "ML-KEM-768 (Kyber) post-quantum key exchange",
                "ChaCha20-Poly1305 authenticated encryption",
                "Kill switch and DNS leak protection",
                "10 global server locations",
                "Zero-log policy with tamper-proof audit trail"
            ],
            "improvements": [],
            "bug_fixes": [],
            "known_issues": [
                "IPv6 support coming in next release",
                "Mobile apps currently in development"
            ]
        }

# Global download manager instance
download_manager = DownloadManager()