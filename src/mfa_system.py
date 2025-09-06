"""
Multi-Factor Authentication (MFA) System with TOTP
"""
import pyotp
import qrcode
import json
import secrets
import base64
import io
from typing import Dict, Optional, Tuple

class MFASystem:
    """TOTP-based Multi-Factor Authentication system"""
    
    def __init__(self, users_file: str = "users.json"):
        self.users_file = users_file
        self.users_data = self._load_users()
    
    def _load_users(self) -> Dict:
        """Load users data from JSON file"""
        try:
            with open(self.users_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def _save_users(self):
        """Save users data to JSON file"""
        with open(self.users_file, 'w') as f:
            json.dump(self.users_data, f, indent=2)
    
    def generate_totp_secret(self, username: str) -> str:
        """Generate new TOTP secret for user"""
        secret = pyotp.random_base32()
        
        # Initialize user if doesn't exist
        if username not in self.users_data:
            self.users_data[username] = {}
        
        self.users_data[username]['totp_secret'] = secret
        self.users_data[username]['mfa_enabled'] = True
        self._save_users()
        
        return secret
    
    def generate_qr_code(self, username: str, issuer: str = "KyberLink VPN") -> str:
        """Generate QR code for TOTP setup"""
        if username not in self.users_data or 'totp_secret' not in self.users_data[username]:
            raise ValueError("TOTP secret not found for user")
        
        secret = self.users_data[username]['totp_secret']
        
        # Create TOTP URI
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(
            name=username,
            issuer_name=issuer
        )
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        # Convert to base64 image
        img = qr.make_image(fill_color="black", back_color="white")
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        img_b64 = base64.b64encode(img_buffer.getvalue()).decode()
        return f"data:image/png;base64,{img_b64}"
    
    def verify_totp(self, username: str, token: str) -> bool:
        """Verify TOTP token for user"""
        if username not in self.users_data or 'totp_secret' not in self.users_data[username]:
            return False
        
        secret = self.users_data[username]['totp_secret']
        totp = pyotp.TOTP(secret)
        
        # Verify with tolerance for clock skew
        return totp.verify(token, valid_window=1)
    
    def is_mfa_enabled(self, username: str) -> bool:
        """Check if MFA is enabled for user"""
        if username not in self.users_data:
            return False
        return self.users_data[username].get('mfa_enabled', False)
    
    def enable_mfa(self, username: str) -> bool:
        """Enable MFA for user"""
        if username not in self.users_data:
            return False
        
        self.users_data[username]['mfa_enabled'] = True
        self._save_users()
        return True
    
    def disable_mfa(self, username: str) -> bool:
        """Disable MFA for user"""
        if username not in self.users_data:
            return False
        
        self.users_data[username]['mfa_enabled'] = False
        self._save_users()
        return True
    
    def get_backup_codes(self, username: str) -> Optional[list]:
        """Get backup codes for user (generate if don't exist)"""
        if username not in self.users_data:
            return None
        
        if 'backup_codes' not in self.users_data[username]:
            # Generate 10 backup codes
            codes = [secrets.token_hex(4).upper() for _ in range(10)]
            self.users_data[username]['backup_codes'] = codes
            self._save_users()
        
        return self.users_data[username]['backup_codes']
    
    def use_backup_code(self, username: str, code: str) -> bool:
        """Use a backup code (removes it after use)"""
        if username not in self.users_data or 'backup_codes' not in self.users_data[username]:
            return False
        
        backup_codes = self.users_data[username]['backup_codes']
        if code.upper() in backup_codes:
            backup_codes.remove(code.upper())
            self._save_users()
            return True
        
        return False
    
    def get_user_mfa_info(self, username: str) -> Dict:
        """Get MFA information for user"""
        if username not in self.users_data:
            return {
                'mfa_enabled': False,
                'has_totp': False,
                'backup_codes_remaining': 0
            }
        
        user_data = self.users_data[username]
        return {
            'mfa_enabled': user_data.get('mfa_enabled', False),
            'has_totp': 'totp_secret' in user_data,
            'backup_codes_remaining': len(user_data.get('backup_codes', []))
        }


# Global MFA system instance
mfa_system = MFASystem()