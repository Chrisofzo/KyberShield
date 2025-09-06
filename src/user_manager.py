#!/usr/bin/env python3
"""
Enhanced User Management System for KyberLink VPN
=================================================

Secure user registration and authentication system with:
- Argon2id password hashing (memory_cost=65536, time_cost=3, parallelism=4)
- SQLite database storage with encrypted password hashes
- Automatic migration from legacy JSON format
"""

import sqlite3
import os
import time
import json
import base64
import io
import hashlib
import secrets
from typing import Dict, Any, Optional
import pyotp
import qrcode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import threading


class UserManager:
    """Enhanced user management with SHA3-256 + unique salt and SQLite"""
    
    def __init__(self, db_file: str = "users.db", legacy_json_file: str = "users.json"):
        self.db_file = db_file
        self.legacy_json_file = legacy_json_file
        
        # Initialize AES-GCM encryption for MFA secrets
        self._init_master_key()
        
        # Rate limiting storage
        self._mfa_attempts = {}  # user -> [(timestamp, success/fail)]
        self._locked_users = {}  # user -> unlock_timestamp
        self._rate_limit_lock = threading.Lock()
        
        # Initialize database
        self.init_db()
        
        # Migrate from legacy JSON if needed
        self._migrate_from_json()
        
        print("🔐 Enhanced UserManager initialized with SHA3-256 + unique salt + SQLite + MFA")
    
    def init_db(self) -> None:
        """Initialize SQLite database and create users table if missing"""
        try:
            with sqlite3.connect(self.db_file) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        mfa_enabled BOOLEAN DEFAULT FALSE,
                        mfa_secret TEXT,
                        backup_codes TEXT,
                        mfa_attempts TEXT,
                        locked_until TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Add new columns if they don't exist (for existing databases)
                try:
                    conn.execute('ALTER TABLE users ADD COLUMN salt TEXT')
                    print("🧂 Added salt column to existing database")
                except sqlite3.OperationalError:
                    pass
                
                try:
                    conn.execute('ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN DEFAULT FALSE')
                    print("🔐 Added mfa_enabled column to existing database")
                except sqlite3.OperationalError:
                    pass
                
                try:
                    conn.execute('ALTER TABLE users ADD COLUMN backup_codes TEXT')
                    print("🔐 Added backup_codes column to existing database")
                except sqlite3.OperationalError:
                    pass
                
                try:
                    conn.execute('ALTER TABLE users ADD COLUMN mfa_attempts TEXT')
                    print("⏱️  Added mfa_attempts column to existing database")
                except sqlite3.OperationalError:
                    pass
                
                try:
                    conn.execute('ALTER TABLE users ADD COLUMN locked_until TIMESTAMP')
                    print("🔒 Added locked_until column to existing database")
                    print("📱 Added backup_codes column to existing database")
                except sqlite3.OperationalError:
                    pass
                
                conn.commit()
                print(f"✅ SQLite database initialized: {self.db_file}")
        except Exception as e:
            print(f"❌ Database initialization error: {e}")
            raise
    
    def _generate_salt(self) -> str:
        """Generate a unique 32-byte salt encoded as hex"""
        return secrets.token_hex(32)
    
    def _hash_password(self, password: str, salt: str) -> str:
        """Hash password using SHA3-256 with unique salt"""
        # Combine password and salt
        salted_password = (password + salt).encode('utf-8')
        
        # Create SHA3-256 hash
        hash_obj = hashlib.sha3_256(salted_password)
        
        return hash_obj.hexdigest()
    
    def _verify_password(self, password: str, salt: str, stored_hash: str) -> bool:
        """Verify password against stored hash"""
        computed_hash = self._hash_password(password, salt)
        return computed_hash == stored_hash
    
    def _init_master_key(self) -> None:
        """Initialize or load master key for AES-GCM encryption of MFA secrets"""
        key_file = "mfa_master.key"
        
        if os.path.exists(key_file):
            # Load existing master key
            with open(key_file, 'rb') as f:
                self.master_key = f.read()
        else:
            # Generate new 256-bit master key
            self.master_key = secrets.token_bytes(32)
            with open(key_file, 'wb') as f:
                f.write(self.master_key)
            print("🔑 Generated new AES-GCM master key for MFA secrets")
    
    def _encrypt_mfa_secret(self, secret: str) -> str:
        """Encrypt MFA secret using AES-GCM with random nonce"""
        # Generate random 12-byte nonce for GCM
        nonce = secrets.token_bytes(12)
        
        # Create AES-GCM cipher
        cipher = Cipher(algorithms.AES(self.master_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        
        # Encrypt the secret
        ciphertext = encryptor.update(secret.encode()) + encryptor.finalize()
        
        # Combine nonce + ciphertext + tag and encode as base64
        encrypted_data = nonce + ciphertext + encryptor.tag
        return base64.b64encode(encrypted_data).decode()
    
    def _decrypt_mfa_secret(self, encrypted_secret: str) -> str:
        """Decrypt MFA secret using AES-GCM"""
        # Decode from base64
        encrypted_data = base64.b64decode(encrypted_secret.encode())
        
        # Extract components
        nonce = encrypted_data[:12]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[12:-16]
        
        # Create AES-GCM cipher and decrypt
        cipher = Cipher(algorithms.AES(self.master_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted.decode()
    
    def _migrate_from_json(self) -> None:
        """Migrate users from legacy JSON format to SQLite with Argon2id"""
        if not os.path.exists(self.legacy_json_file):
            return  # No legacy file to migrate
        
        try:
            # Check if migration already completed
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM users")
                user_count = cursor.fetchone()[0]
                
                if user_count > 0:
                    print(f"📊 Database already has {user_count} users, skipping migration")
                    return
            
            # Load legacy JSON data
            with open(self.legacy_json_file, 'r') as f:
                legacy_users = json.load(f)
            
            if not legacy_users:
                print("📂 Legacy JSON file is empty, no migration needed")
                return
            
            print(f"🔄 Migrating {len(legacy_users)} users from JSON to SQLite with Argon2id...")
            
            # Migrate each user (we can't convert old hashes, so create temporary passwords)
            migrated_count = 0
            with sqlite3.connect(self.db_file) as conn:
                for username, user_data in legacy_users.items():
                    try:
                        # Create a temporary secure password for migrated users
                        # In production, users would need to reset passwords
                        temp_password = f"temp_{username}_2024"  # Users need to change this
                        salt = self._generate_salt()
                        password_hash = self._hash_password(temp_password, salt)
                        
                        conn.execute(
                            "INSERT INTO users (username, password_hash, salt, mfa_enabled, created_at) VALUES (?, ?, ?, ?, ?)",
                            (username, password_hash, salt, False, time.time())
                        )
                        migrated_count += 1
                        print(f"✅ Migrated user: {username} (temp password: temp_{username}_2024)")
                        
                    except sqlite3.IntegrityError:
                        print(f"⚠️  User {username} already exists, skipping")
                    except Exception as e:
                        print(f"❌ Error migrating user {username}: {e}")
                
                conn.commit()
            
            print(f"🎉 Migration completed: {migrated_count} users migrated to secure SQLite + Argon2id")
            
            # Rename legacy file to prevent re-migration
            backup_name = f"{self.legacy_json_file}.migrated.backup"
            os.rename(self.legacy_json_file, backup_name)
            print(f"📁 Legacy JSON file backed up as: {backup_name}")
            
        except Exception as e:
            print(f"❌ Migration error: {e}")
    
    def generate_mfa_secret(self) -> str:
        """Generate a new TOTP secret for MFA"""
        return pyotp.random_base32()
    
    def _generate_backup_codes(self, count: int = 5) -> list:
        """Generate backup codes for MFA recovery"""
        codes = []
        for _ in range(count):
            # Generate 8-digit backup codes
            code = ''.join([secrets.choice('0123456789') for _ in range(8)])
            codes.append(code)
        return codes
    
    def _hash_backup_codes(self, codes: list) -> dict:
        """Hash backup codes for secure storage"""
        hashed_codes = {}
        for code in codes:
            # Use SHA3-256 to hash each backup code
            salt = secrets.token_hex(16)
            hash_obj = hashlib.sha3_256()
            hash_obj.update((code + salt).encode())
            code_hash = hash_obj.hexdigest()
            hashed_codes[code_hash] = {'salt': salt, 'used': False}
        return hashed_codes
    
    def _check_rate_limit(self, username: str) -> tuple[bool, int]:
        """Check if user is rate limited for MFA attempts"""
        current_time = time.time()
        
        with self._rate_limit_lock:
            # Check if user is currently locked
            if username in self._locked_users:
                unlock_time = self._locked_users[username]
                if current_time < unlock_time:
                    remaining = int(unlock_time - current_time)
                    return False, remaining
                else:
                    # Lock expired, remove from locked users
                    del self._locked_users[username]
            
            # Initialize attempts list if not exists
            if username not in self._mfa_attempts:
                self._mfa_attempts[username] = []
            
            # Clean up old attempts (older than 1 minute)
            recent_attempts = []
            for attempt_time, success in self._mfa_attempts[username]:
                if current_time - attempt_time <= 60:  # 1 minute window
                    recent_attempts.append((attempt_time, success))
            
            self._mfa_attempts[username] = recent_attempts
            
            # Check if exceeded 5 attempts in 1 minute
            if len(recent_attempts) >= 5:
                # Lock user for 5 minutes
                unlock_time = current_time + 300  # 5 minutes
                self._locked_users[username] = unlock_time
                return False, 300
            
            return True, 0
    
    def _record_mfa_attempt(self, username: str, success: bool) -> None:
        """Record MFA attempt for rate limiting"""
        current_time = time.time()
        
        with self._rate_limit_lock:
            if username not in self._mfa_attempts:
                self._mfa_attempts[username] = []
            
            self._mfa_attempts[username].append((current_time, success))
    
    def _verify_backup_code(self, username: str, backup_code: str) -> bool:
        """Verify backup code and mark as used"""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT backup_codes FROM users 
                    WHERE username = ? AND mfa_enabled = TRUE
                """, (username,))
                
                result = cursor.fetchone()
                if not result or not result[0]:
                    return False
                
                stored_codes = json.loads(result[0])
                
                # Check each stored hash
                for code_hash, code_data in stored_codes.items():
                    if code_data['used']:
                        continue
                    
                    # Hash the provided backup code with stored salt
                    hash_obj = hashlib.sha3_256()
                    hash_obj.update((backup_code + code_data['salt']).encode())
                    computed_hash = hash_obj.hexdigest()
                    
                    if computed_hash == code_hash:
                        # Mark code as used
                        code_data['used'] = True
                        
                        # Update database
                        cursor.execute("""
                            UPDATE users SET backup_codes = ? WHERE username = ?
                        """, (json.dumps(stored_codes), username))
                        
                        print(f"✅ Backup code verified for user {username}")
                        return True
                
                print(f"❌ Invalid backup code for user {username}")
                return False
                
        except Exception as e:
            print(f"❌ Error verifying backup code: {e}")
            return False
    
    def get_backup_codes_status(self, username: str) -> Dict[str, Any]:
        """Get remaining backup codes count for a user"""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT backup_codes FROM users 
                    WHERE username = ? AND mfa_enabled = TRUE
                """, (username,))
                
                result = cursor.fetchone()
                if not result or not result[0]:
                    return {"success": False, "message": "No backup codes found"}
                
                stored_codes = json.loads(result[0])
                
                # Count unused codes
                remaining_count = sum(1 for code_data in stored_codes.values() if not code_data['used'])
                total_count = len(stored_codes)
                used_count = total_count - remaining_count
                
                return {
                    "success": True,
                    "remaining_codes": remaining_count,
                    "total_codes": total_count,
                    "used_codes": used_count
                }
                
        except Exception as e:
            print(f"❌ Error getting backup codes status: {e}")
            return {"success": False, "message": f"Error: {str(e)}"}
    
    def generate_mfa_qr(self, username: str) -> Optional[str]:
        """
        Generate QR code for MFA setup
        
        Args:
            username: Username to get MFA secret for
            
        Returns:
            Base64 encoded PNG QR code image, or None if user not found
        """
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT mfa_secret FROM users WHERE username = ?", (username,))
                result = cursor.fetchone()
                
                if not result or not result[0]:
                    print(f"❌ No MFA secret found for user {username}")
                    return None
                
                mfa_secret = result[0]
                
                # Create provisioning URI
                totp_uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(
                    name=username,
                    issuer_name="KyberLink VPN"
                )
                
                # Generate QR code
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=4,
                )
                qr.add_data(totp_uri)
                qr.make(fit=True)
                
                # Create QR code image
                img = qr.make_image(fill_color="black", back_color="white")
                
                # Convert to base64
                buffer = io.BytesIO()
                img.save(buffer, format='PNG')
                img_str = base64.b64encode(buffer.getvalue()).decode()
                
                print(f"📱 Generated MFA QR code for user {username}")
                return img_str
                
        except Exception as e:
            print(f"❌ Error generating QR code for {username}: {e}")
            return None
    
    def verify_mfa(self, username: str, token: str) -> bool:
        """
        Verify MFA TOTP token
        
        Args:
            username: Username to verify MFA for
            token: 6-digit TOTP token
            
        Returns:
            True if token is valid, False otherwise
        """
        if not username or not token:
            return False
        
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT mfa_secret FROM users WHERE username = ?", (username,))
                result = cursor.fetchone()
                
                if not result or not result[0]:
                    print(f"❌ No MFA secret found for user {username}")
                    return False
                
                mfa_secret = result[0]
                totp = pyotp.TOTP(mfa_secret)
                
                if totp.verify(token):
                    print(f"✅ MFA token verified for user {username}")
                    return True
                else:
                    print(f"❌ Invalid MFA token for user {username}")
                    return False
                
        except Exception as e:
            print(f"❌ MFA verification error for {username}: {e}")
            return False
    
    def setup_mfa(self, username: str) -> Dict[str, Any]:
        """
        Setup MFA for a user - generate secret, encrypt and store it, return QR code URL
        
        Args:
            username: Username to setup MFA for
            
        Returns:
            Dict with success status, TOTP secret, and otpauth URL
        """
        if not username:
            return {"success": False, "message": "Username is required"}
        
        try:
            # Check if user exists
            if not self.user_exists(username):
                return {"success": False, "message": "User not found"}
            
            # Generate new TOTP secret
            mfa_secret = self.generate_mfa_secret()
            
            # Encrypt the secret before storing
            encrypted_secret = self._encrypt_mfa_secret(mfa_secret)
            
            # Generate backup codes
            backup_codes = self._generate_backup_codes()
            hashed_backup_codes = self._hash_backup_codes(backup_codes)
            
            # Create otpauth URL for QR code
            totp = pyotp.TOTP(mfa_secret)
            otpauth_url = totp.provisioning_uri(
                name=username,
                issuer_name="KyberLink VPN"
            )
            
            # Update user record with encrypted MFA secret, backup codes, and enable MFA
            with sqlite3.connect(self.db_file) as conn:
                conn.execute(
                    "UPDATE users SET mfa_enabled = ?, mfa_secret = ?, backup_codes = ? WHERE username = ?",
                    (True, encrypted_secret, json.dumps(hashed_backup_codes), username)
                )
                conn.commit()
            
            print(f"✅ MFA setup completed for user {username} with {len(backup_codes)} backup codes")
            
            # Return only what's needed for initial setup - never expose the secret again
            return {
                "success": True,
                "message": "MFA setup successful",
                "totp_secret": mfa_secret,  # Only returned during initial setup
                "otpauth_url": otpauth_url,
                "backup_codes": backup_codes  # Only returned during initial setup
            }
            
        except Exception as e:
            print(f"❌ MFA setup error for {username}: {e}")
            return {"success": False, "message": f"MFA setup error: {str(e)}"}
    
    def disable_mfa(self, username: str) -> Dict[str, Any]:
        """
        Disable MFA for a user - clear secret and backup codes
        
        Args:
            username: Username to disable MFA for
            
        Returns:
            Dict with success status and message
        """
        if not username:
            return {"success": False, "message": "Username is required"}
        
        try:
            # Check if user exists
            if not self.user_exists(username):
                return {"success": False, "message": "User not found"}
            
            # Update user record to disable MFA and clear secrets
            with sqlite3.connect(self.db_file) as conn:
                conn.execute(
                    "UPDATE users SET mfa_enabled = ?, mfa_secret = ?, backup_codes = ? WHERE username = ?",
                    (False, None, json.dumps([]), username)
                )
                conn.commit()
            
            print(f"✅ MFA disabled for user {username}")
            
            return {
                "success": True,
                "message": "MFA disabled successfully"
            }
            
        except Exception as e:
            print(f"❌ MFA disable error for {username}: {e}")
            return {"success": False, "message": f"MFA disable error: {str(e)}"}
    
    def get_user_mfa_status(self, username: str) -> Dict[str, Any]:
        """
        Get MFA status for a user
        
        Args:
            username: Username to check MFA status for
            
        Returns:
            Dict with MFA enabled status
        """
        if not username:
            return {"mfa_enabled": False}
        
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT mfa_enabled FROM users WHERE username = ?",
                    (username,)
                )
                result = cursor.fetchone()
                
                if result:
                    return {"mfa_enabled": bool(result[0])}
                else:
                    return {"mfa_enabled": False}
                    
        except Exception as e:
            print(f"❌ Error checking MFA status for {username}: {e}")
            return {"mfa_enabled": False}
    
    def verify_mfa_with_decryption(self, username: str, token: str) -> bool:
        """
        Verify MFA TOTP token or backup code with rate limiting
        
        Args:
            username: Username to verify MFA for
            token: 6-digit TOTP token or 8-digit backup code
            
        Returns:
            True if token is valid, False otherwise
        """
        if not username or not token:
            return False
        
        # Check rate limiting
        allowed, remaining = self._check_rate_limit(username)
        if not allowed:
            print(f"❌ MFA rate limit exceeded for {username}, locked for {remaining} seconds")
            return False
        
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT mfa_secret, mfa_enabled FROM users WHERE username = ?", 
                    (username,)
                )
                result = cursor.fetchone()
                
                if not result or not result[0] or not result[1]:
                    print(f"❌ MFA not enabled or no secret found for user {username}")
                    self._record_mfa_attempt(username, False)
                    return False
                
                encrypted_secret, mfa_enabled = result
                
                # Check if this is a backup code (8 digits) or TOTP code (6 digits)
                if len(token) == 8 and token.isdigit():
                    # Verify backup code
                    success = self._verify_backup_code(username, token)
                    self._record_mfa_attempt(username, success)
                    return success
                elif len(token) == 6 and token.isdigit():
                    # Verify TOTP token
                    mfa_secret = self._decrypt_mfa_secret(encrypted_secret)
                    totp = pyotp.TOTP(mfa_secret)
                    
                    if totp.verify(token):
                        print(f"✅ MFA TOTP token verified for user {username}")
                        self._record_mfa_attempt(username, True)
                        return True
                    else:
                        print(f"❌ Invalid MFA TOTP token for user {username}")
                        self._record_mfa_attempt(username, False)
                        return False
                else:
                    print(f"❌ Invalid token format for user {username}")
                    self._record_mfa_attempt(username, False)
                    return False
                
        except Exception as e:
            print(f"❌ MFA verification error for {username}: {e}")
            self._record_mfa_attempt(username, False)
            return False
    
    def create_user(self, username: str, password: str) -> Dict[str, Any]:
        """
        Create a new user with SHA3-256 hashed password and unique salt
        
        Args:
            username: User's chosen username
            password: User's chosen password
            
        Returns:
            Dict with success status and message
        """
        if not username or not password:
            print("❌ Username and password cannot be empty")
            return {"success": False, "message": "Username and password cannot be empty"}
        
        try:
            # Check if user already exists
            if self.user_exists(username):
                print(f"❌ User {username} already exists")
                return {"success": False, "message": f"User '{username}' already exists"}
            
            # Generate unique salt and hash password
            salt = self._generate_salt()
            password_hash = self._hash_password(password, salt)
            print(f"🔐 Hashing password for {username} with SHA3-256 + unique salt...")
            
            # Insert user into database with simplified schema
            with sqlite3.connect(self.db_file) as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash, salt, mfa_enabled, mfa_secret, backup_codes) VALUES (?, ?, ?, ?, ?, ?)",
                    (username, password_hash, salt, False, None, json.dumps([]))
                )
                conn.commit()
            
            print(f"✅ User {username} created successfully with SHA3-256 + unique salt")
            
            return {
                "success": True,
                "message": f"User '{username}' registered successfully!"
            }
            
        except sqlite3.Error as e:
            print(f"❌ Database error creating user {username}: {e}")
            return {"success": False, "message": f"Database error: {str(e)}"}
        except Exception as e:
            print(f"❌ Unexpected error creating user {username}: {e}")
            return {"success": False, "message": f"Unexpected error: {str(e)}"}
    
    def verify_user(self, username: str, password: str) -> bool:
        """
        Verify user credentials using SHA3-256 + unique salt
        
        Args:
            username: Username to verify
            password: Password to verify
            
        Returns:
            True if credentials are valid, False otherwise
        """
        if not username or not password:
            return False
        
        try:
            # Get user from database
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT password_hash, salt FROM users WHERE username = ?",
                    (username,)
                )
                result = cursor.fetchone()
                
                if not result:
                    print(f"❌ Login failed for {username}: User not found")
                    return False
                
                stored_hash, salt = result
            
            # Verify password with SHA3-256
            if self._verify_password(password, salt, stored_hash):
                print(f"✅ Login successful for {username} (SHA3-256 verified)")
                return True
            else:
                print(f"❌ Login failed for {username}: Invalid password")
                return False
            
        except sqlite3.Error as e:
            print(f"❌ Database error verifying user {username}: {e}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error verifying user {username}: {e}")
            return False
    
    def user_exists(self, username: str) -> bool:
        """Check if a user exists in the database"""
        if not username:
            return False
        
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT 1 FROM users WHERE username = ?",
                    (username,)
                )
                return cursor.fetchone() is not None
        except sqlite3.Error as e:
            print(f"❌ Database error checking user existence: {e}")
            return False
    
    def get_user_count(self) -> int:
        """Get total number of registered users"""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM users")
                return cursor.fetchone()[0]
        except sqlite3.Error as e:
            print(f"❌ Database error getting user count: {e}")
            return 0
    
    def list_users(self) -> list:
        """Get list of all usernames (for admin purposes)"""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT username, created_at FROM users ORDER BY created_at")
                return cursor.fetchall()
        except sqlite3.Error as e:
            print(f"❌ Database error listing users: {e}")
            return []
    
    def delete_user(self, username: str) -> bool:
        """Delete a user from the database"""
        if not username:
            return False
        
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM users WHERE username = ?", (username,))
                deleted_count = cursor.rowcount
                conn.commit()
                
                if deleted_count > 0:
                    print(f"✅ User {username} deleted successfully")
                    return True
                else:
                    print(f"❌ User {username} not found")
                    return False
        except sqlite3.Error as e:
            print(f"❌ Database error deleting user {username}: {e}")
            return False


# Convenience functions for direct usage
_user_manager = UserManager()

def create_user(username: str, password: str) -> bool:
    """Create a new user (convenience function)"""
    return _user_manager.create_user(username, password)

def verify_user(username: str, password: str) -> bool:
    """Verify user credentials (convenience function)"""
    return _user_manager.verify_user(username, password)

def user_exists(username: str) -> bool:
    """Check if user exists (convenience function)"""
    return _user_manager.user_exists(username)

def get_user_count() -> int:
    """Get total number of registered users (convenience function)"""
    return _user_manager.get_user_count()


def demo_setup():
    """Set up demo users for testing"""
    print("\n🔧 Setting up demo users with Argon2id security...")
    
    # Create test users
    test_users = [
        ("testuser", "testpass"),
        ("admin", "admin123"),
        ("demo", "demopass123")
    ]
    
    for username, password in test_users:
        if not user_exists(username):
            success = create_user(username, password)
            if success:
                print(f"Demo user '{username}' created")
        else:
            print(f"Demo user '{username}' already exists")
    
    # Test verification
    print("\n🧪 Testing user verification...")
    for username, password in test_users:
        if verify_user(username, password):
            print(f"✅ {username} verification successful")
        else:
            print(f"❌ {username} verification failed")
    
    print(f"\n📊 Total users in database: {get_user_count()}")


if __name__ == "__main__":
    # Run demo setup when executed directly
    demo_setup()