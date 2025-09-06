#!/usr/bin/env python3
"""
User Management System for Quantum-Resistant VPN
===============================================

Secure user registration and authentication system with SHA3-256 password hashing.
"""

import json
import os
import secrets
import hashlib
from typing import Dict, Any, Optional


class UserManager:
    """Manages user registration and authentication"""
    
    def __init__(self, users_file: str = "users.json"):
        self.users_file = users_file
        self.users_data = self._load_users()
    
    def _load_users(self) -> Dict[str, Any]:
        """Load users from JSON file"""
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                print(f"Warning: Could not load {self.users_file}, starting with empty user database")
                return {}
        return {}
    
    def _save_users(self) -> None:
        """Save users to JSON file"""
        try:
            with open(self.users_file, 'w') as f:
                json.dump(self.users_data, f, indent=2)
        except IOError as e:
            print(f"Error saving users: {e}")
    
    def _hash_password(self, password: str, salt: bytes) -> str:
        """Hash password with SHA3-256 and salt"""
        # Combine password and salt
        password_bytes = password.encode('utf-8')
        combined = salt + password_bytes
        
        # Hash with SHA3-256
        hash_obj = hashlib.sha3_256(combined)
        return hash_obj.hexdigest()
    
    def create_user(self, username: str, password: str) -> bool:
        """
        Create a new user with hashed password
        
        Args:
            username: User's chosen username
            password: User's chosen password
            
        Returns:
            True if user created successfully, False if username already exists
        """
        if not username or not password:
            print("❌ Username and password cannot be empty")
            return False
        
        # Check if user already exists
        if username in self.users_data:
            print(f"❌ User {username} already exists")
            return False
        
        # Generate random salt (32 bytes = 256 bits)
        salt = secrets.token_bytes(32)
        
        # Hash password with salt
        password_hash = self._hash_password(password, salt)
        
        # Store user data
        self.users_data[username] = {
            "salt": salt.hex(),  # Store salt as hex string
            "hash": password_hash,
            "created_at": __import__('time').time()
        }
        
        # Save to file
        self._save_users()
        
        print(f"✅ User {username} created")
        return True
    
    def verify_user(self, username: str, password: str) -> bool:
        """
        Verify user credentials
        
        Args:
            username: Username to verify
            password: Password to verify
            
        Returns:
            True if credentials are valid, False otherwise
        """
        if not username or not password:
            print("❌ Username and password cannot be empty")
            return False
        
        # Check if user exists
        if username not in self.users_data:
            print(f"❌ Login failed for {username}: User not found")
            return False
        
        user_data = self.users_data[username]
        
        # Get stored salt and hash
        stored_salt = bytes.fromhex(user_data["salt"])
        stored_hash = user_data["hash"]
        
        # Hash entered password with stored salt
        entered_hash = self._hash_password(password, stored_salt)
        
        # Compare hashes
        if entered_hash == stored_hash:
            print(f"✅ Login successful for {username}")
            return True
        else:
            print(f"❌ Login failed for {username}: Invalid password")
            return False
    
    def get_user_count(self) -> int:
        """Get total number of registered users"""
        return len(self.users_data)
    
    def user_exists(self, username: str) -> bool:
        """Check if a user exists"""
        return username in self.users_data


# Convenience functions for direct usage
_user_manager = UserManager()

def create_user(username: str, password: str) -> bool:
    """Create a new user (convenience function)"""
    return _user_manager.create_user(username, password)

def verify_user(username: str, password: str) -> bool:
    """Verify user credentials (convenience function)"""
    return _user_manager.verify_user(username, password)

def get_user_count() -> int:
    """Get total number of registered users (convenience function)"""
    return _user_manager.get_user_count()


def demo_setup():
    """Set up demo user for testing"""
    print("\n🔧 Setting up demo user...")
    success = create_user("testuser", "testpass")
    if success:
        print("Demo user 'testuser' created with password 'testpass'")
    else:
        print("Demo user 'testuser' already exists")
    
    # Test verification
    print("\n🧪 Testing user verification...")
    if verify_user("testuser", "testpass"):
        print("✅ Demo user verification successful")
    else:
        print("❌ Demo user verification failed")


if __name__ == "__main__":
    # Run demo setup when executed directly
    demo_setup()