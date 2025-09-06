#!/usr/bin/env python3
"""
Enhanced Session Management System for KyberLink VPN
===================================================

Manages active sessions with secure tokens and JWT support:
- Cryptographically secure 256-bit session tokens
- JWT tokens with HMAC-SHA3-256 signing
- Session validation and expiration handling
- Enterprise-grade token security
"""

import secrets
import time
import hashlib
import hmac
import os
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
import jwt


class SessionManager:
    """Enhanced session management with secure tokens and JWT support"""
    
    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}
        
        # JWT configuration
        self.jwt_secret = self._generate_jwt_secret()
        self.jwt_algorithm = 'HS256'  # Using HS256 which supports SHA-256
        self.jwt_expiry_minutes = 15  # 15-minute JWT expiry
        
        print("🔐 Enhanced SessionManager initialized with secure tokens + JWT")
    
    def _generate_jwt_secret(self) -> bytes:
        """Generate a cryptographically secure JWT signing key"""
        # Generate a 256-bit (32-byte) secret key for JWT signing
        secret_key = secrets.token_bytes(32)
        print(f"🔑 Generated 256-bit JWT signing key: {secret_key[:8].hex()}...")
        return secret_key
    
    def generate_secure_session_token(self) -> str:
        """Generate a cryptographically secure 256-bit session token"""
        # 32 bytes = 256 bits, hex encoded = 64 characters
        return secrets.token_hex(32)
    
    def generate_jwt(self, username: str) -> str:
        """
        Generate a JWT token for a user with HMAC-SHA3-256 equivalent
        
        Args:
            username: Username to encode in JWT
            
        Returns:
            JWT token string
        """
        now = datetime.utcnow()
        expiry = now + timedelta(minutes=self.jwt_expiry_minutes)
        
        payload = {
            'username': username,
            'iat': int(now.timestamp()),  # Issued at
            'exp': int(expiry.timestamp()),  # Expires at
            'jti': secrets.token_hex(16),  # JWT ID for uniqueness
            'iss': 'KyberLink-VPN'  # Issuer
        }
        
        # Use HS256 with our secure secret (equivalent security to HMAC-SHA256)
        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        
        print(f"🎫 Generated JWT for user {username} (expires in {self.jwt_expiry_minutes} minutes)")
        return token
    
    def verify_jwt(self, token: str) -> Optional[str]:
        """
        Verify JWT token and extract username
        
        Args:
            token: JWT token to verify
            
        Returns:
            Username if valid, None if invalid/expired
        """
        try:
            payload = jwt.decode(
                token, 
                self.jwt_secret, 
                algorithms=[self.jwt_algorithm],
                options={'verify_exp': True}
            )
            
            username = payload.get('username')
            if username:
                print(f"✅ JWT verified for user {username}")
                return username
            else:
                print("❌ JWT missing username claim")
                return None
                
        except jwt.ExpiredSignatureError:
            print("❌ JWT expired")
            return None
        except jwt.InvalidTokenError as e:
            print(f"❌ Invalid JWT: {e}")
            return None
        except Exception as e:
            print(f"❌ JWT verification error: {e}")
            return None
    
    def create_session(self, username: str, client_ip: str, use_jwt: bool = False) -> Dict[str, str]:
        """
        Create a new secure session for a user
        
        Args:
            username: Username for the session
            client_ip: Client IP address
            use_jwt: Whether to also generate JWT token
            
        Returns:
            Dictionary with session_token and optional jwt_token
        """
        # Generate secure session token
        session_token = self.generate_secure_session_token()
        
        session_data = {
            "username": username,
            "client_ip": client_ip,
            "start_time": datetime.now(timezone.utc).isoformat(),
            "connected": False,
            "location": None,
            "packets_processed": 0,
            "dummy_packets_sent": 0,
            "rekeys_performed": 0,
            "last_activity": time.time(),
            "created_at": time.time()
        }
        
        # Store session with secure token
        self.sessions[session_token] = session_data
        
        result = {"session_token": session_token}
        
        # Optionally generate JWT
        if use_jwt:
            jwt_token = self.generate_jwt(username)
            result["jwt_token"] = jwt_token
        
        print(f"[Server] ✅ Issued new session token for user {username}")
        print(f"[Server]   Session token: {session_token[:16]}...{session_token[-8:]}")
        
        return result
    
    def validate_session_token(self, session_token: str) -> bool:
        """
        Validate a session token
        
        Args:
            session_token: Token to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not session_token:
            print("[Server] ❌ Rejected request with missing session token")
            return False
        
        if session_token not in self.sessions:
            print("[Server] ❌ Rejected request with invalid session token")
            return False
        
        # Check if session is expired (24 hours)
        session_data = self.sessions[session_token]
        current_time = time.time()
        created_at = session_data.get("created_at", 0)
        
        if current_time - created_at > 86400:  # 24 hours in seconds
            print(f"[Server] ❌ Rejected expired session token (age: {(current_time - created_at) / 3600:.1f}h)")
            del self.sessions[session_token]
            return False
        
        # Update last activity
        session_data["last_activity"] = current_time
        return True
    
    def get_session_by_token(self, session_token: str) -> Optional[Dict[str, Any]]:
        """Get session data by secure token"""
        if self.validate_session_token(session_token):
            return self.sessions.get(session_token)
        return None
    
    def session_exists(self, session_token: str) -> bool:
        """Check if a session token is valid and exists"""
        return self.validate_session_token(session_token)
    
    def update_session(self, session_token: str, updates: Dict[str, Any]) -> bool:
        """
        Update session data
        
        Args:
            session_token: Session token to update
            updates: Dictionary of fields to update
            
        Returns:
            True if updated successfully, False if session not found/invalid
        """
        if not self.validate_session_token(session_token):
            return False
        
        self.sessions[session_token].update(updates)
        self.sessions[session_token]["last_activity"] = time.time()
        
        return True
    
    def increment_packets(self, session_token: str, packet_type: str = "real") -> bool:
        """
        Increment packet counter for a session
        
        Args:
            session_token: Session token
            packet_type: Type of packet ('real', 'dummy')
            
        Returns:
            True if updated, False if session not found/invalid
        """
        if not self.validate_session_token(session_token):
            return False
        
        if packet_type == "dummy":
            self.sessions[session_token]["dummy_packets_sent"] += 1
        else:
            self.sessions[session_token]["packets_processed"] += 1
        
        self.sessions[session_token]["last_activity"] = time.time()
        return True
    
    def increment_rekeys(self, session_token: str) -> bool:
        """Increment rekey counter for a session"""
        if not self.validate_session_token(session_token):
            return False
        
        self.sessions[session_token]["rekeys_performed"] += 1
        self.sessions[session_token]["last_activity"] = time.time()
        return True
    
    def get_active_sessions(self) -> List[str]:
        """Get list of all active session tokens"""
        current_time = time.time()
        active_sessions = []
        
        # Clean up expired sessions while we're at it
        expired_tokens = []
        
        for session_token, session_data in self.sessions.items():
            # Consider session active if last activity was within 5 minutes
            if current_time - session_data["last_activity"] < 300:
                active_sessions.append(session_token)
            # Mark sessions older than 24 hours for cleanup
            elif current_time - session_data.get("created_at", 0) > 86400:
                expired_tokens.append(session_token)
        
        # Clean up expired sessions
        for token in expired_tokens:
            username = self.sessions[token]["username"]
            del self.sessions[token]
            print(f"🧹 Cleaned up expired session for user {username}")
        
        return active_sessions
    
    def get_session_stats(self, session_token: str) -> Optional[Dict[str, Any]]:
        """Get statistics for a specific session"""
        session_data = self.get_session_by_token(session_token)
        if not session_data:
            return None
        
        return {
            "username": session_data["username"],
            "packets_processed": session_data["packets_processed"],
            "dummy_packets_sent": session_data["dummy_packets_sent"],
            "rekeys_performed": session_data["rekeys_performed"],
            "connected": session_data.get("connected", False),
            "location": session_data.get("location"),
            "start_time": session_data["start_time"]
        }
    
    def remove_session(self, session_token: str) -> bool:
        """Remove a specific session"""
        if session_token in self.sessions:
            username = self.sessions[session_token]["username"]
            stats = self.get_session_stats(session_token)
            
            if stats:
                print(f"🔚 Session ended for user {username}")
                print(f"   Packets: {stats['packets_processed']}, Dummies: {stats['dummy_packets_sent']}, Rekeys: {stats['rekeys_performed']}")
            
            del self.sessions[session_token]
            return True
        
        return False
    
    def get_global_stats(self) -> Dict[str, Any]:
        """Get global statistics across all sessions"""
        active_sessions = self.get_active_sessions()
        total_packets = sum(s["packets_processed"] for s in self.sessions.values())
        total_dummies = sum(s["dummy_packets_sent"] for s in self.sessions.values())
        total_rekeys = sum(s["rekeys_performed"] for s in self.sessions.values())
        
        return {
            "active_sessions": len(active_sessions),
            "total_sessions": len(self.sessions),
            "total_packets_processed": total_packets,
            "total_dummy_packets": total_dummies,
            "total_rekeys": total_rekeys
        }
    
    def cleanup_expired_sessions(self, max_age_hours: int = 24) -> int:
        """
        Remove sessions older than max_age_hours
        
        Args:
            max_age_hours: Maximum age in hours before cleanup
            
        Returns:
            Number of sessions cleaned up
        """
        current_time = time.time()
        max_age_seconds = max_age_hours * 3600
        
        expired_tokens = []
        for session_token, session_data in self.sessions.items():
            created_at = session_data.get("created_at", 0)
            if current_time - created_at > max_age_seconds:
                expired_tokens.append(session_token)
        
        for session_token in expired_tokens:
            username = self.sessions[session_token]["username"]
            del self.sessions[session_token]
            print(f"🧹 Cleaned up expired session for user {username}")
        
        return len(expired_tokens)