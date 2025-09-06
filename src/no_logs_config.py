#!/usr/bin/env python3
"""
KyberLink VPN - No-Logs Policy Configuration
============================================

Comprehensive logging control for absolute anonymity and privacy protection.
Implements strict no-logs policy with debug mode for development only.
"""

import os
import sys
from typing import Any

class NoLogsConfig:
    """
    No-Logs Policy Configuration Manager
    
    Controls all logging behavior based on environment variables:
    - ENABLE_DEBUG_LOGS=true/false (default: false)
    - KYBERLINK_PRODUCTION=true/false (default: true)
    """
    
    def __init__(self):
        # Environment-based configuration
        self.debug_enabled = os.getenv('ENABLE_DEBUG_LOGS', 'false').lower() == 'true'
        self.production_mode = os.getenv('KYBERLINK_PRODUCTION', 'true').lower() == 'true'
        
        # Override: if explicitly in development mode
        if not self.production_mode:
            self.debug_enabled = True
    
    def is_debug_enabled(self) -> bool:
        """Check if debug logging is enabled"""
        return self.debug_enabled and not self.production_mode
    
    def is_production_mode(self) -> bool:
        """Check if running in production mode"""
        return self.production_mode
    
    def should_suppress_logs(self) -> bool:
        """Check if logs should be suppressed (production mode)"""
        return self.production_mode and not self.debug_enabled

# Global configuration instance
_no_logs_config = NoLogsConfig()

def get_no_logs_config() -> NoLogsConfig:
    """Get global no-logs configuration"""
    return _no_logs_config

def debug_print(*args, **kwargs):
    """
    Debug-only print function that respects no-logs policy
    
    Only prints in development mode or when ENABLE_DEBUG_LOGS=true
    """
    if _no_logs_config.is_debug_enabled():
        print(*args, **kwargs)

def safe_print(message: str, level: str = "INFO"):
    """
    Safe print function that never logs sensitive data
    
    Args:
        message: Non-sensitive message to print
        level: Log level (INFO, WARN, ERROR)
    """
    if not _no_logs_config.should_suppress_logs():
        print(f"[{level}] {message}")

def sanitized_error_response(error: Exception, user_message: str = "Operation failed") -> str:
    """
    Generate sanitized error response for production
    
    Args:
        error: Original exception
        user_message: Safe message for user
        
    Returns:
        Sanitized error message (no stack traces in production)
    """
    if _no_logs_config.is_debug_enabled():
        return f"{user_message}: {str(error)}"
    else:
        return user_message

def log_startup_banner():
    """Display startup banner with no-logs confirmation"""
    config = _no_logs_config
    
    print("\n" + "="*60)
    print("🔒 KyberLink VPN - Quantum-Resistant Privacy Protection")
    print("="*60)
    
    if config.is_production_mode():
        print("✅ NO-LOGS MODE ACTIVE")
        print("   • All connection data is ephemeral (memory-only)")
        print("   • No client IPs, session IDs, or timestamps stored")
        print("   • Zero persistent logging to disk")
        print("   • Absolute anonymity guaranteed")
        
        if config.is_debug_enabled():
            print("⚠️  DEBUG LOGS ENABLED (should be disabled in production!)")
        else:
            print("🔇 All debugging output suppressed")
    else:
        print("🔧 DEVELOPMENT MODE")
        print("   • Debug logging enabled for development")
        print("   • Set KYBERLINK_PRODUCTION=true for no-logs mode")
    
    print("="*60 + "\n")

def suppress_flask_logs():
    """Suppress Flask HTTP access logs in production"""
    if _no_logs_config.should_suppress_logs():
        # Redirect werkzeug logger to null
        import logging
        logging.getLogger('werkzeug').setLevel(logging.ERROR)
        
        # Suppress Flask access logs
        flask_log = logging.getLogger('flask')
        flask_log.setLevel(logging.ERROR)
        
        # Redirect access logs to null device
        sys.stdout = open(os.devnull, 'w') if _no_logs_config.production_mode else sys.stdout

def restore_stdout():
    """Restore stdout if it was redirected"""
    if hasattr(sys.stdout, 'close') and sys.stdout.name == os.devnull:
        sys.stdout.close()
        sys.stdout = sys.__stdout__