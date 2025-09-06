#!/usr/bin/env python3
"""
KyberLink VPN - Permanent NO-LOGS Mode
=======================================

Enforces absolute no-logs policy with zero logging capability.
No debug mode, no development mode - permanent privacy protection.
"""

import os
import sys
import logging

# Permanent no-logs enforcement - no environment variables, no overrides
PERMANENT_NO_LOGS_MODE = True

def silence_all_logging():
    """Permanently silence all logging systems"""
    # Disable all Python logging
    logging.disable(logging.CRITICAL)
    
    # Override all loggers to CRITICAL level
    logging.getLogger().setLevel(logging.CRITICAL)
    logging.getLogger('werkzeug').setLevel(logging.CRITICAL)
    logging.getLogger('flask').setLevel(logging.CRITICAL)
    logging.getLogger('gunicorn').setLevel(logging.CRITICAL)
    
    # Redirect stdout/stderr to devnull in production
    try:
        devnull = open(os.devnull, 'w')
        sys.stdout = devnull
        sys.stderr = devnull
    except:
        pass

def generic_error_response(operation: str = "Operation") -> str:
    """Return only generic error messages - no details ever"""
    return f"❌ {operation} failed. Please try again."

def startup_message():
    """Single startup message only"""
    # Temporarily restore stdout for startup message only
    original_stdout = sys.__stdout__
    sys.stdout = original_stdout
    print("✅ KyberLink VPN started. Strict NO-LOGS policy enforced by default.")
    # Immediately silence again
    silence_all_logging()

# Initialize permanent no-logs mode
silence_all_logging()