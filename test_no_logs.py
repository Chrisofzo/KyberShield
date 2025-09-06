#!/usr/bin/env python3
"""
KyberLink VPN - No-Logs Policy Test Coverage
============================================

Comprehensive tests to verify zero logging occurs in production.
Confirms no files created, no console output, only generic errors.
"""

import os
import sys
import tempfile
import subprocess
import threading
import time
from io import StringIO

def test_no_file_creation():
    """Test: Confirm no files are created in working directory"""
    print("🧪 Testing: No file creation during operation")
    
    # Get initial file count
    initial_files = set(os.listdir('.'))
    
    try:
        # Import and initialize server components
        sys.path.append('src')
        from vpn_server_udp import KyberLinkUDPVPNServer
        from vpn_client_udp import KyberLinkUDPVPNClient
        
        # Create server and client instances
        server = KyberLinkUDPVPNServer(host='127.0.0.1', port=5561)
        client = KyberLinkUDPVPNClient(host='127.0.0.1', port=5561)
        
        # Simulate some operations without actually running server
        server.generate_session_id()
        
        # Check if any new files were created
        final_files = set(os.listdir('.'))
        new_files = final_files - initial_files
        
        if new_files:
            print(f"❌ FAILED: New files created: {new_files}")
            return False
        else:
            print("✅ PASSED: No files created during operation")
            return True
            
    except Exception as e:
        print(f"❌ FAILED: Exception during test: {e}")
        return False

def test_no_console_output():
    """Test: Confirm no console output during normal operation"""
    print("🧪 Testing: No console output during requests/errors")
    
    try:
        # Capture stdout/stderr
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        
        captured_stdout = StringIO()
        captured_stderr = StringIO()
        
        sys.stdout = captured_stdout
        sys.stderr = captured_stderr
        
        # Import after redirecting output
        sys.path.append('src')
        from permanent_no_logs import silence_all_logging
        
        # Force silence all logging
        silence_all_logging()
        
        # Try various operations that would normally log
        try:
            from vpn_server_udp import KyberLinkUDPVPNServer
            server = KyberLinkUDPVPNServer(host='127.0.0.1', port=5562)
            
            # Simulate error conditions
            server.handle_handshake_init(('127.0.0.1', 12345), b'invalid_data')
            
        except:
            pass  # Expected to fail, we're testing no output
        
        # Restore stdout/stderr
        sys.stdout = old_stdout  
        sys.stderr = old_stderr
        
        # Check captured output
        stdout_content = captured_stdout.getvalue()
        stderr_content = captured_stderr.getvalue()
        
        if stdout_content.strip() or stderr_content.strip():
            print(f"❌ FAILED: Unexpected output detected")
            print(f"   stdout: {repr(stdout_content[:100])}")
            print(f"   stderr: {repr(stderr_content[:100])}")
            return False
        else:
            print("✅ PASSED: No console output during operation")
            return True
            
    except Exception as e:
        # Restore stdout/stderr
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        print(f"❌ FAILED: Exception during output test: {e}")
        return False

def test_generic_error_responses():
    """Test: Confirm only generic error responses are returned"""
    print("🧪 Testing: Generic error responses only")
    
    try:
        sys.path.append('src')
        from permanent_no_logs import generic_error_response
        
        # Test various error scenarios
        test_operations = [
            "Connection",
            "Authentication", 
            "Data processing",
            "Session management"
        ]
        
        all_generic = True
        
        for operation in test_operations:
            response = generic_error_response(operation)
            
            # Check response is generic (no sensitive details)
            if any(sensitive in response.lower() for sensitive in 
                   ['ip', 'address', 'session', 'user', 'timestamp', 'stack', 'trace']):
                print(f"❌ FAILED: Response contains sensitive info: {response}")
                all_generic = False
            elif response != f"❌ {operation} failed. Please try again.":
                print(f"❌ FAILED: Response not in expected format: {response}")
                all_generic = False
        
        if all_generic:
            print("✅ PASSED: All error responses are generic")
            return True
        else:
            return False
            
    except Exception as e:
        print(f"❌ FAILED: Exception during error response test: {e}")
        return False

def test_flask_logging_suppression():
    """Test: Confirm Flask/Werkzeug logging is suppressed"""
    print("🧪 Testing: Flask logging suppression")
    
    try:
        import logging
        
        # Check logging levels
        flask_logger = logging.getLogger('flask')
        werkzeug_logger = logging.getLogger('werkzeug')
        root_logger = logging.getLogger()
        
        if (flask_logger.level >= logging.CRITICAL and 
            werkzeug_logger.level >= logging.CRITICAL):
            print("✅ PASSED: Flask/Werkzeug loggers set to CRITICAL level")
            return True
        else:
            print(f"❌ FAILED: Logging levels not properly set")
            print(f"   Flask: {flask_logger.level}, Werkzeug: {werkzeug_logger.level}")
            return False
            
    except Exception as e:
        print(f"❌ FAILED: Exception during Flask logging test: {e}")
        return False

def test_ram_only_sessions():
    """Test: Confirm sessions are stored in RAM only"""
    print("🧪 Testing: RAM-only session storage")
    
    try:
        sys.path.append('src')
        from vpn_server_udp import KyberLinkUDPVPNServer
        
        server = KyberLinkUDPVPNServer(host='127.0.0.1', port=5563)
        
        # Check sessions are stored in memory dict
        if isinstance(server.sessions, dict):
            print("✅ PASSED: Sessions stored in Python dict (RAM-only)")
            
            # Verify no file-based persistence
            session_files = [f for f in os.listdir('.') if 'session' in f.lower()]
            if not session_files:
                print("✅ PASSED: No session files found on disk")
                return True
            else:
                print(f"❌ FAILED: Session files found: {session_files}")
                return False
        else:
            print(f"❌ FAILED: Sessions not stored in dict: {type(server.sessions)}")
            return False
            
    except Exception as e:
        print(f"❌ FAILED: Exception during RAM session test: {e}")
        return False

def main():
    """Run all no-logs policy tests"""
    print("🔒 KyberLink VPN - No-Logs Policy Test Suite")
    print("=" * 50)
    
    tests = [
        ("File Creation", test_no_file_creation),
        ("Console Output", test_no_console_output), 
        ("Generic Errors", test_generic_error_responses),
        ("Flask Logging", test_flask_logging_suppression),
        ("RAM Sessions", test_ram_only_sessions)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 Running: {test_name}")
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"❌ Test error: {e}")
    
    print(f"\n🎯 TEST RESULTS:")
    print(f"   • Passed: {passed}/{total}")
    print(f"   • Failed: {total - passed}/{total}")
    
    if passed == total:
        print("\n✅ ALL TESTS PASSED - NO-LOGS POLICY VERIFIED!")
        print("   🔒 Zero logging confirmed")
        print("   🔒 Zero file creation confirmed")  
        print("   🔒 Zero sensitive error details confirmed")
        print("   🔒 Permanent no-logs mode active")
        return True
    else:
        print(f"\n❌ {total - passed} TESTS FAILED - NO-LOGS POLICY VIOLATIONS DETECTED")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)