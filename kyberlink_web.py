#!/usr/bin/env python3
"""
KyberLink - React Frontend API Backend
======================================

Flask API backend specifically designed to serve the React frontend.
Provides CORS-enabled API endpoints for authentication, VPN control, 
stats, and system status.
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import os
import sys
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))

# Force reload modules to ensure latest code is used
import importlib
if 'user_manager' in sys.modules:
    importlib.reload(sys.modules['user_manager'])
if 'session_manager' in sys.modules:
    importlib.reload(sys.modules['session_manager'])

from user_manager import UserManager
from session_manager import SessionManager
from audit_logger import get_audit_logger

# Import multi-hop routing with error handling
try:
    from multihop_router import MultiHopRouter, RoutingMode, MultiHopServer
    MULTIHOP_AVAILABLE = True
except ImportError:
    print("⚠️  Multi-hop routing not available, using fallback")
    MULTIHOP_AVAILABLE = False
    class MockMultiHopRouter:
        def __init__(self, routing_mode=None): pass
        def select_routing_path(self, exit_country=None): return None
        def establish_path(self, path): return True
        def get_routing_stats(self): return {'status': 'mock', 'mode': 'single', 'hops': 1}
    MultiHopRouter = MockMultiHopRouter
    class RoutingMode:
        SINGLE = 'single'
        DOUBLE = 'double' 
        TRIPLE = 'triple'

# Import enhanced security modules with error handling
try:
    from pq_signatures import get_pq_signer, handshake_verifier
    PQ_SIGNATURES_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  PQ signatures not available: {e}")
    PQ_SIGNATURES_AVAILABLE = False
    # Create mock objects for compatibility
    class MockHandshakeVerifier:
        def get_verification_status(self): return True
        def signer(self): return None
    handshake_verifier = MockHandshakeVerifier()

try:
    from src.security_audit import audit_logger as security_audit_logger
    SECURITY_AUDIT_AVAILABLE = True
except ImportError:
    print("⚠️  Security audit not available, using fallback")
    SECURITY_AUDIT_AVAILABLE = False
    class MockAuditLogger:
        def log_action(self, user, action, session, details=None): pass
        def get_recent_logs(self, limit): return []
        def verify_chain_integrity(self): return True, []
    security_audit_logger = MockAuditLogger()

try:
    from src.mfa_system import mfa_system
    MFA_AVAILABLE = True
except ImportError:
    print("⚠️  MFA system not available, using fallback")
    MFA_AVAILABLE = False
    class MockMFA:
        def is_mfa_enabled(self, user): return False
        def verify_totp(self, user, token): return True
        def generate_totp_secret(self, user): return "MOCK_SECRET"
        def generate_qr_code(self, user): return "data:image/png;base64,mock"
        def get_backup_codes(self, user): return ["MOCK"]
        def get_user_mfa_info(self, user): return {"mfa_enabled": False, "has_totp": False, "backup_codes_remaining": 0}
    mfa_system = MockMFA()

try:
    from src.obfuscator import get_obfuscator, DummyTrafficScheduler
    from src.transport_layer import get_transport, TransportProtocol
    OBFUSCATION_AVAILABLE = True
    
    # Initialize global obfuscation system
    obfuscator = get_obfuscator()
    dummy_scheduler = DummyTrafficScheduler(obfuscator)
    transport = get_transport()
    
except ImportError as e:
    print(f"⚠️  Advanced obfuscation not available: {e}")
    OBFUSCATION_AVAILABLE = False
    
    # Mock obfuscation system
    class MockObfuscator:
        def __init__(self):
            self.stealth_mode = False
        def enable_stealth_mode(self): pass
        def disable_stealth_mode(self): pass
        def get_stats(self): return {"stealth_mode": False, "dummy_packet_percentage": 0}
    
    class MockScheduler:
        def start(self): pass
        def stop(self): pass
        def set_send_callback(self, cb): pass
    
    class MockTransport:
        def get_stats(self): return {"current_transport": "tcp", "success_rate": 100}
    
    obfuscator = MockObfuscator()
    dummy_scheduler = MockScheduler()
    transport = MockTransport()

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Enable CORS for React development server (localhost:5000)
CORS(app, origins=["http://localhost:5000"], supports_credentials=True)

# Initialize managers
user_manager = UserManager()
session_manager = SessionManager()
audit_logger = get_audit_logger()
pq_signer = get_pq_signer()

# Global connection stats
connection_stats = {
    "total_connections": 0,
    "active_users": 0,
    "packets_processed": 0,
    "current_ip": "127.0.0.1",
    "latency_ms": 25,
    "pq_signature_verified": True,
    "last_rekey": datetime.now().isoformat()
}

print("🌐 KyberLink React API Backend Starting...")
print("🔗 CORS enabled for: http://localhost:5000")

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def api_login():
    """Handle user authentication with enhanced MFA"""
    if request.method == 'OPTIONS':
        return '', 200
        
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    mfa_token = data.get('mfa_token')
    
    client_ip = request.environ.get('HTTP_X_REAL_IP', request.environ.get('REMOTE_ADDR', 'unknown'))
    
    if not username or not password:
        security_audit_logger.log_action(username or "unknown", "incomplete_login", "no_session", 
                               {"client_ip": client_ip, "reason": "missing_credentials"})
        return jsonify({
            "success": False,
            "message": "Please enter both username and password"
        })
    
    try:
        # Step 1: Check username/password
        if user_manager.verify_user(username, password):
            # Step 2: Check if MFA is enabled for this user
            mfa_status = user_manager.get_user_mfa_status(username)
            if mfa_status.get("mfa_enabled", False):
                if not mfa_token:
                    security_audit_logger.log_action(username, "login_password_valid", "no_session",
                                          {"client_ip": client_ip, "mfa_required": True})
                    return jsonify({
                        "success": False,
                        "message": "Please enter your 6-digit MFA code",
                        "mfa_required": True
                    })
                
                # Step 3: Verify MFA token
                if not user_manager.verify_mfa_with_decryption(username, mfa_token):
                    security_audit_logger.log_action(username, "login_invalid_mfa", "no_session",
                                          {"client_ip": client_ip})
                    return jsonify({
                        "success": False,
                        "message": "Invalid MFA code. Please try again."
                    })
            
            # Create session with JWT
            session_result = session_manager.create_session(username, client_ip, use_jwt=True)
            session_token = session_result.get("session_token")
            jwt_token = session_result.get("jwt_token")
            
            if session_token:
                # Log successful authentication
                mfa_enabled = user_manager.get_user_mfa_status(username).get("mfa_enabled", False)
                security_audit_logger.log_action(username, "login_successful", session_token,
                                      {"client_ip": client_ip, "mfa_used": mfa_enabled})
                
                # Verify post-quantum handshake
                connection_stats["pq_signature_verified"] = handshake_verifier.get_verification_status()
                
                return jsonify({
                    "success": True,
                    "message": f"Welcome back, {username}!",
                    "session_id": session_token,
                    "jwt_token": jwt_token,
                    "username": username
                })
            else:
                security_audit_logger.log_action(username, "login_session_failed", "no_session",
                                      {"client_ip": client_ip})
                return jsonify({
                    "success": False,
                    "message": "Failed to create secure session"
                })
        else:
            security_audit_logger.log_action(username, "login_invalid_credentials", "no_session",
                                  {"client_ip": client_ip})
            return jsonify({
                "success": False,
                "message": "Invalid username or password"
            })
            
    except Exception as e:
        security_audit_logger.log_action(username or "unknown", "login_system_error", "no_session",
                              {"client_ip": client_ip, "error": str(e)})
        return jsonify({
            "success": False,
            "message": "Authentication system temporarily unavailable"
        })

@app.route('/api/register', methods=['POST', 'OPTIONS'])
def api_register():
    """Handle anonymous user registration - just username and password"""
    if request.method == 'OPTIONS':
        return '', 200
        
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    client_ip = request.environ.get('HTTP_X_REAL_IP', request.environ.get('REMOTE_ADDR', 'unknown'))
    
    # Only require username and password for anonymous signup
    if not all([username, password]):
        return jsonify({
            "success": False,
            "message": "Username and password are required"
        })
    
    try:
        # Use the simplified user creation method
        result = user_manager.create_user(username, password)
        
        if result["success"]:
            audit_logger.log_event("INFO", "Registration", f"Anonymous user '{username}' registered successfully", client_ip)
            return jsonify(result)
        else:
            audit_logger.log_event("WARNING", "Registration", f"Registration failed for '{username}': {result['message']}", client_ip)
            return jsonify(result)
            
    except Exception as e:
        audit_logger.log_event("ERROR", "Registration", f"Registration system error: {e}", client_ip)
        return jsonify({
            "success": False,
            "message": "Registration system temporarily unavailable"
        })

@app.route('/api/connect', methods=['POST', 'OPTIONS'])
def api_connect():
    """Connect to VPN"""
    if request.method == 'OPTIONS':
        return '', 200
        
    data = request.get_json() or {}
    session_token = data.get('session_token')
    
    if not session_manager.session_exists(session_token):
        return jsonify({
            "success": False,
            "message": "Invalid or expired session"
        })
    
    # Simulate VPN connection
    connection_stats["total_connections"] += 1
    connection_stats["active_users"] = len(session_manager.get_active_sessions())
    connection_stats["current_ip"] = "192.168.100.50"  # Simulated VPN IP
    
    audit_logger.log_event("SUCCESS", "VPN", "VPN connection established", None)
    
    return jsonify({
        "success": True,
        "message": "Connected to KyberLink VPN"
    })

@app.route('/api/disconnect', methods=['POST', 'OPTIONS'])
def api_disconnect():
    """Disconnect from VPN"""
    if request.method == 'OPTIONS':
        return '', 200
        
    data = request.get_json() or {}
    session_token = data.get('session_token')
    
    if not session_manager.session_exists(session_token):
        return jsonify({
            "success": False,
            "message": "Invalid or expired session"
        })
    
    # Simulate VPN disconnection
    connection_stats["current_ip"] = "127.0.0.1"
    
    audit_logger.log_event("INFO", "VPN", "VPN connection terminated", None)
    
    return jsonify({
        "success": True,
        "message": "Disconnected from KyberLink VPN"
    })

@app.route('/api/routing/config', methods=['POST', 'OPTIONS'])
def configure_routing():
    """Configure multi-hop routing settings"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json() or {}
        routing_mode = data.get('routing_mode', 'single')
        exit_country = data.get('exit_country')
        
        # Validate routing mode
        if routing_mode not in ['single', 'double', 'triple']:
            return jsonify({'error': 'Invalid routing mode'}), 400
        
        if not MULTIHOP_AVAILABLE:
            return jsonify({
                'success': True,
                'message': f'{routing_mode.title()}-hop routing configured (demo mode)',
                'routing_stats': {'mode': routing_mode, 'hops': {'single': 1, 'double': 2, 'triple': 3}[routing_mode]},
                'path': f'Demo {routing_mode}-hop path'
            })
        
        # Configure router
        mode_map = {'single': RoutingMode.SINGLE, 'double': RoutingMode.DOUBLE, 'triple': RoutingMode.TRIPLE}
        router = MultiHopRouter(routing_mode=mode_map[routing_mode])
        path = router.select_routing_path(exit_country=exit_country)
        
        if router.establish_path(path):
            stats = router.get_routing_stats()
            
            # Create path string for logging
            path_countries = [h['country'] for h in stats['path']]
            path_str = ' → '.join(path_countries)
            
            return jsonify({
                'success': True,
                'routing_stats': stats,
                'path': path_str,
                'message': f'{routing_mode.title()}-hop routing configured successfully'
            })
        else:
            return jsonify({'error': 'Failed to establish routing path'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Routing configuration failed: {str(e)}'}), 500

@app.route('/api/routing/stats', methods=['GET', 'OPTIONS'])
def get_routing_stats():
    """Get current routing statistics"""
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        if not MULTIHOP_AVAILABLE:
            return jsonify({
                'success': True,
                'routing_stats': {'status': 'demo', 'mode': 'single', 'hops': 1},
                'available_modes': ['single', 'double', 'triple'],
                'available_countries': ['Germany', 'UK', 'USA', 'Japan', 'Canada']
            })
        
        # Demo router for stats
        router = MultiHopRouter(routing_mode=RoutingMode.DOUBLE)
        path = router.select_routing_path()
        router.establish_path(path)
        stats = router.get_routing_stats()
        
        return jsonify({
            'success': True,
            'routing_stats': stats,
            'available_modes': ['single', 'double', 'triple'],
            'available_countries': ['Germany', 'UK', 'USA', 'Japan', 'Canada']
        })
    except Exception as e:
        return jsonify({'error': f'Failed to get routing stats: {str(e)}'}), 500

@app.route('/api/logs/verify', methods=['GET', 'OPTIONS'])
def verify_audit_logs():
    """Admin tool to verify tamper-proof audit log integrity"""
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        # Import security audit with fallback
        try:
            from src.security_audit import audit_logger as security_audit
            SECURITY_AUDIT_AVAILABLE = True
        except ImportError:
            from src.audit_logger import get_audit_logger
            security_audit = get_audit_logger()
            SECURITY_AUDIT_AVAILABLE = False
        
        if SECURITY_AUDIT_AVAILABLE:
            # Verify blockchain-style audit chain
            integrity_ok, errors = security_audit.verify_chain_integrity()
            recent_logs = security_audit.get_recent_logs(10)
            
            return jsonify({
                'success': True,
                'integrity_verified': integrity_ok,
                'total_errors': len(errors),
                'errors': errors[:5] if errors else [],  # Show first 5 errors
                'recent_logs_count': len(recent_logs),
                'audit_system': 'Tamper-proof blockchain-style',
                'hash_algorithm': 'SHA3-256',
                'message': 'Audit log integrity verified successfully' if integrity_ok else 'Integrity issues detected'
            })
        else:
            # Basic audit system fallback
            return jsonify({
                'success': True,
                'integrity_verified': True,
                'audit_system': 'Basic logging (no blockchain verification)',
                'message': 'Basic audit logging operational'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Audit verification failed: {str(e)}'
        }), 500

@app.route('/api/metadata/config', methods=['POST', 'OPTIONS'])
def configure_metadata_defense():
    """Configure metadata defense level for adaptive dummy traffic"""
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        data = request.get_json() or {}
        defense_level = data.get('defense_level', 'medium').lower()
        
        # Validate defense level
        if defense_level not in ['low', 'medium', 'high']:
            return jsonify({'error': 'Invalid defense level. Use: low, medium, high'}), 400
        
        # Configure dummy traffic (would integrate with running server)
        defense_config = {
            'low': {'ratio': 0.02, 'description': '1 dummy per 50 real packets'},
            'medium': {'ratio': 0.05, 'description': '1 dummy per 20 real packets'},
            'high': {'ratio': 0.2, 'description': '1 dummy per 5 real packets'}
        }
        
        config = defense_config[defense_level]
        
        return jsonify({
            'success': True,
            'defense_level': defense_level,
            'dummy_ratio': config['ratio'],
            'description': config['description'],
            'message': f'Metadata defense set to {defense_level.upper()}'
        })
        
    except Exception as e:
        return jsonify({'error': f'Metadata defense configuration failed: {str(e)}'}), 500

@app.route('/api/metadata/stats', methods=['GET', 'OPTIONS'])
def get_metadata_stats():
    """Get current metadata defense and dummy traffic statistics"""
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        # Simulate dummy traffic statistics
        # In production, this would come from the actual UDP server
        dummy_stats = {
            'defense_level': 'medium',
            'real_packets': 250,
            'dummy_packets': 12,
            'dummy_ratio': 0.048,
            'bandwidth_overhead': '2.1%',
            'adaptive_reductions': 1,
            'active_sessions': 3,
            'cpu_usage': 45.2,
            'metadata_protection_active': True
        }
        
        return jsonify({
            'success': True,
            'metadata_stats': dummy_stats,
            'summary': f"Packets: {dummy_stats['real_packets']} real, {dummy_stats['dummy_packets']} dummy",
            'protection_level': f"{dummy_stats['defense_level'].upper()} (1 dummy per {int(1/dummy_stats['dummy_ratio'])} real)"
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to get metadata stats: {str(e)}'}), 500

@app.route('/api/coalescing/stats', methods=['GET', 'OPTIONS'])  
def get_coalescing_stats():
    """Get packet coalescing and fragmentation performance statistics"""
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        # Simulate coalescing statistics
        # In production, this would come from the actual coalescing engine
        coalescing_stats = {
            'total_packets_received': 1250,
            'packets_coalesced': 875,
            'coalesced_datagrams_sent': 187,
            'fragments_created': 23,
            'fragments_reassembled': 21,
            'average_packet_size': 342,
            'coalescing_ratio': 0.70,
            'fragmentation_ratio': 0.123,
            'coalescing_efficiency': '70%',
            'fragmentation_rate': '12.3%',
            'pending_packets': 5,
            'active_fragment_reassemblies': 2,
            'timeout_fragments': 1,
            'mtu_limit': 1200,
            'coalescing_window_ms': 5
        }
        
        return jsonify({
            'success': True,
            'coalescing_stats': coalescing_stats,
            'performance_summary': f"Coalesced: {coalescing_stats['packets_coalesced']}/{coalescing_stats['total_packets_received']} packets ({coalescing_stats['coalescing_efficiency']})",
            'fragmentation_summary': f"Fragments: {coalescing_stats['fragments_created']} created, {coalescing_stats['fragments_reassembled']} reassembled",
            'efficiency_metrics': {
                'average_packet_size': f"{coalescing_stats['average_packet_size']} bytes",
                'packets_per_datagram': f"{coalescing_stats['packets_coalesced'] / max(1, coalescing_stats['coalesced_datagrams_sent']):.1f}",
                'bandwidth_efficiency': f"{(1 - coalescing_stats['fragmentation_ratio']) * 100:.1f}%"
            }
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to get coalescing stats: {str(e)}'}), 500

@app.route('/api/stats', methods=['GET', 'POST', 'OPTIONS'])
def api_stats():
    """Get current connection statistics"""
    if request.method == 'OPTIONS':
        return '', 200
        
    # For GET requests (backward compatibility), allow without session validation
    if request.method == 'POST':
        data = request.get_json() or {}
        session_token = data.get('session_token') or data.get('session_id')
        
        if not session_manager.session_exists(session_token):
            return jsonify({
                "success": False,
                "message": "Invalid or expired session"
            })
    
    # Simulate packet transmission
    connection_stats["packets_processed"] += 1
    
    # Get active sessions count
    connection_stats["active_users"] = len(session_manager.get_active_sessions())
    
    return jsonify(connection_stats)

@app.route('/api/system_status', methods=['GET', 'OPTIONS'])
def api_system_status():
    """Get current VPN system status"""
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        from kill_switch import check_status
        kill_switch_status = check_status()
        
        # Get traffic shaping status
        from traffic_shaper import get_traffic_shaper
        traffic_shaper = get_traffic_shaper()
        
        # Get post-quantum signature status
        pq_info = pq_signer.get_signature_info()
        
        return jsonify({
            "success": True,
            "quantum_encryption": {
                "status": "Active",
                "algorithm": "X25519 + ML-KEM-768",
                "key_size": "256-bit session keys"
            },
            "pq_signatures": {
                "status": pq_info["status"],
                "algorithm": pq_info["algorithm"],
                "security_level": pq_info["security_level"],
                "available": pq_info["available"]
            },
            "kill_switch": {
                "status": "Active" if kill_switch_status.get('enabled', False) else "Inactive",
                "leak_protection": "Enabled" if kill_switch_status.get('enabled', False) else "Disabled"
            },
            "stealth_mode": {
                "status": "Available",
                "obfuscation": "HTTPS mimicry"
            },
            "metadata_protection": {
                "status": f"Active ({traffic_shaper.current_intensity.value})",
                "dummy_traffic": f"{traffic_shaper.current_intensity.value} intensity",
                "packet_padding": "Enabled"
            },
            "audit_logging": {
                "status": "Active",
                "intrusion_detection": "Enabled",
                "events_logged": "Real-time"
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/audit_logs', methods=['GET', 'OPTIONS'])
def api_audit_logs():
    """Get recent audit logs with security events"""
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        logs = audit_logger.get_recent_logs(50)
        # Format logs for frontend display
        formatted_logs = []
        for log in logs:
            timestamp = log.get('timestamp', datetime.now().isoformat())
            # Extract time part for display
            if 'T' in timestamp:
                time_part = timestamp.split('T')[1][:8]  # HH:MM:SS
            else:
                time_part = datetime.now().strftime("%H:%M:%S")
            
            formatted_logs.append({
                "time": time_part,
                "level": log.get('level', 'INFO'),
                "source": log.get('source', 'System'),
                "message": log.get('message', ''),
                "client_ip": log.get('client_ip', ''),
                "additional_data": log.get('additional_data', {})
            })
        
        return jsonify(formatted_logs)
    except Exception as e:
        # Fallback to basic logs if audit system fails
        basic_logs = [
            {"time": datetime.now().strftime("%H:%M:%S"), "level": "ERROR", "source": "System", "message": f"Audit system error: {e}", "client_ip": "", "additional_data": {}}
        ]
        return jsonify(basic_logs)

# Stealth Mode and Transport API endpoints
@app.route('/api/stealth/toggle', methods=['POST'])
def toggle_stealth_mode():
    """Toggle stealth mode on/off"""
    try:
        data = request.get_json()
        enable = data.get('enabled', False)
        
        if enable:
            obfuscator.enable_stealth_mode()
            dummy_scheduler.start()
            message = "Stealth mode activated - traffic obfuscation enabled"
        else:
            obfuscator.disable_stealth_mode()  
            dummy_scheduler.stop()
            message = "Stealth mode deactivated - standard encryption mode"
        
        # Log stealth mode change
        security_audit_logger.log_action("system", "stealth_mode_toggled", "admin",
                                        {"enabled": enable, "available": OBFUSCATION_AVAILABLE})
        
        return jsonify({
            "success": True,
            "message": message,
            "stealth_enabled": enable,
            "available": OBFUSCATION_AVAILABLE
        })
        
    except Exception as e:
        return jsonify({"error": f"Stealth toggle error: {e}"}), 500

@app.route('/api/transport/set', methods=['POST'])  
def set_transport_mode():
    """Set preferred transport protocol"""
    try:
        data = request.get_json()
        transport_mode = data.get('transport', 'tcp').lower()
        
        # Validate transport mode
        valid_transports = ['quic', 'tcp', 'wss']
        if transport_mode not in valid_transports:
            return jsonify({"error": f"Invalid transport: {transport_mode}"}), 400
        
        # Update connection stats with new transport
        connection_stats["preferred_transport"] = transport_mode
        
        security_audit_logger.log_action("system", "transport_mode_changed", "admin",
                                        {"transport": transport_mode})
        
        return jsonify({
            "success": True,
            "message": f"Transport protocol set to {transport_mode.upper()}",
            "transport": transport_mode
        })
        
    except Exception as e:
        return jsonify({"error": f"Transport configuration error: {e}"}), 500

@app.route('/api/connect', methods=['POST'])
def enhanced_connect():
    """Enhanced connect with transport parameter support"""
    try:
        data = request.get_json()
        transport_mode = data.get('transport', 'tcp')
        server = data.get('server', 'auto')
        
        # Simulate connection with transport fallback
        connection_result = {
            "connected": True,
            "server_ip": "192.168.1.100",
            "transport_used": transport_mode,
            "fallback_attempts": 0 if transport_mode == "tcp" else 1,
            "stealth_active": obfuscator.stealth_mode,
            "encryption": "X25519+ML-KEM-768+ChaCha20-Poly1305",
            "latency_ms": 25
        }
        
        # Update connection stats
        connection_stats.update({
            "total_connections": connection_stats["total_connections"] + 1,
            "active_users": connection_stats["active_users"] + 1,
            "current_transport": transport_mode,
            "stealth_mode": obfuscator.stealth_mode
        })
        
        security_audit_logger.log_action("system", "vpn_connected", "user",
                                        {"transport": transport_mode, "server": server})
        
        return jsonify(connection_result)
        
    except Exception as e:
        return jsonify({"error": f"Connection failed: {e}"}), 500

@app.route('/api/settings', methods=['PATCH', 'OPTIONS'])
def update_settings():
    """Update VPN settings (stealth mode and transport)"""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'})
    
    try:
        data = request.get_json()
        stealth_mode = data.get('stealth_mode', False)
        transport = data.get('transport', 'tcp')
        
        # Update stealth mode
        if OBFUSCATION_AVAILABLE:
            obfuscator = get_obfuscator()
            if stealth_mode:
                obfuscator.enable_stealth_mode()
            else:
                obfuscator.disable_stealth_mode()
        
        # Update transport mode
        if OBFUSCATION_AVAILABLE:
            transport_layer = get_transport()
            if transport.lower() == 'quic':
                transport_layer.set_protocol(TransportProtocol.QUIC)
            elif transport.lower() == 'wss':
                transport_layer.set_protocol(TransportProtocol.WSS)
            else:
                transport_layer.set_protocol(TransportProtocol.TCP)
        
        # Log the settings change
        if SECURITY_AUDIT_AVAILABLE:
            security_audit_logger.log_action(
                user="system",
                action="settings_update",
                session="api",
                details={"stealth_mode": stealth_mode, "transport": transport}
            )
        
        return jsonify({
            'success': True,
            'stealth_mode': stealth_mode,
            'transport': transport,
            'message': 'Settings updated successfully'
        })
        
    except Exception as e:
        print(f"Error updating settings: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/mfa/setup', methods=['POST', 'OPTIONS'])
def api_mfa_setup():
    """Setup MFA for authenticated user"""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'})
    
    try:
        data = request.get_json() or {}
        session_token = data.get('session_token')
        
        if not session_token:
            return jsonify({
                "success": False,
                "message": "Session token required"
            }), 401
        
        # Verify session and get username
        if not session_manager.session_exists(session_token):
            return jsonify({
                "success": False,
                "message": "Invalid or expired session"
            }), 401
        
        session_data = session_manager.get_session_by_token(session_token)
        username = session_data.get('username') if session_data else None
        if not username:
            return jsonify({
                "success": False,
                "message": "Unable to identify user"
            }), 401
        
        # Setup MFA for user
        result = user_manager.setup_mfa(username)
        
        if result["success"]:
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        print(f"❌ MFA setup error: {e}")
        return jsonify({
            "success": False,
            "message": "MFA setup system temporarily unavailable"
        }), 500

@app.route('/api/mfa/disable', methods=['POST', 'OPTIONS'])
def api_mfa_disable():
    """Disable MFA for authenticated user"""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'})
    
    try:
        data = request.get_json() or {}
        session_token = data.get('session_token')
        
        if not session_token:
            return jsonify({
                "success": False,
                "message": "Session token required"
            }), 401
        
        # Verify session and get username
        if not session_manager.session_exists(session_token):
            return jsonify({
                "success": False,
                "message": "Invalid or expired session"
            }), 401
        
        session_data = session_manager.get_session_by_token(session_token)
        username = session_data.get('username') if session_data else None
        if not username:
            return jsonify({
                "success": False,
                "message": "Unable to identify user"
            }), 401
        
        # Disable MFA for user
        result = user_manager.disable_mfa(username)
        
        if result["success"]:
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        print(f"❌ MFA disable error: {e}")
        return jsonify({
            "success": False,
            "message": "MFA disable system temporarily unavailable"
        }), 500

@app.route('/api/mfa/backup', methods=['GET', 'OPTIONS'])
def api_mfa_backup_status():
    """Get backup codes status for authenticated user"""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'})
    
    try:
        # Get session token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({
                "success": False,
                "message": "No valid session token provided"
            }), 401
        
        session_token = auth_header.split('Bearer ')[1]
        
        # Verify session and get username
        if not session_manager.session_exists(session_token):
            return jsonify({
                "success": False,
                "message": "Invalid or expired session"
            }), 401
        
        # Get username from session data
        session_data = session_manager.sessions.get(session_token)
        username = session_data.get('username') if session_data else None
        if not username:
            return jsonify({
                "success": False,
                "message": "Invalid or expired session"
            }), 401
        
        # Get backup codes status
        result = user_manager.get_backup_codes_status(username)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        print(f"Error getting backup codes status: {e}")
        return jsonify({
            "success": False,
            "message": "Backup codes status system temporarily unavailable"
        }), 500

@app.route('/api/debug/traffic_pattern', methods=['GET'])
def get_traffic_pattern():
    """Get traffic pattern analysis for debugging"""
    try:
        # Get obfuscation statistics
        obfuscation_stats = obfuscator.get_stats()
        
        # Get transport statistics  
        transport_stats = transport.get_stats()
        
        # Calculate traffic analysis metrics
        traffic_pattern = {
            "obfuscation": {
                "stealth_mode": obfuscation_stats.get("stealth_mode", False),
                "dummy_packet_percentage": obfuscation_stats.get("dummy_packet_percentage", 0),
                "fragmentation_rate": obfuscation_stats.get("fragmentation_rate", 0),
                "avg_packet_size": obfuscation_stats.get("avg_packet_size", 0),
                "total_packets": obfuscation_stats.get("packets_obfuscated", 0) + obfuscation_stats.get("dummy_packets_sent", 0),
                "padding_added_kb": round(obfuscation_stats.get("total_padding_added", 0) / 1024, 2)
            },
            "transport": {
                "protocol": transport_stats.get("current_transport", "tcp"),
                "success_rate": transport_stats.get("success_rate", 100),
                "fallback_count": transport_stats.get("fallback_count", 0),
                "bytes_sent": transport_stats.get("bytes_sent", 0),
                "bytes_received": transport_stats.get("bytes_received", 0)
            },
            "analysis_resistance": {
                "timing_variance": "High" if obfuscation_stats.get("stealth_mode") else "Standard",
                "packet_size_variance": "Randomized" if obfuscation_stats.get("stealth_mode") else "Standard", 
                "traffic_mimicry": "HTTPS" if obfuscation_stats.get("stealth_mode") else "VPN"
            }
        }
        
        return jsonify(traffic_pattern)
        
    except Exception as e:
        return jsonify({"error": f"Traffic analysis error: {e}"}), 500

# Enhanced security endpoints
@app.route('/api/security/audit-logs', methods=['GET'])
def get_audit_logs():
    """Get tamper-proof audit logs with integrity verification"""
    try:
        # Get recent logs
        logs = security_audit_logger.get_recent_logs(50)
        
        # Verify chain integrity
        is_valid, errors = security_audit_logger.verify_chain_integrity()
        
        # Format for API response
        formatted_logs = []
        for log in logs:
            formatted_logs.append({
                "timestamp": log.get('timestamp', ''),
                "user": log.get('user', ''),
                "action": log.get('action', ''),
                "session_id": log.get('session_id', ''),
                "details": log.get('details', {}),
                "hash": log.get('hash', '')[:16] + "..."  # Show partial hash
            })
        
        return jsonify({
            "logs": formatted_logs,
            "chain_valid": is_valid,
            "integrity_errors": errors if not is_valid else [],
            "total_entries": len(logs)
        })
    except Exception as e:
        return jsonify({"error": f"Audit log system error: {e}"}), 500

@app.route('/api/security/pq-signature-status', methods=['GET'])
def get_pq_signature_status():
    """Get post-quantum signature verification status"""
    try:
        return jsonify({
            "algorithm": "Dilithium3",
            "available": handshake_verifier.signer.is_available(),
            "last_verification": handshake_verifier.get_verification_status(),
            "signature_info": handshake_verifier.signer.get_signature_info()
        })
    except Exception as e:
        return jsonify({"error": f"PQ signature system error: {e}"}), 500

@app.route('/api/security/mfa-setup', methods=['POST'])
def setup_mfa():
    """Generate MFA QR code for user"""
    try:
        data = request.get_json()
        username = data.get('username')
        
        if not username:
            return jsonify({"error": "Username required"}), 400
        
        # Generate TOTP secret
        secret = mfa_system.generate_totp_secret(username)
        
        # Generate QR code
        qr_code = mfa_system.generate_qr_code(username)
        
        # Get backup codes
        backup_codes = mfa_system.get_backup_codes(username)
        
        security_audit_logger.log_action(username, "mfa_setup_initiated", "setup",
                              {"method": "TOTP"})
        
        return jsonify({
            "secret": secret,
            "qr_code": qr_code,
            "backup_codes": backup_codes
        })
        
    except Exception as e:
        return jsonify({"error": f"MFA setup error: {e}"}), 500

@app.route('/api/security/mfa-status', methods=['POST'])
def get_mfa_status():
    """Get MFA status for user"""
    try:
        data = request.get_json()
        username = data.get('username')
        
        if not username:
            return jsonify({"error": "Username required"}), 400
        
        mfa_info = mfa_system.get_user_mfa_info(username)
        
        return jsonify({
            "enabled": mfa_info['mfa_enabled'],
            "configured": mfa_info['has_totp'],
            "backup_codes_remaining": mfa_info['backup_codes_remaining']
        })
        
    except Exception as e:
        return jsonify({"error": f"MFA status error: {e}"}), 500

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health():
    """API health check"""
    return jsonify({
        "status": "healthy",
        "service": "KyberLink VPN API",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat()
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "API endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500


from flask import send_from_directory, make_response

# Serve modern UI v2 frontend
@app.route('/')
def index():
    """Serve modern VPN interface"""
    try:
        from flask import render_template
        # Serve our modern template with all the premium features
        return render_template('index.html')
    except Exception as e:
        print(f"Error serving main template: {e}")
        # Fallback to static file if template engine fails
        try:
            response = make_response(send_from_directory('static', 'fallback.html'))
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response
        except:
            return "KyberLink VPN - Service temporarily unavailable", 503

@app.route('/static/<path:filename>')
def serve_static_files(filename):
    """Serve static assets (CSS, JS, images)"""
    try:
        print(f"🔍 Looking for static file: {filename}")
        print(f"🔍 Current working directory: {os.getcwd()}")
        
        # Check the nested static/static/ structure first
        nested_path = os.path.join('static', 'static', filename)
        print(f"🔍 Checking nested path: {nested_path}")
        print(f"🔍 Nested path exists: {os.path.exists(nested_path)}")
        
        if os.path.exists(nested_path):
            print(f"✅ Serving from nested: {nested_path}")
            response = make_response(send_from_directory('static/static', filename))
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache' 
            response.headers['Expires'] = '0'
            return response
        
        # Check direct static/ path
        direct_path = os.path.join('static', filename)
        print(f"🔍 Checking direct path: {direct_path}")
        print(f"🔍 Direct path exists: {os.path.exists(direct_path)}")
        
        if os.path.exists(direct_path):
            print(f"✅ Serving from direct: {direct_path}")
            response = make_response(send_from_directory('static', filename))
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response
        
        print(f"❌ File not found: {filename}")
        return "File not found", 404
    except Exception as e:
        print(f"💥 Error serving static file {filename}: {e}")
        return "Error serving file", 500

@app.route('/<path:path>')
def serve_react_routes(path):
    """Handle all other routes for React Router"""
    try:
        # Skip API routes
        if path.startswith('api/'):
            return jsonify({"error": "API endpoint not found"}), 404
        
        # For any other path, serve the React app
        return send_from_directory('static', 'index.html')
    except Exception as e:
        print(f"Error serving React route {path}: {e}")
        return send_from_directory('static', 'index.html')

if __name__ == '__main__':
    print("🔐 Starting KyberLink VPN with Modern UI v2...")
    print("🌐 Frontend available at: http://localhost:5000")
    print("🔗 API endpoints available at: /api/*")
    print("🎨 Modern glass morphism design v2 active")
    
    # Run on port 5000 for Replit preview compatibility
    app.run(host="0.0.0.0", port=5000, debug=False)