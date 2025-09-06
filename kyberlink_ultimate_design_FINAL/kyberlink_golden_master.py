#!/usr/bin/env python3
"""
KyberShield VPN - Golden Master Flask Application
Professional quantum-resistant VPN with premium UI
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file, send_from_directory
from flask_cors import CORS
import os
import json
import secrets
from datetime import datetime
from server_config import server_manager
from download_config import download_manager

app = Flask(__name__)

# Determine environment
ENV = os.environ.get('FLASK_ENV', 'development')
is_production = ENV == 'production' or os.environ.get('REPL_DEPLOYMENT_ID')

# Load configuration based on environment
if is_production:
    try:
        from production_config import ProductionConfig
        ProductionConfig.init_app(app)
        allowed_origins = ProductionConfig.CORS_ORIGINS
    except ImportError:
        # Fallback for production without config file
        app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(32).hex())
        app.config['SESSION_COOKIE_SECURE'] = True
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
        allowed_origins = ["https://kybershield.io", "https://www.kybershield.io"]
else:
    # Development configuration
    app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'kybershield-demo-secret-key-2025')
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    allowed_origins = ["*"]

# Configure CORS with environment-specific origins
CORS(app, supports_credentials=True, origins=allowed_origins)

# Demo user data
DEMO_USERS = {
    "admin@kybershield.com": {
        "password": "shield2025",
        "name": "KyberShield Admin",
        "plan": "Premium",
        "mfa_enabled": False,
        "mfa_required": False,
        "created": "2025-01-01"
    },
    "user@kybershield.com": {
        "password": "quantum123",
        "name": "Premium User",
        "plan": "Premium", 
        "mfa_enabled": True,
        "mfa_required": False,
        "created": "2025-01-01"
    }
}

# Demo server data
DEMO_SERVERS = [
    {"id": "ny", "name": "New York", "country": "US", "flag": "🇺🇸", "ping": 23, "load": "low"},
    {"id": "london", "name": "London", "country": "UK", "flag": "🇬🇧", "ping": 45, "load": "medium"},
    {"id": "tokyo", "name": "Tokyo", "country": "JP", "flag": "🇯🇵", "ping": 67, "load": "low"},
    {"id": "singapore", "name": "Singapore", "country": "SG", "flag": "🇸🇬", "ping": 34, "load": "low"},
    {"id": "frankfurt", "name": "Frankfurt", "country": "DE", "flag": "🇩🇪", "ping": 56, "load": "medium"},
    {"id": "sydney", "name": "Sydney", "country": "AU", "flag": "🇦🇺", "ping": 89, "load": "high"},
    {"id": "toronto", "name": "Toronto", "country": "CA", "flag": "🇨🇦", "ping": 78, "load": "low"},
    {"id": "stockholm", "name": "Stockholm", "country": "SE", "flag": "🇸🇪", "ping": 112, "load": "high"}
]

@app.route('/')
def spa():
    """Single Page Application - All routes go through main SPA"""
    return render_template('spa.html')

@app.route('/download')
def spa_download():
    """Download page route - handled by SPA"""
    return render_template('spa.html')

@app.route('/compare')
def spa_compare():
    """Compare page route - handled by SPA"""
    return render_template('spa.html')

@app.route('/login')
def spa_login():
    """Login page route - handled by SPA"""
    return render_template('spa.html')

@app.route('/register')
def spa_register():
    """Register page route - handled by SPA"""
    return render_template('spa.html')

@app.route('/dashboard')
def spa_dashboard():
    """Dashboard page route - handled by SPA"""
    return render_template('spa.html')


# DASHBOARD ROUTES REMOVED - React frontend will handle dashboard
# @app.route('/dashboard')
# def dashboard():
#     """Premium dashboard with interactive world map"""
#     if 'user' not in session or not session.get('authenticated'):
#         return redirect(url_for('spa_login'))
#     return render_template('dashboard-redesigned.html')

# @app.route('/demo')
# def demo():
#     """Demo redirect to dashboard"""
#     session['user'] = 'demo@kyberlink.com'
#     return redirect(url_for('dashboard'))

# SPA Page Content API
@app.route('/api/page/<page_name>')
def get_page_content(page_name):
    """API endpoint to fetch page content for SPA routing"""
    try:
        # Validate page name to prevent path traversal
        valid_pages = ['landing', 'download', 'compare', 'login', 'register', 'dashboard']
        if page_name not in valid_pages:
            return jsonify({"error": "Page not found"}), 404
            
        if page_name == 'landing':
            return render_template('landing_content.html')
        elif page_name == 'download':
            return render_template('download_content.html')
        elif page_name == 'compare':
            return render_template('compare.html')
        elif page_name == 'login':
            return render_template('login_content.html')
        elif page_name == 'register':
            return render_template('register_content.html')
        elif page_name == 'dashboard':
            # Check if user is authenticated
            if 'user' not in session or not session.get('authenticated'):
                return jsonify({"error": "Authentication required", "redirect": "/login"}), 401
            return render_template('dashboard_content.html')
        else:
            return jsonify({"error": "Page not found"}), 404
            
    except FileNotFoundError as e:
        print(f"Template not found: {e}")
        return jsonify({"error": "Template not found"}), 500
    except Exception as e:
        print(f"API error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# API Endpoints
@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    """Logout API endpoint"""
    session.clear()
    return jsonify({"success": True, "message": "Logged out successfully"})

@app.route('/api/auth/status', methods=['GET'])
def api_auth_status():
    """Check authentication status"""
    try:
        authenticated = 'user' in session and session.get('authenticated', False)
        user_email = session.get('user') if authenticated else None
        
        return jsonify({
            "authenticated": authenticated,
            "user": user_email
        })
    except Exception as e:
        print(f"Auth status error: {e}")
        return jsonify({"authenticated": False, "user": None})

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """Login API endpoint with better error handling"""
    try:
        # Accept both JSON and form data
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
            
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        print(f"Login attempt for email: {email}")
        
        if not email or not password:
            return jsonify({"success": False, "error": "Email and password required"}), 400
        
        # Check credentials case-insensitively
        user_found = None
        for user_email, user_data in DEMO_USERS.items():
            if user_email.lower() == email:
                if user_data['password'] == password:
                    user_found = (user_email, user_data)
                    break
        
        if user_found:
            actual_email, user_data = user_found
            # Set session
            session['user'] = actual_email
            session['authenticated'] = True
            session.permanent = True
            
            print(f"Login successful for {actual_email}")
            
            return jsonify({
                "success": True,
                "user": {
                    "email": actual_email,
                    "name": user_data['name'],
                    "plan": user_data['plan'],
                    "mfa_required": user_data.get('mfa_required', False)
                },
                "message": "Login successful"
            })
        
        print(f"Invalid credentials for {email}")
        return jsonify({"success": False, "error": "Invalid email or password"}), 401
        
    except Exception as e:
        print(f"Login error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": "Server error"}), 500

@app.route('/api/auth/mfa/verify', methods=['POST'])
def api_mfa_verify():
    """MFA verification endpoint"""
    if not request.is_json:
        return jsonify({"success": False, "error": "JSON data required"}), 400
    
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400
        
    code = data.get('code')
    
    # Demo: accept any 6-digit code
    if len(code) == 6 and code.isdigit():
        return jsonify({"success": True, "message": "MFA verified"})
    
    return jsonify({"success": False, "error": "Invalid MFA code"}), 400

@app.route('/api/servers')
def api_servers():
    """Get server list from server manager"""
    servers = server_manager.get_all_servers()
    return jsonify({"servers": servers, "stats": server_manager.get_server_stats()})

@app.route('/api/connect', methods=['POST'])
def api_connect():
    """Connect to VPN server"""
    data = request.get_json()
    server_id = data.get('server_id')
    
    server = server_manager.get_server_by_id(server_id)
    if server:
        return jsonify({
            "success": True,
            "message": f"Connected to {server['name']}",
            "server": server,
            "ip": "10.0.0." + str(hash(server_id) % 255),
            "protocol": "KyberShield Quantum"
        })
    
    return jsonify({"success": False, "error": "Server not found"}), 404

@app.route('/api/disconnect', methods=['POST'])
def api_disconnect():
    """Disconnect from VPN"""
    return jsonify({
        "success": True,
        "message": "Disconnected from VPN"
    })

@app.route('/api/stats')
def api_stats():
    """Get connection statistics"""
    return jsonify({
        "download_speed": 45.6,
        "upload_speed": 12.3,
        "latency": 28,
        "data_used": 1.2,
        "session_time": 3600,
        "threats_blocked": 127
    })

@app.route('/api/user/profile')
def api_user_profile():
    """Get user profile"""
    if 'user' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    user_email = session['user']
    user_data = DEMO_USERS.get(user_email, {})
    
    return jsonify({
        "email": user_email,
        "name": user_data.get('name', 'User'),
        "plan": user_data.get('plan', 'Free'),
        "mfa_enabled": user_data.get('mfa_enabled', False),
        "created": user_data.get('created', '2025-01-01')
    })

@app.route('/api/settings', methods=['GET', 'POST'])
def api_settings():
    """Get or update user settings"""
    if request.method == 'GET':
        # Return default settings
        return jsonify({
            "kill_switch": True,
            "dns_protection": True,
            "auto_connect": False,
            "theme": "dark",
            "notifications": True,
            "sounds": True
        })
    
    # Update settings
    data = request.get_json()
    return jsonify({"success": True, "message": "Settings updated"})

# Download routes for installer files
@app.route('/downloads/KyberLinkVPN-Setup.exe')
def download_windows():
    """Serve Windows installer"""
    try:
        return app.send_static_file('downloads/windows/latest.exe')
    except:
        return "Windows installer not available", 404

@app.route('/downloads/KyberLinkVPN.dmg')
def download_mac():
    """Serve macOS installer"""
    try:
        return app.send_static_file('downloads/mac/latest.dmg')
    except:
        return "macOS installer not available", 404

@app.route('/downloads/KyberLinkVPN.AppImage')
def download_linux():
    """Serve Linux installer"""
    try:
        return app.send_static_file('downloads/linux/latest.AppImage')
    except:
        return "Linux installer not available", 404

# Health check endpoint for connection monitoring
@app.route('/api/health')
def health_check():
    """Health check endpoint for connection monitoring"""
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()}), 200

@app.route('/api/downloads')
def api_downloads():
    """Get download information for all platforms"""
    user_agent = request.headers.get('User-Agent', '')
    detected_platform = download_manager.detect_platform(user_agent)
    
    return jsonify({
        "detected_platform": detected_platform,
        "downloads": download_manager.get_all_downloads(),
        "latest_version": download_manager.get_latest_version(),
        "release_notes": download_manager.get_release_notes()
    })

@app.route('/api/downloads/<platform>')
def api_download_platform(platform):
    """Get download information for specific platform"""
    download_info = download_manager.get_download_info(platform)
    if download_info:
        return jsonify(download_info)
    return jsonify({"error": "Platform not found"}), 404

@app.route('/api/servers/best')
def api_best_server():
    """Get the best server based on load and latency"""
    best_server = server_manager.get_best_server()
    return jsonify({"server": best_server})

@app.route('/api/servers/<server_id>')
def api_server_details(server_id):
    """Get details for a specific server"""
    server = server_manager.get_server_by_id(server_id)
    if server:
        return jsonify(server)
    return jsonify({"error": "Server not found"}), 404

# Download route for deployment files
@app.route('/download/<path:filename>')
def download_file(filename):
    """Serve deployment files for download"""
    return send_from_directory(os.path.join(app.root_path, 'static'), filename, as_attachment=True)

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('spa.html'), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({"error": "Internal server error"}), 500

# Security headers and connection stability
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # Only add HSTS in production with HTTPS
    if is_production:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        # Add additional production security headers
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self';"
    
    # Connection stability headers - Fixed conflicting headers
    if '/static/' not in request.path and '/download/' not in request.path:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    else:
        # Allow caching for static files and downloads
        response.headers['Cache-Control'] = 'public, max-age=300'
    
    # Remove conflicting connection headers
    if 'Connection' in response.headers:
        del response.headers['Connection']
    
    return response

if __name__ == '__main__':
    if is_production:
        print("🛡️  KyberShield VPN - Production Mode")
        print("🌐  Domain: https://kybershield.io")
        print("🔒  Production security enabled")
        print("🚀  Quantum-resistant encryption active!")
    else:
        print("🛡️  KyberShield VPN - Development Mode")
        print("🌐  Landing Page: http://localhost:5000")
        print("🔐  Demo Login: admin@kybershield.com / shield2025")
        print("📊  Dashboard: http://localhost:5000/dashboard")
        print("🚀  Quantum-resistant security activated!")
    
    # Run with production-ready settings
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=not is_production,
        threaded=True
    )