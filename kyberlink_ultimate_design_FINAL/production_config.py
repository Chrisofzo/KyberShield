"""
Production configuration for KyberShield VPN
Domain: kybershield.io
"""

import os
from datetime import timedelta

class ProductionConfig:
    # Domain configuration
    DOMAIN = "kybershield.io"
    SERVER_NAME = None  # Let Replit handle this
    PREFERRED_URL_SCHEME = "https"
    
    # Security settings
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', os.urandom(32).hex())
    
    # Session configuration
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    # Don't set domain during deployment phase - let Flask handle it
    # SESSION_COOKIE_DOMAIN will be set dynamically based on request host
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    # CORS settings for production
    CORS_ORIGINS = [
        "https://kybershield.io",
        "https://www.kybershield.io",
        "https://app.kybershield.io"
        # Development origins removed for production security
    ]
    
    # Database (if needed in future)
    DATABASE_URL = os.environ.get('DATABASE_URL')
    
    # API configuration
    API_BASE_URL = "https://kybershield.io/api"
    
    # VPN Server endpoints (for production)
    VPN_SERVERS = {
        "us-east": {
            "endpoint": "vpn-us-east.kybershield.io",
            "port": 443
        },
        "us-west": {
            "endpoint": "vpn-us-west.kybershield.io", 
            "port": 443
        },
        "eu-central": {
            "endpoint": "vpn-eu.kybershield.io",
            "port": 443
        },
        "asia-pacific": {
            "endpoint": "vpn-asia.kybershield.io",
            "port": 443
        }
    }
    
    # Feature flags
    ENABLE_MFA = True
    ENABLE_QUANTUM_ENCRYPTION = True
    ENABLE_KILL_SWITCH = True
    ENABLE_ANALYTICS = False  # Privacy first
    
    # Rate limiting
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL', 'memory://')
    
    # Logging
    LOG_LEVEL = 'INFO'
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Email (for future notifications)
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = 'noreply@kybershield.io'
    
    # CDN and static files
    CDN_URL = "https://cdn.kybershield.io"  # Future CDN
    STATIC_URL = "/static"
    
    # Download URLs
    DOWNLOAD_BASE_URL = "https://downloads.kybershield.io"
    
    @staticmethod
    def init_app(app):
        """Initialize the application with production settings"""
        # Set production environment
        app.config['ENV'] = 'production'
        app.config['DEBUG'] = False
        app.config['TESTING'] = False
        
        # Apply all configuration
        app.config.from_object(ProductionConfig)
        
        # Additional production setup
        if not app.config.get('SECRET_KEY'):
            raise ValueError("SECRET_KEY must be set in production!")
        
        return app