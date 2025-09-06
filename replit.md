# KyberShield - Quantum-Resistant VPN Protocol

## Overview

**KyberShield** — quantum-resistant VPN powered by hybrid post-quantum encryption.

This project implements a complete quantum-resistant VPN protocol with hybrid key exchange and authenticated encryption. The system combines classical and post-quantum cryptographic methods to create a secure communication tunnel that's resistant to both current and future quantum computer attacks. The protocol includes a working client-server implementation with socket-based networking for encrypted packet transmission.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Core Components

**1. Hybrid Key Exchange Protocol**
- X25519 elliptic-curve Diffie-Hellman for classical security
- ML-KEM-768 (Kyber768) post-quantum KEM for quantum resistance  
- HKDF with SHA3-256 for secure session key derivation
- Both parties independently derive identical 256-bit session keys

**2. Authenticated Encryption**
- ChaCha20-Poly1305 AEAD cipher for packet protection
- Fresh random 12-byte nonce for each packet
- Authenticated encryption prevents tampering and forgery
- Each encrypted packet includes nonce + ciphertext + authentication tag

**3. Network Communication**
- Client-server architecture using Python sockets
- Server listens on localhost:5555 for client connections
- Length-prefixed message protocol for reliable data transmission
- Bidirectional encrypted communication with acknowledgments

### File Structure
```
src/
├── crypto_utils.py       # Shared cryptographic utilities
├── vpn_server.py         # VPN server implementation
├── vpn_client.py         # VPN client implementation
├── kill_switch.py        # Kill switch for leak prevention
├── obfuscator.py         # Advanced traffic obfuscation with XOR+ChaCha20
├── transport_layer.py    # Pluggable transport (QUIC/TCP/WSS) with fallback
├── traffic_shaper.py     # Adaptive metadata protection
├── audit_logger.py       # Centralized security event logging
├── security_audit.py     # Tamper-proof blockchain-style audit logging
├── pq_signatures.py      # Post-quantum Dilithium3 signature verification
├── mfa_system.py         # Enhanced TOTP MFA with QR codes and backup codes
├── user_manager.py       # User authentication with MFA
└── session_manager.py    # Secure session management
app.py                  # Flask web dashboard with HTTPS
templates/              # Web interface templates
users.db                # SQLite user database
kyberlink.crt/.key      # TLS certificates
```

## Enhanced Security Architecture (December 2025)

### Enterprise Security Features
- **Tamper-Proof Audit Logging**: Blockchain-style hash chaining with SHA3-256 integrity verification
- **Post-Quantum Signature Verification**: Dilithium3 signatures for handshake authentication
- **Enhanced MFA System**: TOTP (RFC 6238) with QR codes and backup codes
- **Real-time Security Monitoring**: Advanced threat detection and intrusion prevention
- **Quantum-Resistant Protocol Stack**: Full enterprise-grade security implementation

### Technology Stack
- **Frontend**: React (web) + Flutter (cross-platform mobile/desktop)
- **Backend**: Flask API with quantum encryption and tamper-proof logging
- **Cryptography**: X25519 + ML-KEM-768 hybrid + ChaCha20-Poly1305 + Dilithium3
- **Authentication**: Argon2id + JWT + TOTP MFA + backup codes
- **Logging**: SHA3-256 hash chain + blockchain verification

### Advanced UI Features
- **Modern Glass Morphism Design**: Professional branding with animated tunnel visualization
- **Real-time Connection Monitoring**: Live stats, latency tracking, security status
- **Enterprise Security Controls**: Multi-hop routing, traffic obfuscation, quantum firewall, stealth mode
- **Advanced Transport Selection**: QUIC/TCP/WebSocket-443 with automatic fallback
- **Traffic Analysis Dashboard**: Obfuscation stats, dummy packet monitoring, transport metrics
- **Responsive Cross-Platform**: Optimized for mobile and desktop viewing
- **Live Security Dashboard**: System status, audit logs, signature verification

### Security Implementations
- **Quantum resistance**: Hybrid classical + post-quantum cryptography with Dilithium3 signatures
- **Perfect forward secrecy**: Fresh session keys with post-quantum handshake verification
- **Tamper-proof audit trail**: Blockchain-style logging with integrity verification endpoints
- **Enterprise MFA**: TOTP authentication with QR setup and backup recovery codes
- **Advanced threat detection**: Real-time intrusion detection with security event correlation
- **Kill Switch**: Connection drop protection with traffic leak prevention
- **Advanced Traffic Obfuscation**: XOR + ChaCha20 stream masking with packet fragmentation
- **Stealth Mode**: HTTPS mimicry with variable padding and dummy traffic generation
- **Pluggable Transport Layer**: QUIC → TCP → WebSocket-443 fallback with audit logging
- **Traffic Analysis Resistance**: Background dummy packets, timing variance, size randomization
- **Deep Packet Inspection Evasion**: HTTP/2 frame headers, fake TLS records, WebSocket tunneling
- **Zero-trust Architecture**: Every connection verified with quantum-resistant signatures