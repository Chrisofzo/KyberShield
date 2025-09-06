#!/usr/bin/env python3
"""
KyberLink VPN Audit Logging and Intrusion Detection
==================================================

Centralized security event logging with threat detection capabilities.
Tracks authentication attempts, security events, and potential intrusions.

Security Features:
- Centralized audit logging with timestamps
- Color-coded event severity levels
- Real-time intrusion detection
- Failed login attempt tracking
- Malformed packet detection
- DoS attack pattern recognition
"""

import os
import json
import time
from datetime import datetime, timezone
from typing import List, Dict, Optional
from collections import defaultdict, deque
import threading


class AuditLogger:
    """Centralized audit logging system for KyberLink VPN"""
    
    def __init__(self, log_file_path: str = "logs/audit.log"):
        self.log_file_path = log_file_path
        self.lock = threading.Lock()
        
        # Intrusion detection tracking
        self.failed_logins = defaultdict(deque)  # IP -> timestamps
        self.session_violations = defaultdict(int)  # IP -> count
        self.packet_anomalies = defaultdict(deque)  # IP -> timestamps
        
        # Detection thresholds
        self.LOGIN_ATTEMPT_THRESHOLD = 3
        self.LOGIN_ATTEMPT_WINDOW = 60  # seconds
        self.PACKET_ANOMALY_THRESHOLD = 5
        self.PACKET_ANOMALY_WINDOW = 30  # seconds
        
        # Ensure log directory exists
        os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
        
        # Initialize log file if it doesn't exist
        if not os.path.exists(log_file_path):
            self.log_event("INFO", "AuditLogger", "Audit logging system initialized")
        
        print("🔍 KyberLink Audit Logger initialized")
    
    def log_event(self, level: str, source: str, message: str, client_ip: str = None, additional_data: Dict = None):
        """
        Log security event with timestamp and metadata
        
        Args:
            level: Event severity (INFO, SUCCESS, WARNING, ERROR, INTRUSION)
            source: Event source (Server, Client, Dashboard, etc.)
            message: Human-readable event description
            client_ip: Client IP address if applicable
            additional_data: Extra metadata for the event
        """
        with self.lock:
            timestamp = datetime.now(timezone.utc).isoformat()
            
            log_entry = {
                "timestamp": timestamp,
                "level": level.upper(),
                "source": source,
                "message": message,
                "client_ip": client_ip,
                "additional_data": additional_data or {}
            }
            
            # Write to audit log file
            try:
                with open(self.log_file_path, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(log_entry) + '\n')
            except Exception as e:
                print(f"❌ Audit logging failed: {e}")
            
            # Also print to console for immediate visibility
            ip_part = f" [{client_ip}]" if client_ip else ""
            console_message = f"[{timestamp[:19]}] [{level.upper()}] [{source}]{ip_part} {message}"
            
            # Color-coded console output
            if level.upper() == "SUCCESS":
                print(f"✅ {console_message}")
            elif level.upper() == "WARNING":
                print(f"⚠️  {console_message}")
            elif level.upper() == "ERROR":
                print(f"❌ {console_message}")
            elif level.upper() == "INTRUSION":
                print(f"🚨 {console_message}")
            else:
                print(f"ℹ️  {console_message}")
    
    def get_recent_logs(self, limit: int = 50) -> List[Dict]:
        """
        Retrieve recent audit log entries
        
        Args:
            limit: Maximum number of entries to return
            
        Returns:
            List of log entries as dictionaries
        """
        logs = []
        
        if not os.path.exists(self.log_file_path):
            return logs
        
        try:
            with open(self.log_file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
                # Get last 'limit' lines
                recent_lines = lines[-limit:] if len(lines) > limit else lines
                
                for line in recent_lines:
                    line = line.strip()
                    if line:
                        try:
                            log_entry = json.loads(line)
                            logs.append(log_entry)
                        except json.JSONDecodeError:
                            continue
                            
        except Exception as e:
            self.log_event("ERROR", "AuditLogger", f"Failed to read audit logs: {e}")
        
        # Sort by timestamp (most recent first)
        logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return logs
    
    def track_login_attempt(self, client_ip: str, username: str, success: bool):
        """
        Track login attempts and detect brute force attacks
        
        Args:
            client_ip: Client IP address
            username: Attempted username
            success: Whether login was successful
        """
        current_time = time.time()
        
        if success:
            self.log_event("SUCCESS", "Authentication", 
                          f"User '{username}' logged in successfully", 
                          client_ip)
            # Clear failed attempts on successful login
            if client_ip in self.failed_logins:
                self.failed_logins[client_ip].clear()
        else:
            # Track failed login
            self.failed_logins[client_ip].append(current_time)
            
            # Remove old attempts outside the time window
            while (self.failed_logins[client_ip] and 
                   current_time - self.failed_logins[client_ip][0] > self.LOGIN_ATTEMPT_WINDOW):
                self.failed_logins[client_ip].popleft()
            
            failed_count = len(self.failed_logins[client_ip])
            
            if failed_count >= self.LOGIN_ATTEMPT_THRESHOLD:
                self.log_event("WARNING", "Authentication", 
                              f"Multiple failed login attempts for user '{username}' - {failed_count} attempts in {self.LOGIN_ATTEMPT_WINDOW}s",
                              client_ip, {"failed_attempts": failed_count, "username": username})
            else:
                self.log_event("WARNING", "Authentication", 
                              f"Failed login attempt for user '{username}' ({failed_count}/{self.LOGIN_ATTEMPT_THRESHOLD})",
                              client_ip, {"username": username})
    
    def track_session_violation(self, client_ip: str, violation_type: str, details: str):
        """
        Track session-related security violations
        
        Args:
            client_ip: Client IP address
            violation_type: Type of violation (invalid_token, replay, etc.)
            details: Additional violation details
        """
        self.session_violations[client_ip] += 1
        violation_count = self.session_violations[client_ip]
        
        level = "WARNING" if violation_count < 3 else "ERROR"
        
        self.log_event(level, "Session", 
                      f"Session violation: {violation_type} - {details}",
                      client_ip, 
                      {"violation_type": violation_type, "violation_count": violation_count})
    
    def track_packet_anomaly(self, client_ip: str, anomaly_type: str, details: str):
        """
        Track packet-level security anomalies
        
        Args:
            client_ip: Client IP address
            anomaly_type: Type of anomaly (malformed, tampering, dos_pattern)
            details: Additional anomaly details
        """
        current_time = time.time()
        self.packet_anomalies[client_ip].append(current_time)
        
        # Remove old anomalies outside the time window
        while (self.packet_anomalies[client_ip] and 
               current_time - self.packet_anomalies[client_ip][0] > self.PACKET_ANOMALY_WINDOW):
            self.packet_anomalies[client_ip].popleft()
        
        anomaly_count = len(self.packet_anomalies[client_ip])
        
        # Determine severity based on anomaly type and frequency
        if anomaly_type in ["malformed", "tampering"]:
            level = "INTRUSION"
        elif anomaly_count >= self.PACKET_ANOMALY_THRESHOLD:
            level = "INTRUSION"
        else:
            level = "WARNING"
        
        self.log_event(level, "PacketAnalysis", 
                      f"Packet anomaly: {anomaly_type} - {details}",
                      client_ip, 
                      {"anomaly_type": anomaly_type, "anomaly_count": anomaly_count})
    
    def detect_dos_pattern(self, client_ip: str, dummy_ratio: float, packet_count: int):
        """
        Detect potential DoS attacks based on traffic patterns
        
        Args:
            client_ip: Client IP address
            dummy_ratio: Ratio of dummy to real packets
            packet_count: Total packet count
        """
        # Suspicious if dummy ratio is extremely high (potential DoS)
        if dummy_ratio > 0.8 and packet_count > 100:
            self.log_event("INTRUSION", "TrafficAnalysis", 
                          f"Suspicious traffic pattern detected - unusually high dummy packet ratio: {dummy_ratio:.2%}",
                          client_ip, 
                          {"dummy_ratio": dummy_ratio, "packet_count": packet_count})
        elif dummy_ratio > 0.6 and packet_count > 50:
            self.log_event("WARNING", "TrafficAnalysis", 
                          f"High dummy packet ratio detected: {dummy_ratio:.2%}",
                          client_ip, 
                          {"dummy_ratio": dummy_ratio, "packet_count": packet_count})
    
    def log_system_event(self, component: str, event: str, details: str = None):
        """
        Log system-level events (startup, configuration changes, etc.)
        
        Args:
            component: System component (Kill Switch, Stealth Mode, etc.)
            event: Event description
            details: Additional event details
        """
        self.log_event("INFO", f"System.{component}", event, 
                      additional_data={"details": details} if details else None)
    
    def get_statistics(self) -> Dict:
        """Get audit logging statistics"""
        total_logs = 0
        level_counts = defaultdict(int)
        
        try:
            with open(self.log_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            log_entry = json.loads(line)
                            total_logs += 1
                            level_counts[log_entry.get('level', 'UNKNOWN')] += 1
                        except json.JSONDecodeError:
                            continue
        except FileNotFoundError:
            pass
        
        return {
            "total_events": total_logs,
            "events_by_level": dict(level_counts),
            "active_ips_tracked": len(self.failed_logins),
            "total_violations": sum(self.session_violations.values())
        }


# Global audit logger instance
_global_audit_logger = None


def get_audit_logger() -> AuditLogger:
    """Get global audit logger instance (singleton)"""
    global _global_audit_logger
    if _global_audit_logger is None:
        _global_audit_logger = AuditLogger()
    return _global_audit_logger


def log_event(level: str, source: str, message: str, client_ip: str = None, additional_data: Dict = None):
    """Global function to log audit events"""
    get_audit_logger().log_event(level, source, message, client_ip, additional_data)


def get_recent_logs(limit: int = 50) -> List[Dict]:
    """Global function to get recent audit logs"""
    return get_audit_logger().get_recent_logs(limit)


if __name__ == "__main__":
    # Test audit logging functionality
    print("🧪 Testing KyberLink Audit Logging System...")
    
    logger = AuditLogger()
    
    # Test different event types
    logger.log_event("INFO", "Test", "Audit logging system test started")
    logger.log_event("SUCCESS", "Test", "Test event logged successfully")
    logger.log_event("WARNING", "Test", "Test warning event", "192.168.1.100")
    logger.log_event("ERROR", "Test", "Test error event", "192.168.1.100", {"error_code": 404})
    logger.log_event("INTRUSION", "Test", "Test intrusion event", "192.168.1.100", {"threat_level": "high"})
    
    # Test login tracking
    logger.track_login_attempt("192.168.1.100", "testuser", False)
    logger.track_login_attempt("192.168.1.100", "testuser", False)
    logger.track_login_attempt("192.168.1.100", "testuser", False)  # Should trigger warning
    logger.track_login_attempt("192.168.1.100", "testuser", True)   # Should clear failed attempts
    
    # Test packet anomaly detection
    logger.track_packet_anomaly("192.168.1.101", "malformed", "Invalid packet header detected")
    logger.track_packet_anomaly("192.168.1.101", "tampering", "Packet authentication failed")
    
    # Test DoS detection
    logger.detect_dos_pattern("192.168.1.102", 0.85, 150)  # Should trigger intrusion alert
    
    # Test recent logs retrieval
    recent_logs = logger.get_recent_logs(5)
    print(f"\n📊 Retrieved {len(recent_logs)} recent log entries:")
    for log in recent_logs:
        print(f"  [{log['level']}] {log['message']}")
    
    # Show statistics
    stats = logger.get_statistics()
    print(f"\n📈 Audit Statistics: {stats}")
    
    print("\n🎉 Audit logging system testing completed!")