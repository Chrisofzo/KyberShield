"""
Tamper-Proof Audit Logging with Blockchain-Style Chaining
"""
import hashlib
import json
import os
from datetime import datetime
from typing import List, Dict, Optional, Tuple

AUDIT_LOG_FILE = "audit.log"

class TamperProofAudit:
    def __init__(self, log_file: str = AUDIT_LOG_FILE):
        self.log_file = log_file
        self.ensure_log_exists()
    
    def ensure_log_exists(self):
        """Create audit log file if it doesn't exist"""
        if not os.path.exists(self.log_file):
            # Initialize with genesis entry
            genesis_entry = {
                "timestamp": datetime.now().isoformat(),
                "user": "system",
                "action": "audit_log_initialized", 
                "session_id": "genesis",
                "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000"
            }
            genesis_hash = self.calculate_entry_hash(genesis_entry)
            genesis_entry["hash"] = genesis_hash
            
            with open(self.log_file, 'w') as f:
                f.write(json.dumps(genesis_entry) + '\n')
    
    def calculate_entry_hash(self, entry: Dict) -> str:
        """Calculate SHA3-256 hash of log entry"""
        # Create deterministic string from entry (excluding hash field)
        hash_data = {k: v for k, v in entry.items() if k != 'hash'}
        entry_str = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha3_256(entry_str.encode()).hexdigest()
    
    def get_last_hash(self) -> str:
        """Get hash of the last log entry"""
        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
                if lines:
                    last_line = lines[-1].strip()
                    last_entry = json.loads(last_line)
                    return last_entry.get('hash', '0' * 64)
                else:
                    return '0' * 64
        except (FileNotFoundError, json.JSONDecodeError):
            return '0' * 64
    
    def log_action(self, user: str, action: str, session_id: str, details: Optional[Dict] = None) -> bool:
        """Add new audit log entry with blockchain-style chaining"""
        try:
            previous_hash = self.get_last_hash()
            
            entry = {
                "timestamp": datetime.now().isoformat(),
                "user": user,
                "action": action,
                "session_id": session_id,
                "previous_hash": previous_hash
            }
            
            if details:
                entry["details"] = details
            
            # Calculate hash for this entry
            entry_hash = self.calculate_entry_hash(entry)
            entry["hash"] = entry_hash
            
            # Append to log file
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(entry) + '\n')
            
            return True
            
        except Exception as e:
            print(f"Audit logging error: {e}")
            return False
    
    def read_all_logs(self) -> List[Dict]:
        """Read all audit log entries"""
        logs = []
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        logs.append(json.loads(line))
        except FileNotFoundError:
            pass
        return logs
    
    def verify_chain_integrity(self) -> Tuple[bool, List[str]]:
        """Verify the integrity of the audit log chain"""
        logs = self.read_all_logs()
        if not logs:
            return True, []
        
        errors = []
        
        for i, entry in enumerate(logs):
            # Verify hash matches content
            stored_hash = entry.get('hash', '')
            calculated_hash = self.calculate_entry_hash(entry)
            
            if stored_hash != calculated_hash:
                errors.append(f"Entry {i}: Hash mismatch (stored: {stored_hash[:16]}..., calculated: {calculated_hash[:16]}...)")
            
            # Verify chain linkage (except genesis)
            if i > 0:
                previous_entry = logs[i-1]
                expected_previous_hash = previous_entry.get('hash', '')
                actual_previous_hash = entry.get('previous_hash', '')
                
                if expected_previous_hash != actual_previous_hash:
                    errors.append(f"Entry {i}: Chain break (expected: {expected_previous_hash[:16]}..., got: {actual_previous_hash[:16]}...)")
        
        return len(errors) == 0, errors
    
    def get_recent_logs(self, limit: int = 50) -> List[Dict]:
        """Get recent audit log entries"""
        logs = self.read_all_logs()
        return logs[-limit:] if logs else []


# Global audit instance
audit_logger = TamperProofAudit()