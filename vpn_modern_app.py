#!/usr/bin/env python3
"""
KyberLink - Modern Quantum-Resistant VPN GUI Application
Built with CustomTkinter for a sleek, dark-themed interface
"""

import customtkinter as ctk
import threading
import time
import json
import socket
import sys
import os
from datetime import datetime

# Add path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))

from user_manager import UserManager
from crypto_utils import QuantumResistantCrypto, send_with_length, recv_with_length

# Set appearance mode and color theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class ModernVPNApp:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("KyberLink - Quantum-Resistant VPN")
        self.root.geometry("800x900")
        self.root.resizable(False, False)
        
        # Initialize components
        self.user_manager = UserManager()
        self.crypto = None
        self.client_socket = None
        self.session_id = None
        self.is_connected = False
        self.should_disconnect = False
        self.username = None
        
        # Session statistics
        self.packets_processed = 0
        self.dummy_packets_dropped = 0
        self.rekeys_performed = 0
        self.current_ip = "Local (127.0.0.1)"
        
        # Background thread control
        self.stats_thread = None
        self.packet_thread = None
        
        # VPN server locations
        self.server_locations = {
            "🇩🇪 Germany": "10.1.0.1",
            "🇺🇸 USA": "10.2.0.1", 
            "🇯🇵 Japan": "10.3.0.1",
            "🇬🇧 UK": "10.4.0.1",
            "🇨🇦 Canada": "10.5.0.1"
        }
        
        # UI State
        self.logged_in = False
        
        self.create_widgets()
        self.start_stats_updater()
        
    def create_widgets(self):
        """Create and layout all GUI components"""
        # Main container with padding
        main_frame = ctk.CTkFrame(self.root, corner_radius=0, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # KyberLink Logo and Title
        logo_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        logo_frame.pack(pady=(0, 20))
        
        # Text-based logo
        logo_label = ctk.CTkLabel(
            logo_frame,
            text="🔐 KyberLink",
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color=("#00d4aa", "#00b894")
        )
        logo_label.pack()
        
        subtitle_label = ctk.CTkLabel(
            logo_frame,
            text="Quantum-Resistant VPN",
            font=ctk.CTkFont(size=16),
            text_color=("#1f538d", "#14375e")
        )
        subtitle_label.pack(pady=(5, 0))
        
        # Create login section initially
        self.create_login_section(main_frame)
        
        # Create VPN panel (hidden initially)
        self.create_vpn_panel(main_frame)
        
        # Create logs panel
        self.create_logs_panel(main_frame)
        
    def create_login_section(self, parent):
        """Create modern login interface"""
        self.login_frame = ctk.CTkFrame(parent, corner_radius=15)
        self.login_frame.pack(fill="x", pady=(0, 20))
        
        # Login title
        login_title = ctk.CTkLabel(
            self.login_frame,
            text="Authentication",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        login_title.pack(pady=(20, 15))
        
        # Username field
        self.username_entry = ctk.CTkEntry(
            self.login_frame,
            placeholder_text="Username",
            width=300,
            height=40,
            font=ctk.CTkFont(size=14),
            corner_radius=10
        )
        self.username_entry.pack(pady=5)
        
        # Password field
        self.password_entry = ctk.CTkEntry(
            self.login_frame,
            placeholder_text="Password",
            show="*",
            width=300,
            height=40,
            font=ctk.CTkFont(size=14),
            corner_radius=10
        )
        self.password_entry.pack(pady=5)
        
        # Button frame
        button_frame = ctk.CTkFrame(self.login_frame, fg_color="transparent")
        button_frame.pack(pady=15)
        
        # Register button
        self.register_btn = ctk.CTkButton(
            button_frame,
            text="Register",
            width=120,
            height=35,
            command=self.register_user,
            font=ctk.CTkFont(size=14, weight="bold"),
            corner_radius=8
        )
        self.register_btn.pack(side="left", padx=(0, 10))
        
        # Login button
        self.login_btn = ctk.CTkButton(
            button_frame,
            text="Login",
            width=120,
            height=35,
            command=self.login_user,
            font=ctk.CTkFont(size=14, weight="bold"),
            corner_radius=8
        )
        self.login_btn.pack(side="left")
        
        # Status label
        self.auth_status_label = ctk.CTkLabel(
            self.login_frame,
            text="Not logged in",
            font=ctk.CTkFont(size=12),
            text_color="#ff6b6b"
        )
        self.auth_status_label.pack(pady=(0, 20))
        
    def create_vpn_panel(self, parent):
        """Create main VPN control panel"""
        self.vpn_frame = ctk.CTkFrame(parent, corner_radius=15)
        
        # Server selection
        server_frame = ctk.CTkFrame(self.vpn_frame, fg_color="transparent")
        server_frame.pack(fill="x", padx=20, pady=(20, 10))
        
        server_label = ctk.CTkLabel(
            server_frame,
            text="Server Location:",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        server_label.pack(anchor="w")
        
        self.location_combo = ctk.CTkComboBox(
            server_frame,
            values=list(self.server_locations.keys()),
            width=300,
            height=35,
            font=ctk.CTkFont(size=14),
            corner_radius=8,
            state="readonly"
        )
        self.location_combo.set("🇩🇪 Germany")
        self.location_combo.pack(pady=(5, 0), anchor="w")
        
        # Large connect button
        self.connect_btn = ctk.CTkButton(
            self.vpn_frame,
            text="Connect",
            width=200,
            height=60,
            command=self.toggle_connection,
            font=ctk.CTkFont(size=18, weight="bold"),
            corner_radius=30,
            fg_color="#28a745",
            hover_color="#218838"
        )
        self.connect_btn.pack(pady=30)
        
        # Status card
        status_card = ctk.CTkFrame(self.vpn_frame, corner_radius=12)
        status_card.pack(fill="x", padx=20, pady=(0, 20))
        
        # Status
        self.status_label = ctk.CTkLabel(
            status_card,
            text="● Disconnected",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#ff6b6b"
        )
        self.status_label.pack(pady=(15, 5))
        
        # Current IP
        self.ip_label = ctk.CTkLabel(
            status_card,
            text=f"Current IP: {self.current_ip}",
            font=ctk.CTkFont(size=14)
        )
        self.ip_label.pack(pady=5)
        
        # Session stats frame
        stats_frame = ctk.CTkFrame(status_card, fg_color="transparent")
        stats_frame.pack(fill="x", padx=15, pady=(10, 15))
        
        # Statistics labels
        self.packets_label = ctk.CTkLabel(
            stats_frame,
            text="Packets: 0",
            font=ctk.CTkFont(size=12)
        )
        self.packets_label.pack(anchor="w")
        
        self.dummy_label = ctk.CTkLabel(
            stats_frame,
            text="Dummies: 0",
            font=ctk.CTkFont(size=12)
        )
        self.dummy_label.pack(anchor="w")
        
        self.rekeys_label = ctk.CTkLabel(
            stats_frame,
            text="Rekeys: 0",
            font=ctk.CTkFont(size=12)
        )
        self.rekeys_label.pack(anchor="w")
        
    def create_logs_panel(self, parent):
        """Create modern logs panel with console-like appearance"""
        logs_frame = ctk.CTkFrame(parent, corner_radius=15)
        logs_frame.pack(fill="both", expand=True, pady=(20, 0))
        
        # Logs title
        logs_title = ctk.CTkLabel(
            logs_frame,
            text="Activity Log",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        logs_title.pack(pady=(15, 10))
        
        # Logs text area
        self.log_text = ctk.CTkTextbox(
            logs_frame,
            width=750,
            height=200,
            font=ctk.CTkFont(family="Consolas", size=11),
            corner_radius=8,
            fg_color="#1a1a1a",
            text_color="#ffffff"
        )
        self.log_text.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
    def log_message(self, message, level="INFO"):
        """Add colored message to log with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color mapping
        colors = {
            "INFO": "#00d4aa",    # Teal
            "SUCCESS": "#28a745",  # Green
            "ERROR": "#dc3545",    # Red
            "WARNING": "#ffc107"   # Yellow
        }
        
        color = colors.get(level, "#ffffff")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        
        def update_log():
            self.log_text.insert("end", log_entry)
            self.log_text.see("end")
            
        # Thread-safe GUI update
        self.root.after(0, update_log)
        
    def register_user(self):
        """Register a new user"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            self.auth_status_label.configure(text="Please enter both username and password", text_color="#ff6b6b")
            self.log_message("Registration failed: Missing credentials", "ERROR")
            return
            
        try:
            if self.user_manager.user_exists(username):
                self.auth_status_label.configure(text=f"User '{username}' already exists", text_color="#ff6b6b")
                self.log_message(f"Registration failed: User {username} exists", "ERROR")
                return
                
            self.user_manager.create_user(username, password)
            self.auth_status_label.configure(text=f"User '{username}' registered successfully", text_color="#28a745")
            self.log_message(f"[KyberLink] User '{username}' registered successfully", "SUCCESS")
            
        except Exception as e:
            self.auth_status_label.configure(text=f"Registration failed: {e}", text_color="#ff6b6b")
            self.log_message(f"Registration failed: {e}", "ERROR")
            
    def login_user(self):
        """Authenticate user credentials"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            self.auth_status_label.configure(text="Please enter both username and password", text_color="#ff6b6b")
            self.log_message("Login failed: Missing credentials", "ERROR")
            return
            
        try:
            if self.user_manager.verify_password(username, password):
                self.username = username
                self.logged_in = True
                self.auth_status_label.configure(text=f"Logged in as: {username}", text_color="#28a745")
                self.log_message(f"[KyberLink] Successfully logged in as {username}", "SUCCESS")
                self.show_vpn_panel()
            else:
                self.auth_status_label.configure(text="Invalid username or password", text_color="#ff6b6b")
                self.log_message("Login failed: Invalid credentials", "ERROR")
                
        except Exception as e:
            self.auth_status_label.configure(text=f"Login failed: {e}", text_color="#ff6b6b")
            self.log_message(f"Login failed: {e}", "ERROR")
            
    def show_vpn_panel(self):
        """Show VPN panel after successful login"""
        self.login_frame.pack_forget()
        self.vpn_frame.pack(fill="x", pady=(0, 20))
        
    def toggle_connection(self):
        """Toggle VPN connection state"""
        if not self.logged_in:
            self.log_message("Please login first", "ERROR")
            return
            
        if not self.is_connected:
            self.connect_vpn()
        else:
            self.disconnect_vpn()
            
    def connect_vpn(self):
        """Connect to VPN server"""
        selected_location = self.location_combo.get()
        self.log_message(f"Connecting to {selected_location} server...", "INFO")
        
        # Update button state
        self.connect_btn.configure(
            text="Connecting...",
            state="disabled",
            fg_color="#6c757d"
        )
        
        # Start connection in background thread
        connect_thread = threading.Thread(target=self.vpn_connection_worker, 
                                          args=(selected_location,))
        connect_thread.daemon = True
        connect_thread.start()
        
    def vpn_connection_worker(self, location):
        """Background worker for VPN connection"""
        try:
            # Initialize crypto
            self.crypto = QuantumResistantCrypto(is_server=False)
            self.crypto.generate_keys()
            self.log_message("[KyberLink] Generated quantum-resistant keys", "SUCCESS")
            
            # Connect to server
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(('localhost', 5555))
            self.log_message("[KyberLink] Connected to VPN server", "SUCCESS")
            
            # Send login packet
            if not self.send_login_packet():
                return
                
            # Perform handshake
            if not self.perform_handshake():
                return
                
            # Receive session ID
            if not self.receive_session_id():
                return
                
            # Update GUI state
            def update_connected_state():
                self.is_connected = True
                self.current_ip = self.server_locations[location]
                self.status_label.configure(text="● Connected", text_color="#28a745")
                self.ip_label.configure(text=f"Current IP: {self.current_ip}")
                self.connect_btn.configure(
                    text="Disconnect",
                    state="normal",
                    fg_color="#dc3545",
                    hover_color="#c82333"
                )
                
            self.root.after(0, update_connected_state)
            self.log_message(f"[KyberLink] VPN connected to {location} - IP: {self.current_ip}", "SUCCESS")
            
            # Start packet transmission thread
            self.should_disconnect = False
            self.packet_thread = threading.Thread(target=self.packet_worker)
            self.packet_thread.daemon = True
            self.packet_thread.start()
            
        except Exception as e:
            self.log_message(f"Connection failed: {e}", "ERROR")
            def restore_button():
                self.connect_btn.configure(
                    text="Connect",
                    state="normal",
                    fg_color="#28a745",
                    hover_color="#218838"
                )
            self.root.after(0, restore_button)
            
    def send_login_packet(self):
        """Send authentication packet to server"""
        try:
            import base64
            from datetime import datetime
            
            # Create login packet
            client_nonce = base64.b64encode(os.urandom(16)).decode('utf-8')
            timestamp = datetime.utcnow().isoformat() + 'Z'
            
            login_data = {
                "username": self.username,
                "client_nonce": client_nonce,
                "timestamp": timestamp,
                "version": "1.0"
            }
            
            login_json = json.dumps(login_data)
            login_bytes = login_json.encode('utf-8')
            send_with_length(self.client_socket, login_bytes)
            
            # Wait for response
            self.client_socket.settimeout(10.0)
            response = recv_with_length(self.client_socket)
            response_text = response.decode('utf-8')
            
            if response_text == "LOGIN_ACCEPTED":
                self.log_message("[KyberLink] Server accepted authentication", "SUCCESS")
                return True
            else:
                self.log_message(f"Server rejected authentication: {response_text}", "ERROR")
                return False
                
        except Exception as e:
            self.log_message(f"Authentication failed: {e}", "ERROR")
            return False
            
    def perform_handshake(self):
        """Perform quantum-resistant handshake"""
        try:
            self.log_message("[KyberLink] Starting quantum-resistant handshake...", "INFO")
            
            # Receive server public keys
            server_public_keys = recv_with_length(self.client_socket)
            self.log_message(f"Received server keys ({len(server_public_keys)} bytes)", "INFO")
            
            # Send client public keys
            client_public_keys = self.crypto.get_public_keys_bytes()
            send_with_length(self.client_socket, client_public_keys)
            self.log_message(f"Sent client keys ({len(client_public_keys)} bytes)", "INFO")
            
            # Perform key exchange
            kyber_ciphertext = self.crypto.client_key_exchange(server_public_keys)
            send_with_length(self.client_socket, kyber_ciphertext)
            self.log_message("[KyberLink] Completed hybrid key exchange", "SUCCESS")
            
            return True
            
        except Exception as e:
            self.log_message(f"Handshake failed: {e}", "ERROR")
            return False
            
    def receive_session_id(self):
        """Receive session ID from server"""
        try:
            session_packet = recv_with_length(self.client_socket)
            session_json = session_packet.decode('utf-8')
            session_data = json.loads(session_json)
            
            if session_data.get("type") == "session_id":
                self.session_id = session_data.get("session_id")
                self.log_message(f"[KyberLink] Assigned session: {self.session_id}", "SUCCESS")
                return True
            else:
                self.log_message("Failed to receive session ID", "ERROR")
                return False
                
        except Exception as e:
            self.log_message(f"Session setup failed: {e}", "ERROR")
            return False
            
    def packet_worker(self):
        """Background worker for packet transmission"""
        packet_count = 0
        
        while not self.should_disconnect and self.is_connected:
            try:
                packet_count += 1
                
                # Send test packet
                message = f"VPN test packet #{packet_count}"
                encrypted_packet = self.crypto.encrypt_packet(message)
                send_with_length(self.client_socket, encrypted_packet)
                
                # Receive acknowledgment
                self.client_socket.settimeout(5.0)
                ack_packet = recv_with_length(self.client_socket)
                ack_message = self.crypto.decrypt_packet(ack_packet)
                
                self.packets_processed += 1
                
                # Send dummy packet occasionally
                if packet_count % 4 == 0:
                    dummy_packet = self.crypto.encrypt_packet("DUMMY", is_dummy=True)
                    send_with_length(self.client_socket, dummy_packet)
                    self.dummy_packets_dropped += 1
                    
                # Check for rekeys
                if hasattr(self.crypto, 'packets_since_rekey') and self.crypto.packets_since_rekey == 0:
                    self.rekeys_performed += 1
                    
                time.sleep(3)  # Send packet every 3 seconds
                
            except Exception as e:
                if not self.should_disconnect:
                    self.log_message(f"Packet transmission error: {e}", "ERROR")
                break
                
    def disconnect_vpn(self):
        """Disconnect from VPN"""
        self.log_message("[KyberLink] Disconnecting from VPN...", "INFO")
        self.should_disconnect = True
        
        # Close socket
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
                
        # Update GUI state
        self.is_connected = False
        self.current_ip = "Local (127.0.0.1)"
        self.status_label.configure(text="● Disconnected", text_color="#ff6b6b")
        self.ip_label.configure(text=f"Current IP: {self.current_ip}")
        self.connect_btn.configure(
            text="Connect",
            state="normal",
            fg_color="#28a745",
            hover_color="#218838"
        )
        
        # Reset stats
        self.packets_processed = 0
        self.dummy_packets_dropped = 0
        self.rekeys_performed = 0
        
        self.log_message("[KyberLink] VPN disconnected - Session ended", "SUCCESS")
        
    def start_stats_updater(self):
        """Start background thread for updating statistics"""
        def update_stats():
            while True:
                def update_gui():
                    if hasattr(self, 'packets_label'):
                        self.packets_label.configure(text=f"Packets: {self.packets_processed}")
                        self.dummy_label.configure(text=f"Dummies: {self.dummy_packets_dropped}")
                        self.rekeys_label.configure(text=f"Rekeys: {self.rekeys_performed}")
                    
                self.root.after(0, update_gui)
                time.sleep(2)  # Update every 2 seconds
                
        self.stats_thread = threading.Thread(target=update_stats)
        self.stats_thread.daemon = True
        self.stats_thread.start()
        
    def on_closing(self):
        """Handle application closing"""
        if self.is_connected:
            self.disconnect_vpn()
        self.root.destroy()


def main():
    app = ModernVPNApp()
    
    # Handle window closing
    app.root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    # Center window on screen
    app.root.eval('tk::PlaceWindow . center')
    
    # Start the modern GUI
    app.root.mainloop()


if __name__ == "__main__":
    main()