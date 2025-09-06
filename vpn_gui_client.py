#!/usr/bin/env python3
"""
Quantum-Resistant VPN GUI Client
================================

A tkinter-based GUI client for the quantum-resistant VPN with IP checking functionality.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import socket
import time
import queue
import os
import json
from src.crypto_utils import QuantumResistantCrypto, send_with_length, recv_with_length
from user_manager import create_user, verify_user


class VPNGUIClient:
    """GUI client for the Quantum-Resistant VPN"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Quantum-Resistant VPN Client")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        # VPN client state
        self.crypto = None
        self.client_socket = None
        self.connection_thread = None
        self.is_connected = False
        self.should_disconnect = False
        
        # Thread-safe logging queue
        self.log_queue = queue.Queue()
        
        self.setup_gui()
        self.process_log_queue()
    
    def setup_gui(self):
        """Set up the GUI layout"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="wens")
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(5, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Quantum-Resistant VPN Client", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Username field
        ttk.Label(main_frame, text="Username:").grid(row=1, column=0, sticky="w", pady=5)
        self.username_entry = ttk.Entry(main_frame, width=30)
        self.username_entry.grid(row=1, column=1, sticky="we", pady=5, padx=(10, 0))
        
        # Password field
        ttk.Label(main_frame, text="Password:").grid(row=2, column=0, sticky="w", pady=5)
        self.password_entry = ttk.Entry(main_frame, width=30, show="*")
        self.password_entry.grid(row=2, column=1, sticky="we", pady=5, padx=(10, 0))
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        self.register_btn = ttk.Button(button_frame, text="Register", 
                                      command=self.register_user, width=12)
        self.register_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.connect_btn = ttk.Button(button_frame, text="Connect", 
                                     command=self.connect_vpn, width=12)
        self.connect_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.disconnect_btn = ttk.Button(button_frame, text="Disconnect", 
                                        command=self.disconnect_vpn, width=12)
        self.disconnect_btn.pack(side=tk.LEFT)
        self.disconnect_btn.config(state="disabled")
        
        # Status label
        self.status_label = ttk.Label(main_frame, text="Status: Disconnected", 
                                     font=("Arial", 12))
        self.status_label.grid(row=4, column=0, columnspan=2, pady=10)
        
        # Log area
        log_frame = ttk.LabelFrame(main_frame, text="Connection Log", padding="5")
        log_frame.grid(row=5, column=0, columnspan=2, sticky="wens", pady=(10, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, width=70, height=15, 
                                                 state=tk.DISABLED, wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky="wens")
        
        # Initial log message
        self.log_message("VPN Client ready")
        self.log_message("Use Register to create account, then Connect to VPN")
    
    def log_message(self, message):
        """Add a message to the log (thread-safe)"""
        timestamp = time.strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        self.log_queue.put(formatted_message)
    
    def process_log_queue(self):
        """Process messages from the log queue and update GUI"""
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.log_text.config(state=tk.NORMAL)
                self.log_text.insert(tk.END, message + "\n")
                self.log_text.see(tk.END)
                self.log_text.config(state=tk.DISABLED)
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_log_queue)
    
    def update_status(self, status):
        """Update the status label"""
        self.status_label.config(text=f"Status: {status}")
    
    def register_user(self):
        """Register a new user"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            self.log_message("Please enter username and password to register")
            messagebox.showerror("Error", "Username and password cannot be empty")
            return
        
        self.log_message(f"Registering user: {username}")
        
        # Create user
        success = create_user(username, password)
        if success:
            self.log_message(f"✅ User {username} registered successfully")
            messagebox.showinfo("Success", f"User {username} registered successfully!")
        else:
            self.log_message(f"❌ Registration failed for {username}")
            messagebox.showerror("Error", f"User {username} already exists")
    
    def connect_vpn(self):
        """Connect to the VPN server"""
        if self.is_connected:
            return
        
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        # Verify user credentials
        if not username or not password:
            self.log_message("Please enter username and password")
            self.update_status("❌ Login failed")
            return
        
        self.log_message(f"Authenticating user: {username}")
        
        # Verify credentials
        if not verify_user(username, password):
            self.log_message(f"❌ Authentication failed for {username}")
            self.update_status("❌ Login failed")
            messagebox.showerror("Error", "Invalid username or password")
            return
        
        self.log_message(f"✅ Authentication successful for {username}")
        self.update_status("Connecting...")
        
        # Disable connect button
        self.connect_btn.config(state="disabled")
        
        # Start connection in separate thread
        self.should_disconnect = False
        self.connection_thread = threading.Thread(target=self.vpn_connection_worker, args=(username,), daemon=True)
        self.connection_thread.start()
    
    def disconnect_vpn(self):
        """Disconnect from the VPN server"""
        if not self.is_connected:
            return
        
        self.log_message("Disconnecting from VPN...")
        self.should_disconnect = True
        
        # Close socket if exists
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        
        self.is_connected = False
        self.update_status("❌ Disconnected")
        self.connect_btn.config(state="normal")
        self.disconnect_btn.config(state="disabled")
        self.log_message("Connection closed")
    
    def send_login_packet(self, username):
        """Send username login packet to server before handshake"""
        self.log_message(f"Sending login packet for user: {username}")
        
        # Create login packet in JSON format
        login_data = {"username": username}
        login_json = json.dumps(login_data)
        login_bytes = login_json.encode('utf-8')
        
        # Send with length prefix
        send_with_length(self.client_socket, login_bytes)
        self.log_message("Login packet sent to server")
        
        # Wait for server response
        try:
            self.client_socket.settimeout(10.0)
            response = recv_with_length(self.client_socket)
            response_text = response.decode('utf-8')
            
            if response_text == "LOGIN_ACCEPTED":
                self.log_message("✅ Server accepted login")
            elif response_text == "LOGIN_REJECTED":
                self.log_message("❌ Server rejected login - unknown user")
                raise Exception("User not found on server")
            else:
                self.log_message(f"❌ Unexpected server response: {response_text}")
                raise Exception("Unexpected server response")
                
        except socket.timeout:
            self.log_message("❌ Server login response timeout")
            raise Exception("Server login timeout")
    
    def vpn_connection_worker(self, username):
        """Worker thread for VPN connection"""
        try:
            # Connect to server
            self.log_message("Connecting to VPN server on localhost:5555...")
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(('localhost', 5555))
            self.log_message("TCP connection established")
            
            # Send username login packet before handshake
            self.send_login_packet(username)
            
            # Initialize crypto
            self.crypto = QuantumResistantCrypto(is_server=False)
            self.log_message("Initializing quantum-resistant cryptography...")
            
            # Generate keys
            self.crypto.generate_keys()
            self.log_message("Generated X25519 and Kyber768 key pairs")
            
            # Perform handshake
            self.perform_handshake()
            
            # Update connection status
            self.is_connected = True
            self.root.after(0, lambda: self.update_status("🔒 Connected"))
            self.root.after(0, lambda: self.connect_btn.config(state="disabled"))
            self.root.after(0, lambda: self.disconnect_btn.config(state="normal"))
            
            # Send test packets
            self.send_test_packets()
            
            # Request IP check from server
            self.request_ip_check()
            
        except Exception as e:
            self.log_message(f"Connection failed: {str(e)}")
            self.root.after(0, lambda: self.update_status("Connection Failed"))
            self.root.after(0, lambda: self.connect_btn.config(state="normal"))
            self.is_connected = False
            
            if self.client_socket:
                try:
                    self.client_socket.close()
                except:
                    pass
    
    def perform_handshake(self):
        """Perform the quantum-resistant handshake"""
        self.log_message("Starting hybrid handshake (X25519 + Kyber768)...")
        
        # Receive server public keys
        server_keys = recv_with_length(self.client_socket)
        self.log_message(f"Received server keys ({len(server_keys)} bytes)")
        
        # Send client public keys
        client_keys = self.crypto.get_public_keys_bytes()
        send_with_length(self.client_socket, client_keys)
        self.log_message(f"Sent client keys ({len(client_keys)} bytes)")
        
        # Perform key exchange
        server_public_keys = self.crypto.parse_public_keys_bytes(server_keys)
        kyber_ciphertext = self.crypto.client_key_exchange(server_public_keys)
        send_with_length(self.client_socket, kyber_ciphertext)
        self.log_message(f"Sent Kyber ciphertext ({len(kyber_ciphertext)} bytes)")
        
        self.log_message("Handshake completed successfully!")
        if self.crypto.session_key:
            key_preview = self.crypto.session_key.hex()[:16]
            self.log_message(f"Session key established: {key_preview}...")
    
    def send_test_packets(self):
        """Send test packets (text, binary, dummy)"""
        self.log_message("Sending test packets...")
        
        # Send text packet
        text_msg = "Hello from GUI VPN client!"
        encrypted_text = self.crypto.encrypt_packet(text_msg, is_dummy=False)
        send_with_length(self.client_socket, encrypted_text)
        self.log_message("Sent text packet")
        
        # Receive ACK for text
        self.receive_ack("text")
        
        # Send binary packet
        binary_data = os.urandom(64)
        encrypted_binary = self.crypto.encrypt_packet(binary_data, is_dummy=False)
        send_with_length(self.client_socket, encrypted_binary)
        self.log_message(f"Sent binary packet ({len(binary_data)} bytes)")
        
        # Receive ACK for binary
        self.receive_ack("binary")
        
        # Send dummy packet
        dummy_packet = self.crypto.create_dummy_packet()
        encrypted_dummy = self.crypto.encrypt_packet(dummy_packet, is_dummy=True)
        send_with_length(self.client_socket, encrypted_dummy)
        self.log_message("Sent dummy packet (no ACK expected)")
        
        time.sleep(0.5)  # Brief pause
    
    def receive_ack(self, packet_type):
        """Receive acknowledgment from server"""
        try:
            self.client_socket.settimeout(5.0)
            ack_packet = recv_with_length(self.client_socket)
            ack_result = self.crypto.decrypt_packet(ack_packet)
            
            if ack_result and ack_result.get("type") == "real":
                ack_data = ack_result["data"]
                self.log_message(f"Received ACK: {ack_data}")
        except Exception as e:
            self.log_message(f"Error receiving {packet_type} ACK: {str(e)}")
    
    def request_ip_check(self):
        """Request IP check from server"""
        self.log_message("Requesting IP check from server...")
        
        try:
            # Send IP check request
            ip_request = "IP_CHECK_REQUEST"
            encrypted_request = self.crypto.encrypt_packet(ip_request, is_dummy=False)
            send_with_length(self.client_socket, encrypted_request)
            self.log_message("Sent IP check request")
            
            # Receive IP response
            self.client_socket.settimeout(5.0)
            ip_response_packet = recv_with_length(self.client_socket)
            ip_result = self.crypto.decrypt_packet(ip_response_packet)
            
            if ip_result and ip_result.get("type") == "real":
                server_ip = ip_result["data"]
                self.log_message(f"Server IP response: {server_ip}")
                self.log_message("Changed IP: Successfully connected through VPN tunnel")
            else:
                self.log_message("No IP response received")
                
        except Exception as e:
            self.log_message(f"IP check failed: {str(e)}")


def main():
    """Main function to run the GUI client"""
    root = tk.Tk()
    app = VPNGUIClient(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("GUI client terminated")


if __name__ == "__main__":
    main()