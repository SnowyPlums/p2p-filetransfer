import socket
import os
import time
import zipfile
import shutil
import threading
import tkinter.messagebox as messagebox
from cryptography.exceptions import InvalidSignature, InvalidTag
from utils import format_time, format_size
from firebase_admin import db

class NetworkManager:
    def __init__(self, app):
        self.app = app
    
    def start_receiver(self):
        """Start receiving files in the background"""
        if not self.app.receiving:
            self.app.receiving = True
            self.app.status_var.set(f"Listening on port {self.app.port}")
            
            # Start receiving in a new thread
            self.app.receive_thread = threading.Thread(
                target=self.receive_file_thread, 
                args=(self.app.port,),
                daemon=True
            )
            self.app.receive_thread.start()
    
    def get_chunk_size(self, file_size):
        """Determine optimal chunk size based on file size"""
        # 1 MB = 1048576 bytes
        if file_size < 10 * 1048576:  # < 10 MB
            return 4096  # 4 KB
        elif file_size < 100 * 1048576:  # < 100 MB
            return 16384  # 16 KB
        elif file_size < 1024 * 1048576:  # < 1 GB
            return 65536  # 64 KB
        else:  # >= 1 GB
            return 262144  # 256 KB
    
    def get_receive_chunk_size(self, file_size):
        """Determine optimal chunk size for receiving based on file size"""
        # 1 MB = 1048576 bytes
        if file_size < 10 * 1048576:  # < 10 MB
            return 4096  # 4 KB
        elif file_size < 100 * 1048576:  # < 100 MB
            return 16384  # 16 KB
        elif file_size < 1024 * 1048576:  # < 1 GB
            return 65536  # 64 KB
        else:  # >= 1 GB
            return 131072  # 128 KB
    
    def send_files_thread(self, recipient_username, host, port, mode):
        try:
            # First try local IP
            try:
                self.app.send_status_var.set("Trying local network...")
                self.app.root.update()
                
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(5)  # Timeout for local connection
                    s.connect((host, port))
                    self.app.send_status_var.set("Connected via local network")
                    self.app.root.update()
                    self.transfer_files(s, mode)
                    return
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                print(f"Local connection failed: {e}")
            
            # Then try public IP
            try:
                self.app.send_status_var.set("Trying public IP...")
                self.app.root.update()
                
                # Get recipient's public IP from Firebase
                users_ref = db.reference('users')
                recipient_data = users_ref.child(recipient_username).get()
                public_ip = recipient_data.get('public_ip', 'unknown')
                
                if public_ip == 'unknown':
                    messagebox.showerror("Error", "Recipient's public IP is not available")
                    return
                
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(15)  # Longer timeout for internet connection
                    s.connect((public_ip, port))
                    self.app.send_status_var.set("Connected via internet")
                    self.app.root.update()
                    self.transfer_files(s, mode)
            except Exception as e:
                messagebox.showerror("Connection Error", f"Failed to connect: {str(e)}")
        
        except Exception as e:
            if not self.app.abort_transfer:  # Only show error if not aborted
                messagebox.showerror("Error", f"Failed to send files: {str(e)}")
        
        finally:
            # Re-enable UI controls
            self.app.transfer_in_progress = False
            self.app.send_btn.configure(state="normal")
            self.app.abort_btn.configure(state="disabled")
            self.app.abort_transfer = False
    
    def transfer_files(self, s, mode):
        """Perform the file transfer over an established socket"""
        # Perform key exchange
        self.app.send_status_var.set("Establishing secure connection...")
        self.app.root.update()
        shared_key, peer_pubkey = self.app.security.perform_key_exchange(s, is_sender=True)
        
        if mode == "zip":
            # Create zip archive
            zip_path, zip_filename = self.app.create_zip_archive()
            if not zip_path:
                self.app.transfer_in_progress = False
                self.app.send_btn.configure(state="normal")
                self.app.abort_btn.configure(state="disabled")
                return
            
            filesize = os.path.getsize(zip_path)
            
            # Determine chunk size based on file size
            chunk_size = self.get_chunk_size(filesize)
            
            # Send zip file info securely
            file_info = f"ZIP:{zip_filename},{filesize}".encode()
            self.app.security.secure_send(s, file_info, shared_key)
            
            # Send zip file
            sent = 0
            self.app.send_status_var.set(f"Encrypting & sending ZIP: {zip_filename}")
            self.app.root.update()
            
            with open(zip_path, 'rb') as f:
                while sent < filesize and not self.app.abort_transfer:
                    bytes_read = f.read(chunk_size)
                    if not bytes_read:
                        break
                    
                    # Encrypt and send the chunk
                    self.app.security.secure_send(s, bytes_read, shared_key)
                    sent += len(bytes_read)
                    
                    # Update progress and stats
                    progress = int((sent / filesize) * 100)
                    self.app.progress.configure(value=progress)
                    elapsed = time.time() - self.app.transfer_start_time
                    self.app.update_transfer_stats(sent, filesize, elapsed)
            
            # Clean up temporary files
            shutil.rmtree(os.path.dirname(zip_path))
            
            if self.app.abort_transfer:
                messagebox.showinfo("Aborted", "Transfer was aborted by user")
            else:
                messagebox.showinfo("Success", "ZIP archive sent securely!")
            
            self.app.progress.configure(value=0)
            self.app.send_status_var.set("")
            self.app.stats_var.set("")
        
        else:  # Individual files
            # Send transfer header securely
            num_files = len(self.app.file_paths)
            total_size = sum(os.path.getsize(f) for f in self.app.file_paths)
            header = f"MULTI:{num_files},{total_size}".encode()
            self.app.security.secure_send(s, header, shared_key)
            
            sent_total = 0
            
            for i, file_path in enumerate(self.app.file_paths):
                if self.app.abort_transfer:
                    break
                    
                filename = os.path.basename(file_path)
                filesize = os.path.getsize(file_path)
                
                # Determine chunk size based on file size
                chunk_size = self.get_chunk_size(filesize)
                
                # Send file info securely
                file_info = f"FILE:{filename},{filesize}".encode()
                self.app.security.secure_send(s, file_info, shared_key)
                
                # Update status
                self.app.send_status_var.set(f"Encrypting & sending file {i+1}/{num_files}: {filename}")
                self.app.root.update()
                
                # Send file data
                sent_file = 0
                with open(file_path, 'rb') as f:
                    while sent_file < filesize and not self.app.abort_transfer:
                        bytes_read = f.read(chunk_size)
                        if not bytes_read:
                            break
                        
                        # Encrypt and send the chunk
                        self.app.security.secure_send(s, bytes_read, shared_key)
                        sent_file += len(bytes_read)
                        sent_total += len(bytes_read)
                        
                        # Update progress and stats
                        progress = int((sent_total / total_size) * 100)
                        self.app.progress.configure(value=progress)
                        elapsed = time.time() - self.app.transfer_start_time
                        self.app.update_transfer_stats(
                            sent_total, 
                            total_size, 
                            elapsed,
                            i+1,
                            num_files
                        )
            
            # Send completion marker
            self.app.security.secure_send(s, b"COMPLETE", shared_key)
            
            if self.app.abort_transfer:
                messagebox.showinfo("Aborted", "Transfer was aborted by user")
            else:
                messagebox.showinfo("Success", f"{num_files} files sent securely!")
            
            self.app.progress.configure(value=0)
            self.app.send_status_var.set("")
            self.app.stats_var.set("")
    
    def receive_file_thread(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('0.0.0.0', port))
                s.listen()
                s.settimeout(1.0)  # Timeout to check self.receiving periodically
                
                self.app.status_var.set(f"Listening securely on port {port}")
                
                while self.app.receiving:
                    try:
                        conn, addr = s.accept()
                        # Reset abort flag and enable button
                        self.app.abort_receive = False
                        self.app.abort_receive_btn.configure(state="normal")
                    except socket.timeout:
                        continue
                    
                    self.app.status_var.set(f"Secure connection from {addr[0]}")
                    
                    try:
                        # Perform key exchange
                        self.app.status_var.set("Establishing secure connection...")
                        shared_key, peer_pubkey = self.app.security.perform_key_exchange(conn, is_sender=False)
                        
                        # Read initial command securely
                        header = self.app.security.secure_recv(conn, shared_key, peer_pubkey).decode().strip()
                        
                        # Check transfer type
                        if header.startswith("ZIP:"):
                            # ZIP file transfer
                            data = header[4:]  # Remove "ZIP:" prefix
                            filename, filesize = data.split(',', 1)  # Split only on first comma
                            filesize = int(filesize)
                            
                            # Use current receive directory
                            save_path = os.path.join(self.app.receive_dir, filename)
                            received = 0
                            
                            # Start timer for stats
                            start_time = time.time()
                            last_update = start_time
                            last_received = 0
                            
                            with open(save_path, 'wb') as f:
                                while received < filesize and self.app.receiving and not self.app.abort_receive:
                                    # Determine chunk size for receiving
                                    chunk_size = self.get_receive_chunk_size(filesize - received)
                                    
                                    # Securely receive data
                                    encrypted_chunk = self.app.security.secure_recv(conn, shared_key, peer_pubkey)
                                    f.write(encrypted_chunk)
                                    received += len(encrypted_chunk)
                                    
                                    # Update stats every 500ms
                                    current_time = time.time()
                                    if current_time - last_update > 0.5:
                                        elapsed = current_time - start_time
                                        speed = (received - last_received) / (current_time - last_update)
                                        progress = (received / filesize) * 100
                                        
                                        # Calculate ETA
                                        if speed > 0:
                                            remaining_bytes = filesize - received
                                            eta_seconds = remaining_bytes / speed
                                            eta_str = format_time(eta_seconds)
                                        else:
                                            eta_str = "Calculating..."
                                        
                                        speed_str = f"{format_size(speed)}/s"
                                        elapsed_str = format_time(elapsed)
                                        self.app.status_var.set(
                                            f"Receiving ZIP: {progress:.1f}% | "
                                            f"Speed: {speed_str} | "
                                            f"Elapsed: {elapsed_str} | "
                                            f"ETA: {eta_str}"
                                        )
                                        
                                        last_update = current_time
                                        last_received = received
                            
                            if received == filesize:
                                self.app.status_var.set(f"Received secure ZIP: {filename}")
                                messagebox.showinfo("Success", f"ZIP archive received securely! Saved to {self.app.receive_dir}")
                            elif self.app.abort_receive:
                                self.app.status_var.set("Receive aborted")
                                if os.path.exists(save_path):
                                    os.remove(save_path)
                            else:
                                if os.path.exists(save_path):
                                    os.remove(save_path)
                                self.app.status_var.set("Transfer incomplete")
                        
                        elif header.startswith("MULTI:"):
                            # Multiple files transfer
                            parts = header.split(':')[1].split(',')
                            num_files = int(parts[0])
                            total_size = int(parts[1])
                            
                            # Start timer for overall transfer
                            start_time = time.time()
                            total_received = 0
                            files_received = 0
                            
                            # Receive files
                            for i in range(num_files):
                                if not self.app.receiving or self.app.abort_receive:
                                    break
                                
                                # Read file header securely
                                file_header = self.app.security.secure_recv(conn, shared_key, peer_pubkey).decode().strip()
                                if not file_header.startswith("FILE:"):
                                    break
                                
                                # Parse file info
                                file_info = file_header[5:]  # Remove "FILE:" prefix
                                filename, filesize = file_info.split(',', 1)
                                filesize = int(filesize)
                                
                                # Use current receive directory
                                save_path = os.path.join(self.app.receive_dir, filename)
                                received = 0
                                file_start_time = time.time()
                                last_update = file_start_time
                                last_received = 0
                                
                                with open(save_path, 'wb') as f:
                                    while received < filesize and self.app.receiving and not self.app.abort_receive:
                                        # Determine chunk size for receiving
                                        chunk_size = self.get_receive_chunk_size(filesize - received)
                                        
                                        # Securely receive data
                                        encrypted_chunk = self.app.security.secure_recv(conn, shared_key, peer_pubkey)
                                        f.write(encrypted_chunk)
                                        received += len(encrypted_chunk)
                                        total_received += len(encrypted_chunk)
                                        
                                        # Update stats every 500ms
                                        current_time = time.time()
                                        if current_time - last_update > 0.5:
                                            elapsed = current_time - start_time
                                            file_elapsed = current_time - file_start_time
                                            speed = (received - last_received) / (current_time - last_update)
                                            
                                            # Calculate ETA for entire transfer
                                            if speed > 0 and total_size > 0:
                                                # ETA for current file
                                                remaining_current = filesize - received
                                                eta_current = remaining_current / speed
                                                
                                                # ETA for remaining files
                                                remaining_total = total_size - total_received
                                                eta_total = remaining_total / speed
                                                eta_str = format_time(eta_total)
                                            else:
                                                eta_str = "Calculating..."
                                            
                                            progress_total = (total_received / total_size) * 100
                                            progress_file = (received / filesize) * 100
                                            
                                            speed_str = f"{format_size(speed)}/s"
                                            elapsed_str = format_time(elapsed)
                                            
                                            self.app.status_var.set(
                                                f"Receiving file {i+1}/{num_files}: {filename} | "
                                                f"File: {progress_file:.1f}% | "
                                                f"Total: {progress_total:.1f}% | "
                                                f"Speed: {speed_str} | "
                                                f"Elapsed: {elapsed_str} | "
                                                f"ETA: {eta_str}"
                                            )
                                            
                                            last_update = current_time
                                            last_received = received
                                
                                # After file completes
                                if received == filesize:
                                    files_received += 1
                                    self.app.status_var.set(f"Received file {i+1}/{num_files}: {filename}")
                            
                            # Read completion marker
                            complete_marker = self.app.security.secure_recv(conn, shared_key, peer_pubkey).decode().strip()
                            
                            if self.app.abort_receive:
                                self.app.status_var.set("Receive aborted")
                            elif files_received == num_files and complete_marker == "COMPLETE":
                                messagebox.showinfo("Success", f"Successfully received {num_files} files securely to {self.app.receive_dir}!")
                                self.app.status_var.set(f"Received {num_files} files securely")
                        
                        else:
                            # Regular file transfer
                            if ',' not in header:
                                continue
                                
                            filename, filesize = header.split(',', 1)  # Split only on first comma
                            filesize = int(filesize)
                            
                            # Determine chunk size for receiving
                            chunk_size = self.get_receive_chunk_size(filesize)
                            
                            # Use current receive directory
                            save_path = os.path.join(self.app.receive_dir, filename)
                            received = 0
                            
                            # Start timer for stats
                            start_time = time.time()
                            last_update = start_time
                            last_received = 0
                            
                            with open(save_path, 'wb') as f:
                                while received < filesize and self.app.receiving and not self.app.abort_receive:
                                    # Securely receive data
                                    encrypted_chunk = self.app.security.secure_recv(conn, shared_key, peer_pubkey)
                                    f.write(encrypted_chunk)
                                    received += len(encrypted_chunk)
                                    
                                    # Update stats every 500ms
                                    current_time = time.time()
                                    if current_time - last_update > 0.5:
                                        elapsed = current_time - start_time
                                        speed = (received - last_received) / (current_time - last_update)
                                        progress = (received / filesize) * 100
                                        
                                        # Calculate ETA
                                        if speed > 0:
                                            remaining_bytes = filesize - received
                                            eta_seconds = remaining_bytes / speed
                                            eta_str = format_time(eta_seconds)
                                        else:
                                            eta_str = "Calculating..."
                                        
                                        speed_str = f"{format_size(speed)}/s"
                                        elapsed_str = format_time(elapsed)
                                        self.app.status_var.set(
                                            f"Receiving: {progress:.1f}% | "
                                            f"Speed: {speed_str} | "
                                            f"Elapsed: {elapsed_str} | "
                                            f"ETA: {eta_str}"
                                        )
                                        
                                        last_update = current_time
                                        last_received = received
                            
                            if received == filesize:
                                self.app.status_var.set(f"Received: {filename}")
                                messagebox.showinfo("Success", f"File received securely! Saved to {self.app.receive_dir}")
                            elif self.app.abort_receive:
                                self.app.status_var.set("Receive aborted")
                                if os.path.exists(save_path):
                                    os.remove(save_path)
                            else:
                                if os.path.exists(save_path):
                                    os.remove(save_path)
                                self.app.status_var.set("Transfer incomplete")
                    
                    except (ValueError, InvalidSignature, InvalidTag) as e:
                        self.app.status_var.set(f"Security error: {str(e)}")
                        messagebox.showerror("Security Error", "Transfer failed security verification")
                    except Exception as e:
                        self.app.status_var.set(f"Error: {str(e)}")
                    
                    finally:
                        conn.close()
                        # Disable the abort button
                        self.app.abort_receive_btn.configure(state="disabled")
                
                self.app.status_var.set("Receiver stopped")
        
        except Exception as e:
            self.app.status_var.set(f"Receiving error: {str(e)}")