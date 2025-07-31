import os
import secrets
import tkinter as tk
import tkinter.messagebox as messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidTag

class SecurityManager:
    def __init__(self, app):
        self.app = app
        self.private_key = None
        self.public_key = None
        self.key_store = {}
        
    def generate_keys(self):
        """Generate ECDSA key pair if not exists"""
        key_store_path = self.app.config.get('Security', 'key_store', fallback='keys.dat')
        
        try:
            # Try to load existing keys
            if os.path.exists(key_store_path):
                with open(key_store_path, 'rb') as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None,
                        backend=default_backend()
                    )
            else:
                # Generate new keys
                self.private_key = ec.generate_private_key(
                    ec.SECP384R1(),  # Using a strong elliptic curve
                    default_backend()
                )
                # Save keys
                with open(key_store_path, 'wb') as f:
                    f.write(self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
            
            # Derive public key
            self.public_key = self.private_key.public_key()
            self.update_key_display()
            
        except Exception as e:
            messagebox.showerror("Key Error", f"Failed to generate/load keys: {str(e)}")
            self.app.key_status_var.set("Key generation failed")
    
    def regenerate_keys(self):
        """Regenerate security keys"""
        key_store_path = self.app.config.get('Security', 'key_store', fallback='keys.dat')
        
        try:
            # Generate new keys
            self.private_key = ec.generate_private_key(
                ec.SECP384R1(),
                default_backend()
            )
            # Save keys
            with open(key_store_path, 'wb') as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Derive public key
            self.public_key = self.private_key.public_key()
            self.update_key_display()
            messagebox.showinfo("Success", "New security keys generated successfully!")
            
        except Exception as e:
            messagebox.showerror("Key Error", f"Failed to regenerate keys: {str(e)}")
    
    def update_key_display(self):
        """Update UI with key information"""
        if self.public_key:
            pubkey_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            self.app.pubkey_text.config(state="normal")
            self.app.pubkey_text.delete(1.0, tk.END)
            self.app.pubkey_text.insert(tk.END, pubkey_pem)
            self.app.pubkey_text.config(state="disabled")
            self.app.key_status_var.set("Keys generated")
        else:
            self.app.key_status_var.set("No keys available")
    
    def derive_shared_key(self, peer_public_key):
        """Derive AES key using ECDH"""
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Derive 32-byte AES key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure file transfer',
            backend=default_backend()
        ).derive(shared_secret)
        
        return derived_key
    
    def encrypt_data(self, data, key):
        """Encrypt data using AES-GCM"""
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return nonce + encryptor.tag + ciphertext
    
    def decrypt_data(self, encrypted_data, key):
        """Decrypt data using AES-GCM"""
        if len(encrypted_data) < 28:  # 12-byte nonce + 16-byte tag
            raise ValueError("Invalid encrypted data")
            
        nonce = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def sign_data(self, data):
        """Sign data using ECDSA"""
        signature = self.private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256()))
        return signature
    
    def verify_signature(self, data, signature, public_key):
        """Verify data signature"""
        try:
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
    
    def secure_send(self, conn, data, key):
        """Securely send data with encryption and signature"""
        # Encrypt data
        encrypted_data = self.encrypt_data(data, key)
        
        # Sign encrypted data
        signature = self.sign_data(encrypted_data)
        
        # Send signature length and signature
        conn.send(len(signature).to_bytes(4, 'big'))
        conn.send(signature)
        
        # Send encrypted data length and data
        conn.send(len(encrypted_data).to_bytes(4, 'big'))
        conn.send(encrypted_data)
    
    def secure_recv(self, conn, key, peer_public_key):
        """Securely receive data with signature verification and decryption"""
        # Receive signature
        sig_length = int.from_bytes(conn.recv(4), 'big')
        signature = conn.recv(sig_length)
        
        # Receive encrypted data
        data_length = int.from_bytes(conn.recv(4), 'big')
        encrypted_data = b''
        while len(encrypted_data) < data_length:
            chunk = conn.recv(min(4096, data_length - len(encrypted_data)))
            if not chunk:
                break
            encrypted_data += chunk
        
        # Verify signature
        if not self.verify_signature(encrypted_data, signature, peer_public_key):
            raise ValueError("Signature verification failed")
        
        # Decrypt data
        return self.decrypt_data(encrypted_data, key)
    
    def perform_key_exchange(self, conn, is_sender=True):
        """Perform ECDH key exchange over the connection"""
        # Exchange public keys
        if is_sender:
            # Send our public key
            pubkey_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            conn.send(len(pubkey_bytes).to_bytes(4, 'big'))
            conn.send(pubkey_bytes)
            
            # Receive peer public key
            peer_pubkey_length = int.from_bytes(conn.recv(4), 'big')
            peer_pubkey_bytes = conn.recv(peer_pubkey_length)
            peer_public_key = serialization.load_pem_public_key(
                peer_pubkey_bytes,
                backend=default_backend()
            )
        else:
            # Receive peer public key
            peer_pubkey_length = int.from_bytes(conn.recv(4), 'big')
            peer_pubkey_bytes = conn.recv(peer_pubkey_length)
            peer_public_key = serialization.load_pem_public_key(
                peer_pubkey_bytes,
                backend=default_backend()
            )
            
            # Send our public key
            pubkey_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            conn.send(len(pubkey_bytes).to_bytes(4, 'big'))
            conn.send(pubkey_bytes)
        
        # Derive shared key
        shared_key = self.derive_shared_key(peer_public_key)
        
        # Verify key exchange with a challenge
        if is_sender:
            # Send challenge
            challenge = secrets.token_bytes(16)
            self.secure_send(conn, challenge, shared_key)
            
            # Receive response
            response = self.secure_recv(conn, shared_key, peer_public_key)
            if response != challenge:
                raise ValueError("Key exchange verification failed")
        else:
            # Receive challenge
            challenge = self.secure_recv(conn, shared_key, peer_public_key)
            
            # Send response
            self.secure_send(conn, challenge, shared_key)
        
        return shared_key, peer_public_key