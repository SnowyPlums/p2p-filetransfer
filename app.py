import os
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ttkbootstrap as ttkbs
from ttkbootstrap.constants import *
import firebase_admin
from firebase_admin import credentials, db
import time
import atexit
import zipfile
import tempfile
from datetime import datetime
import configparser
import platform
import queue
from dotenv import load_dotenv

from utils import format_size, format_time, open_directory, get_chunk_size, get_local_ip, get_public_ip
from security import SecurityManager
from network import NetworkManager

class FileTransferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PeerFile Transfer")
        self.root.geometry("850x700")
        
        # Set application icon
        try:
            if platform.system() == 'Windows':
                if os.path.exists("icon.ico"):
                    self.root.iconbitmap("icon.ico")
            elif platform.system() == 'Linux':
                if os.path.exists("icon.png"):
                    img = tk.PhotoImage(file='icon.png')
                    self.root.tk.call('wm', 'iconphoto', self.root._w, img)
            elif platform.system() == 'Darwin':  # macOS
                if os.path.exists("icon.icns"):
                    self.root.iconbitmap("icon.icns")
        except Exception as e:
            print(f"Error setting icon: {e}")
        
        # Load configuration
        self.config = configparser.ConfigParser()
        self.config_file = "config.ini"
        self.load_config()
        
        # Apply theme
        self.style = ttkbs.Style(theme=self.config.get('UI', 'theme', fallback='darkly'))
        
        # Firebase user data
        self.username = self.config.get('User', 'username', fallback='')
        self.local_ip = get_local_ip()
        self.public_ip = get_public_ip()
        self.user_ref = None
        
        # Initialize managers
        self.security = SecurityManager(self)
        self.network = NetworkManager(self)
        
        # Status variables
        self.receiving = False
        self.receive_thread = None
        self.active_users = {}
        self.file_paths = []
        self.send_mode = "individual"  # or "zip"
        self.receive_dir = self.config.get('Settings', 'receive_dir', fallback=os.getcwd())
        self.port = self.config.getint('Network', 'port', fallback=5001)
        
        # Transfer stats
        self.transfer_start_time = 0
        self.last_update_time = 0
        self.last_bytes_sent = 0
        self.current_speed = 0
        self.abort_transfer = False
        self.transfer_in_progress = False
        
        # Zipping progress
        self.zipping_progress = 0
        self.zipping_active = False
        
        # Receiver abort
        self.abort_receive = False
        
        # Queue for zipping progress updates
        self.zipping_queue = queue.Queue()
        
        # Register cleanup function
        atexit.register(self.cleanup)
        
        # Check if username exists in config
        if self.username:
            # Initialize Firebase and proceed to main UI
            if self.initialize_firebase():
                self.initialize_after_login()
            else:
                self.username = ''
                self.create_login_frame()
        else:
            self.create_login_frame()

    def initialize_firebase(self):
        """Initialize Firebase with credentials"""
        try:
            # Only initialize if not already initialized
            if not firebase_admin._apps:
                load_dotenv()  # Load environment variables
                
                key_path = os.getenv("FIREBASE_KEY_PATH")
                if not os.path.exists(key_path):
                    raise FileNotFoundError(f"Firebase key file not found at {key_path}")
                    
                cred = credentials.Certificate(key_path)
                firebase_admin.initialize_app(cred, {
                    'databaseURL': os.getenv('FIREBASE_DATABASE_URL')
                })
                print("Firebase initialized successfully")
                return True
        except Exception as e:
            print(f"Error initializing Firebase: {e}")
            self.firebase_error = e
            return False

    def load_config(self):
        """Load or create configuration file"""
        self.config.read(self.config_file)
        
        # Create default config if doesn't exist
        for section in ['UI', 'Settings', 'Security', 'Network', 'User']:
            if not self.config.has_section(section):
                self.config.add_section(section)
                
        # Set defaults
        defaults = {
            'UI': {'theme': 'darkly'},
            'Settings': {'receive_dir': os.getcwd()},
            'Security': {'key_store': 'keys.dat'},
            'Network': {'port': '5001'},
            'User': {'username': ''}
        }
        
        for section, options in defaults.items():
            for key, value in options.items():
                if not self.config.has_option(section, key):
                    self.config.set(section, key, value)
    
    def save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as configfile:
            self.config.write(configfile)
    
    def create_login_frame(self):
        self.login_frame = ttk.Frame(self.root)
        self.login_frame.pack(fill=BOTH, expand=YES, padx=50, pady=50)
        ttk.Label(self.login_frame, text="PeerFile Transfer", font=("Helvetica", 16)).pack(pady=20)
        
        # Username input
        input_frame = ttk.Frame(self.login_frame)
        input_frame.pack(fill=X, pady=10)
        ttk.Label(input_frame, text="Username:").pack(side=LEFT, padx=(0, 10))
        self.username_entry = ttk.Entry(input_frame)
        self.username_entry.pack(side=LEFT, fill=X, expand=YES)
        
        # Login button
        ttk.Button(
            self.login_frame, 
            text="Login", 
            command=self.login,
            bootstyle=SUCCESS,
            width=10
        ).pack(pady=20)
        
        # Status label
        self.login_status = ttk.Label(self.login_frame, text="", foreground="red")
        self.login_status.pack()
    
    def initialize_after_login(self):
        """Initialize app after successful login"""
        
        # Create main UI
        self.create_main_ui()
        
        # Start background processes
        threading.Thread(target=self.update_presence, daemon=True).start()
        self.update_user_list()
        self.start_receiver()
        threading.Thread(target=self.monitor_zipping_progress, daemon=True).start()
        self.security.generate_keys()
    
    def create_main_ui(self):
        # Remove login frame if exists
        if hasattr(self, 'login_frame'):
            self.login_frame.destroy()
        
        # Create main notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=BOTH, expand=YES, padx=10, pady=10)
        
        # Create tabs
        self.main_tab = ttk.Frame(self.notebook)
        self.config_tab = ttk.Frame(self.notebook)
        self.security_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.main_tab, text="File Transfer")
        self.notebook.add(self.config_tab, text="Configuration")
        self.notebook.add(self.security_tab, text="Security")
        
        # Create UI components
        self.create_main_tab()
        self.create_config_tab()
        self.create_security_tab()
        
        # Create status bar
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.pack(fill=X, side=BOTTOM, padx=10, pady=5)
        
        # Status components
        status_left = ttk.Frame(self.status_bar)
        status_left.pack(side=LEFT, fill=X, expand=YES)
        ip_info = f"User: {self.username} | Local IP: {self.local_ip}"
        if self.public_ip and self.public_ip != "unknown":
            ip_info += f" | Public IP: {self.public_ip}"
        ttk.Label(status_left, text=ip_info).pack(anchor=W)
        
        status_right = ttk.Frame(self.status_bar)
        status_right.pack(side=RIGHT)
        self.status_var = tk.StringVar(value="Ready to receive files")
        ttk.Label(status_right, textvariable=self.status_var).pack(anchor=E)
    
    def create_main_tab(self):
        # User selection
        user_frame = ttk.LabelFrame(self.main_tab, text="Recipient")
        user_frame.pack(fill=X, padx=10, pady=5)
        ttk.Label(user_frame, text="Send to:").pack(side=LEFT, padx=(0, 10))
        self.user_combobox = ttk.Combobox(user_frame, state="readonly")
        self.user_combobox.pack(side=LEFT, fill=X, expand=YES, padx=5)
        ttk.Button(
            user_frame, 
            text="Refresh", 
            command=self.update_user_list,
            bootstyle=INFO,
            width=8
        ).pack(side=RIGHT, padx=(5, 0))
        
        # File Selection
        file_frame = ttk.LabelFrame(self.main_tab, text="Files to Send")
        file_frame.pack(fill=X, padx=10, pady=10)
        
        # File info frame
        file_info_frame = ttk.Frame(file_frame)
        file_info_frame.pack(fill=X, expand=YES)
        self.file_label = ttk.Label(file_info_frame, text="No files selected")
        self.file_label.pack(side=LEFT, fill=X, expand=YES, padx=(0, 10))
        
        # File stats label
        self.file_stats_var = tk.StringVar(value="")
        ttk.Label(file_info_frame, textvariable=self.file_stats_var, foreground="gray").pack(side=RIGHT)
        
        button_frame = ttk.Frame(file_frame)
        button_frame.pack(side=RIGHT)
        ttk.Button(
            button_frame, 
            text="Browse", 
            command=self.browse_files,
            bootstyle=PRIMARY
        ).pack(side=LEFT, padx=(0, 5))
        
        # Transfer mode selection
        mode_frame = ttk.Frame(self.main_tab)
        mode_frame.pack(fill=X, padx=10, pady=5)
        ttk.Label(mode_frame, text="Transfer Mode:").pack(side=LEFT, padx=(0, 10))
        self.mode_var = tk.StringVar(value="individual")
        ttk.Radiobutton(
            mode_frame,
            text="Individual Files",
            variable=self.mode_var,
            value="individual",
            command=self.update_file_label
        ).pack(side=LEFT, padx=(0, 10))
        
        ttk.Radiobutton(
            mode_frame,
            text="ZIP Archive",
            variable=self.mode_var,
            value="zip",
            command=self.update_file_label
        ).pack(side=LEFT)
        
        # Download Directory Section
        dir_frame = ttk.LabelFrame(self.main_tab, text="Download Directory")
        dir_frame.pack(fill=X, padx=10, pady=10)
        
        # Directory path label
        self.dir_label = ttk.Label(dir_frame, text=self.receive_dir)
        self.dir_label.pack(side=LEFT, fill=X, expand=YES, padx=(0, 10))
        
        # Button frame
        dir_button_frame = ttk.Frame(dir_frame)
        dir_button_frame.pack(side=RIGHT)
        
        ttk.Button(
            dir_button_frame, 
            text="Change", 
            command=self.change_directory,
            bootstyle=PRIMARY,
            width=8
        ).pack(side=LEFT, padx=(0, 5))
        
        ttk.Button(
            dir_button_frame, 
            text="Open", 
            command=lambda: open_directory(self.receive_dir),
            bootstyle=SECONDARY,
            width=8
        ).pack(side=LEFT)
        
        # Progress bar
        self.progress = ttkbs.Progressbar(
            self.main_tab, 
            orient=HORIZONTAL,
            length=300,
            mode='determinate'
        )
        self.progress.pack(fill=X, padx=10, pady=5)
        
        # Stats frame
        stats_frame = ttk.Frame(self.main_tab)
        stats_frame.pack(fill=X, padx=10, pady=5)
        
        # Transfer statistics
        self.stats_var = tk.StringVar(value="")
        ttk.Label(stats_frame, textvariable=self.stats_var, font=("TkDefaultFont", 9)).pack(anchor=W)
        
        # Status label
        self.send_status_var = tk.StringVar(value="")
        ttk.Label(self.main_tab, textvariable=self.send_status_var, font=("TkDefaultFont", 10, "bold")).pack(pady=5)
        
        # Button frame for transfer control
        button_frame = ttk.Frame(self.main_tab)
        button_frame.pack(pady=10)
        
        # Send Button
        self.send_btn = ttk.Button(
            button_frame, 
            text="Send File(s)", 
            command=self.send_files,
            bootstyle=SUCCESS, 
            width=12
        )
        self.send_btn.pack(side=LEFT, padx=(0, 10))
        
        # Abort Button
        self.abort_btn = ttk.Button(
            button_frame, 
            text="Abort Transfer", 
            command=self.abort_current_transfer,
            bootstyle=DANGER,
            state=DISABLED,
            width=13
        )
        self.abort_btn.pack(side=LEFT)
        
        # Receive abort button
        receive_abort_frame = ttk.Frame(self.main_tab)
        receive_abort_frame.pack(pady=10)
        
        self.abort_receive_btn = ttk.Button(
            receive_abort_frame, 
            text="Abort Receiving", 
            command=self.abort_receiving,
            bootstyle=DANGER,
            state=DISABLED, 
            width=15
        )
        self.abort_receive_btn.pack()
    
    def create_config_tab(self):
        # Theme Selection
        theme_frame = ttk.LabelFrame(self.config_tab, text="Appearance")
        theme_frame.pack(fill=X, padx=10, pady=10)
        ttk.Label(theme_frame, text="Theme:").pack(side=LEFT, padx=(0, 10))
        self.theme_var = tk.StringVar(value=self.config.get('UI', 'theme'))
        themes = self.style.theme_names()
        theme_combo = ttk.Combobox(
            theme_frame, 
            textvariable=self.theme_var,
            values=themes,
            state="readonly"
        )
        theme_combo.pack(side=LEFT, fill=X, expand=YES, padx=5)
        theme_combo.bind("<<ComboboxSelected>>", self.change_theme)
        
        # Network Settings
        net_frame = ttk.LabelFrame(self.config_tab, text="Network Settings")
        net_frame.pack(fill=X, padx=10, pady=10)
        
        # Port configuration
        port_frame = ttk.Frame(net_frame)
        port_frame.pack(fill=X, padx=5, pady=5)
        ttk.Label(port_frame, text="Port:").pack(side=LEFT, padx=(0, 10))
        
        self.port_var = tk.StringVar(value=str(self.port))
        port_entry = ttk.Entry(port_frame, textvariable=self.port_var, width=10)
        port_entry.pack(side=LEFT, padx=5)
        port_entry.bind("<FocusOut>", self.port_changed)
        
        # Warning label
        ttk.Label(net_frame, text="Note: Changing port requires restart", foreground="orange").pack(anchor=W, padx=5)
    
    def create_security_tab(self):
        """Create security settings tab"""
        security_frame = ttk.LabelFrame(self.security_tab, text="Security Settings")
        security_frame.pack(fill=BOTH, expand=YES, padx=10, pady=10)
        
        # Key management
        key_frame = ttk.Frame(security_frame)
        key_frame.pack(fill=X, padx=5, pady=5)
        
        ttk.Label(key_frame, text="Key Status:").pack(side=LEFT, padx=(0, 10))
        self.key_status_var = tk.StringVar(value="No keys generated")
        ttk.Label(key_frame, textvariable=self.key_status_var).pack(side=LEFT)
        
        ttk.Button(
            key_frame, 
            text="Regenerate Keys", 
            command=self.security.regenerate_keys,
            bootstyle=WARNING,
            width=15
        ).pack(side=RIGHT)
        
        # Public key display
        pubkey_frame = ttk.LabelFrame(security_frame, text="Your Public Key")
        pubkey_frame.pack(fill=X, padx=5, pady=5)
        self.pubkey_text = tk.Text(pubkey_frame, height=5, width=70, state=DISABLED)
        self.pubkey_scroll = ttk.Scrollbar(pubkey_frame, command=self.pubkey_text.yview)
        self.pubkey_text.configure(yscrollcommand=self.pubkey_scroll.set)
        self.pubkey_text.pack(side=LEFT, fill=BOTH, expand=YES, padx=5, pady=5)
        self.pubkey_scroll.pack(side=RIGHT, fill=Y, padx=(0, 5), pady=5)
        
        # Key sharing info
        ttk.Label(security_frame, 
                  text="Your public key is automatically shared with peers during transfers.",
                  font=("TkDefaultFont", 9)).pack(anchor=W, padx=5, pady=5)
        
        # Security status
        status_frame = ttk.Frame(security_frame)
        status_frame.pack(fill=X, padx=5, pady=5)
        ttk.Label(status_frame, text="Encryption Status:").pack(side=LEFT, padx=(0, 10))
        self.encryption_status_var = tk.StringVar(value="Active (AES-256-GCM)")
        ttk.Label(status_frame, textvariable=self.encryption_status_var, foreground="green").pack(side=LEFT)
    
    def port_changed(self, event=None):
        """Handle port change"""
        try:
            port = int(self.port_var.get())
            if port < 1024 or port > 65535:
                raise ValueError("Port must be between 1024 and 65535")
            self.port = port
            self.config.set('Network', 'port', str(port))
            self.save_config()
        except ValueError as e:
            messagebox.showerror("Invalid Port", f"Invalid port number: {str(e)}")
            self.port_var.set(str(self.port))
    
    def change_theme(self, event=None):
        """Change application theme"""
        theme = self.theme_var.get()
        self.style.theme_use(theme)
        self.config.set('UI', 'theme', theme)
        self.save_config()
    
    def change_directory(self):
        """Change the receive directory"""
        directory = filedialog.askdirectory()
        if directory:
            self.receive_dir = directory
            self.dir_label.config(text=directory)
            self.config.set('Settings', 'receive_dir', directory)
            self.save_config()
    
    def login(self):
        """Handle user login"""
        username = self.username_entry.get().strip()
        if not username:
            self.login_status.config(text="Username cannot be empty!")
            return

        try:
            # Initialize Firebase if not already initialized
            if not firebase_admin._apps and not self.initialize_firebase():
                self.login_status.config(text="Failed to initialize Firebase. Check your configuration.")
                return

            # Check if username is already in use
            users_ref = db.reference('users')
            existing_user = users_ref.child(username).get()
            
            if existing_user:
                self.login_status.config(text="Username already in use!")
                return
            
            # Store username in config
            self.config.set('User', 'username', username)
            self.save_config()
            
            self.username = username
            self.initialize_after_login()
            
        except Exception as e:
            error_msg = str(e)
            if hasattr(self, 'firebase_error'):
                error_msg = str(self.firebase_error)
            self.login_status.config(text=f"Login error: {error_msg}")
    
    def start_receiver(self):
        """Start receiving files in the background"""
        if not self.receiving:
            self.receiving = True
            self.status_var.set(f"Listening on port {self.port}")
            
            # Start receiving in a new thread
            self.receive_thread = threading.Thread(
                target=self.network.receive_file_thread, 
                args=(self.port,), 
                daemon=True
            )
            self.receive_thread.start()
    
    def calculate_total_size(self):
        """Calculate total size of selected files"""
        if not self.file_paths:
            return 0
        
        total_size = 0
        for file_path in self.file_paths:
            if os.path.isfile(file_path):
                total_size += os.path.getsize(file_path)
        return total_size
    
    def update_file_label(self):
        """Update file label based on selected files and mode"""
        if not self.file_paths:
            self.file_label.config(text="No files selected")
            self.file_stats_var.set("")
            return
        
        total_size = self.calculate_total_size()
        size_str = format_size(total_size)
        
        if self.mode_var.get() == "zip":
            num_files = len(self.file_paths)
            self.file_label.config(text=f"{num_files} files will be zipped")
            self.file_stats_var.set(f"Total size: {size_str}")
        else:
            if len(self.file_paths) == 1:
                file_path = self.file_paths[0]
                file_size = os.path.getsize(file_path)
                self.file_label.config(text=os.path.basename(file_path))
                self.file_stats_var.set(f"Size: {format_size(file_size)}")
            else:
                self.file_label.config(text=f"{len(self.file_paths)} files selected")
                self.file_stats_var.set(f"Total size: {size_str}")
    
    def browse_files(self):
        file_paths = filedialog.askopenfilenames()
        if file_paths:
            self.file_paths = list(file_paths)
            self.update_file_label()
    
    def create_zip_archive(self):
        """Create a temporary zip file from selected files"""
        try:
            # Create temp directory for zip file
            temp_dir = tempfile.mkdtemp()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            zip_filename = f"transfer_{timestamp}.zip"
            zip_path = os.path.join(temp_dir, zip_filename)
            
            # Update status
            self.send_status_var.set("Creating ZIP archive...")
            self.root.update()
            
            # Create zip file
            with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zipf:
                for file_path in self.file_paths:
                    if os.path.isfile(file_path):
                        # Add file to zip using the standard method
                        arcname = os.path.basename(file_path)
                        zipf.write(file_path, arcname)
            
            return zip_path, zip_filename
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create ZIP archive: {str(e)}")
            return None, None

    def monitor_zipping_progress(self):
        """Monitor and display zipping progress - simplified version"""
        # Placeholder - no longer needed for progress tracking
        pass
    
    def update_transfer_stats(self, sent, total, elapsed, file_index=None, file_count=None):
        """Update transfer statistics display with ETA"""
        # Calculate transfer speed
        current_time = time.time()
        time_diff = current_time - self.last_update_time
        
        if time_diff > 0.5:  # Update stats every 500ms
            bytes_diff = sent - self.last_bytes_sent
            self.current_speed = bytes_diff / time_diff
            self.last_bytes_sent = sent
            self.last_update_time = current_time
        
        # Format statistics
        progress_percent = (sent / total) * 100
        speed_str = f"{format_size(self.current_speed)}/s"
        elapsed_str = format_time(elapsed)
        
        # Calculate ETA
        if self.current_speed > 0:
            remaining_bytes = total - sent
            eta_seconds = remaining_bytes / self.current_speed
            eta_str = format_time(eta_seconds)
        else:
            eta_str = "Calculating..."
        
        stats = ""
        if file_count and file_index is not None:
            remaining_files = file_count - file_index
            stats = f"Files: {file_index}/{file_count} ({remaining_files} left) | "
        
        stats += f"Progress: {progress_percent:.1f}% | "
        stats += f"Speed: {speed_str} | "
        stats += f"Elapsed: {elapsed_str} | "
        stats += f"ETA: {eta_str}"
        self.stats_var.set(stats)
        self.root.update()
    
    def send_files(self):
        # Reset abort flag
        self.abort_transfer = False
        
        # Get selected user
        selected_user = self.user_combobox.get()
        if not selected_user:
            messagebox.showerror("Error", "Please select a recipient")
            return
        
        # Get files
        if not self.file_paths:
            messagebox.showerror("Error", "Please select at least one file")
            return
        
        # Get recipient IP from active users
        host = self.active_users.get(selected_user)
        if not host:
            messagebox.showerror("Error", "Selected user is no longer available")
            self.update_user_list()
            return
        
        # Disable send button and enable abort button
        self.send_btn.configure(state=DISABLED)
        self.abort_btn.configure(state=NORMAL)
        self.transfer_in_progress = True
        
        port = self.port
        mode = self.mode_var.get()
        
        # Initialize transfer stats
        self.transfer_start_time = time.time()
        self.last_update_time = self.transfer_start_time
        self.last_bytes_sent = 0
        self.current_speed = 0
        
        # Start sending in a new thread
        threading.Thread(
            target=self.network.send_files_thread, 
            args=(selected_user, host, port, mode), 
            daemon=True
        ).start()
    
    def abort_current_transfer(self):
        """Abort the current transfer"""
        self.abort_transfer = True
        self.abort_btn.configure(state=DISABLED)
        self.send_status_var.set("Aborting transfer...")
    
    def abort_receiving(self):
        """Abort the current receive operation"""
        self.abort_receive = True
        self.abort_receive_btn.configure(state=DISABLED)
        self.status_var.set("Aborting receive...")
    
    def update_presence(self):
        """Periodically update user presence in Firebase"""
        while True:
            if self.user_ref:
                try:
                    self.user_ref.update({
                        'local_ip': self.local_ip,
                        'public_ip': self.public_ip,
                        'last_seen': time.time()
                    })
                except Exception as e:
                    print(f"Error updating presence: {e}")
            time.sleep(30)
    
    def update_user_list(self):
        """Fetch active users from Firebase"""
        try:
            users = db.reference('users').get() or {}
            
            # Filter active users (active in last 2 minutes)
            current_time = time.time()
            active_users = []
            self.active_users = {}
            
            for username, data in users.items():
                if username == self.username:
                    continue  # Skip self    
                
                # Skip invalid entries
                if not isinstance(data, dict):
                    continue
                
                if current_time - data.get('last_seen', 0) < 120:  # 2 minutes
                    active_users.append(username)
                    
                    # Prefer local IP if available
                    if 'local_ip' in data:
                        self.active_users[username] = data['local_ip']
                    elif 'ip' in data:  # Backward compatibility
                        self.active_users[username] = data['ip']
                    else:
                        self.active_users[username] = data.get('public_ip', 'unknown')
            
            # Update combobox
            self.user_combobox['values'] = active_users
            
            # Auto-select if only one user
            if active_users:
                self.user_combobox.current(0)
            
            # Schedule next update
            self.root.after(15000, self.update_user_list)
        except Exception as e:
            print(f"Error updating user list: {e}")
            self.root.after(15000, self.update_user_list)
    
    def cleanup(self):
        """Clean up resources on exit"""
        self.receiving = False
        self.abort_transfer = True
        self.abort_receive = True
        
        # Remove user from Firebase
        if self.username:
            try:
                db.reference('users').child(self.username).delete()
                print(f"User {self.username} removed from Firebase")
            except Exception as e:
                print(f"Error removing user from Firebase: {e}")
        
        # Save configuration
        self.save_config()
        
        # Save configuration
        self.save_config()