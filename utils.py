import os
import math
import platform
import subprocess
import socket
import requests

def format_size(size_bytes):
    """Convert bytes to human-readable format"""
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"

def format_time(seconds):
    """Convert seconds to human-readable format"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = seconds // 60
    seconds %= 60
    return f"{int(minutes)}m {seconds:.1f}s"

def open_directory(path):
    """Open directory in system file explorer"""
    try:
        if platform.system() == "Windows":
            os.startfile(path)
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception as e:
        print(f"Error opening directory: {e}")

def get_chunk_size(file_size):
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

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"
    
def get_public_ip():
        """Get public IP address"""
        try:
            # Use multiple services for reliability
            services = [
                'https://api.ipify.org',
                'https://ident.me',
                'https://ipinfo.io/ip'
            ]
            
            for service in services:
                try:
                    response = requests.get(service, timeout=5)
                    if response.status_code == 200:
                        return response.text.strip()
                except:
                    continue
            return "unknown"
        except Exception as e:
            print(f"Error getting public IP: {e}")
            return "unknown"