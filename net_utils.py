import subprocess
import socket
import miniupnpc

def check_port_forwarding(port):
    """Check if port is properly forwarded"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('0.0.0.0', port))
            return True
    except OSError:
        return False

def setup_upnp(port):
    """Attempt automatic port forwarding using UPNP"""
    try:
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 200
        upnp.discover()
        upnp.selectigd()
        upnp.addportmapping(port, 'TCP', upnp.lanaddr, port, 'P2P File Transfer', '')
        return True
    except Exception as e:
        print(f"UPNP error: {e}")
        return False

def check_firewall_windows(port):
    """Check if Windows firewall allows the port"""
    try:
        # Check if rule exists
        command = f'netsh advfirewall firewall show rule name="P2P Port {port}"'
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        
        if "No rules match" in result.stdout:
            # Add firewall rule
            command = (
                f'netsh advfirewall firewall add rule name="P2P Port {port}" '
                f'dir=in action=allow protocol=TCP localport={port}'
            )
            subprocess.run(command, shell=True)
            return True
        return "yes" in result.stdout.lower()  # Check if rule is enabled
    except Exception as e:
        print(f"Firewall check error: {e}")
        return False