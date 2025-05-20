#!/usr/bin/env python3
import os
import sys
import logging
import platform
import socket
import re
import ipaddress
import subprocess
from pathlib import Path

logger = logging.getLogger('vpn_utils')

def get_public_ip():
    """
    Get the public IP address of this machine
    
    Returns:
        String with the public IP address, or None if could not be determined
    """
    try:
        # Try using an external service
        import urllib.request
        response = urllib.request.urlopen('https://api.ipify.org').read().decode('utf8')
        return response
    except Exception as e:
        logger.warning(f"Could not get public IP from external service: {e}")
        
        try:
            # Try using socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception as e:
            logger.warning(f"Could not get public IP using socket: {e}")
            return None

def is_valid_ip(ip_str):
    """
    Check if a string is a valid IP address
    
    Args:
        ip_str: String to check
        
    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def check_openvpn_installed():
    """
    Check if OpenVPN is installed
    
    Returns:
        True if installed, False otherwise
    """
    try:
        result = subprocess.run(['openvpn', '--version'], 
                             stdout=subprocess.PIPE, 
                             stderr=subprocess.PIPE, 
                             check=True)
        version_match = re.search(r'OpenVPN\s+(\d+\.\d+\.\d+)', result.stdout.decode('utf8'))
        if version_match:
            logger.info(f"OpenVPN {version_match.group(1)} is installed")
            return True
        else:
            logger.warning("OpenVPN seems to be installed but could not determine version")
            return True
    except (subprocess.SubprocessError, FileNotFoundError):
        logger.error("OpenVPN is not installed")
        return False

def require_root():
    """
    Check if running as root/administrator, exit if not
    """
    if platform.system() == 'Windows':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            logger.error("This operation requires administrator privileges")
            sys.exit(1)
    else:  # Unix-like
        if os.geteuid() != 0:
            logger.error("This operation requires root privileges")
            sys.exit(1)

def find_network_interfaces():
    """
    Find network interfaces on the system
    
    Returns:
        Dictionary mapping interface names to their IP addresses
    """
    interfaces = {}
    
    if platform.system() == 'Windows':
        # Windows implementation
        try:
            output = subprocess.check_output(['ipconfig'], universal_newlines=True)
            current_if = None
            
            for line in output.splitlines():
                # Look for adapter name
                if 'adapter' in line.lower() and ':' in line:
                    current_if = line.split(':')[0].strip()
                # Look for IPv4 address
                elif current_if and 'IPv4 Address' in line and ':' in line:
                    ip = line.split(':')[1].strip()
                    # Remove parentheses if present
                    ip = re.sub(r'\([^)]*\)', '', ip).strip()
                    interfaces[current_if] = ip
        except Exception as e:
            logger.error(f"Failed to get network interfaces on Windows: {e}")
    else:
        # Unix-like implementation
        try:
            import netifaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    interfaces[iface] = addrs[netifaces.AF_INET][0]['addr']
        except ImportError:
            # Fallback to using subprocess if netifaces is not available
            try:
                if platform.system() == 'Darwin':  # macOS
                    output = subprocess.check_output(['ifconfig'], universal_newlines=True)
                else:  # Linux
                    output = subprocess.check_output(['ip', 'addr', 'show'], universal_newlines=True)
                
                current_if = None
                
                for line in output.splitlines():
                    if platform.system() == 'Darwin':  # macOS
                        # Look for interface name
                        if line and not line.startswith('\t') and not line.startswith(' '):
                            current_if = line.split(':')[0].strip()
                        # Look for inet address
                        elif current_if and 'inet ' in line:
                            parts = line.strip().split()
                            index = parts.index('inet') + 1
                            if index < len(parts):
                                interfaces[current_if] = parts[index]
                    else:  # Linux
                        # Look for interface name
                        if line.startswith(' ') and ':' in line:
                            current_if = line.split(':')[1].strip()
                        # Look for inet address
                        elif current_if and 'inet ' in line:
                            ip = line.strip().split()[1].split('/')[0]
                            interfaces[current_if] = ip
            except Exception as e:
                logger.error(f"Failed to get network interfaces on Unix-like system: {e}")
    
    return interfaces

def format_bytes(bytes_count):
    """
    Format bytes to a human-readable string
    
    Args:
        bytes_count: Number of bytes
        
    Returns:
        Formatted string (e.g. "1.23 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024
    return f"{bytes_count:.2f} PB"

def format_duration(seconds):
    """
    Format duration in seconds to a human-readable string
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted string (e.g. "1d 2h 3m 4s")
    """
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0 or days > 0:
        parts.append(f"{hours}h")
    if minutes > 0 or hours > 0 or days > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    
    return " ".join(parts)

def get_config_dir():
    """
    Get the configuration directory for the application
    
    Returns:
        Path object for the configuration directory
    """
    if platform.system() == 'Windows':
        config_dir = Path(os.environ.get('APPDATA', '')) / 'SimpleVPN'
    else:
        config_dir = Path.home() / '.simple_vpn'
    
    # Create the directory if it doesn't exist
    config_dir.mkdir(parents=True, exist_ok=True)
    
    return config_dir

def get_platform_info():
    """
    Get information about the current platform
    
    Returns:
        Dictionary with platform information
    """
    return {
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'hostname': socket.gethostname(),
        'username': os.getlogin() if hasattr(os, 'getlogin') else 'unknown'
    }

if __name__ == "__main__":
    # Simple test of utility functions
    logging.basicConfig(level=logging.INFO)
    
    print(f"Public IP: {get_public_ip()}")
    print(f"OpenVPN installed: {check_openvpn_installed()}")
    print(f"Network interfaces: {find_network_interfaces()}")
    print(f"Platform info: {get_platform_info()}")
    print(f"Config directory: {get_config_dir()}")
