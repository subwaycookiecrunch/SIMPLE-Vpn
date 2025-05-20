#!/usr/bin/env python3
import os
import sys
import subprocess
import logging
import time
import platform
import tempfile
from pathlib import Path
import shutil

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('vpn_client')

class VPNConnection:
    def __init__(self, config_file=None, config_dir='./vpn_client_configs', log_file=None):
        """
        Initialize VPN connection
        
        Args:
            config_file: Path to the OpenVPN client configuration file
            config_dir: Directory to store client configuration files
            log_file: Path to the log file for connection output
        """
        self.config_dir = Path(config_dir)
        
        # Create config directory if it doesn't exist
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        if config_file:
            self.config_file = Path(config_file)
        else:
            # Look for .ovpn files in the config directory
            ovpn_files = list(self.config_dir.glob('*.ovpn'))
            if ovpn_files:
                self.config_file = ovpn_files[0]
                logger.info(f"Using config file: {self.config_file}")
            else:
                self.config_file = None
                logger.warning("No OpenVPN configuration file found")
        
        # Set log file
        if log_file:
            self.log_file = Path(log_file)
        else:
            self.log_file = self.config_dir / 'openvpn-client.log'
        
        # Process handle for the OpenVPN client
        self.process = None
        self.system = platform.system().lower()
        
        # Check if OpenVPN is installed
        self._check_openvpn_installed()
    
    def _check_openvpn_installed(self):
        """Verify OpenVPN is installed on the system"""
        try:
            subprocess.run(['openvpn', '--version'], 
                          stdout=subprocess.PIPE, 
                          stderr=subprocess.PIPE, 
                          check=True)
            logger.info("OpenVPN is installed")
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.error("OpenVPN is not installed. Please install it before proceeding.")
            sys.exit(1)
    
    def import_config(self, config_file, name=None):
        """
        Import an OpenVPN configuration file
        
        Args:
            config_file: Path to the configuration file to import
            name: Name to save the configuration as (defaults to the filename)
            
        Returns:
            Path to the imported configuration file
        """
        src_path = Path(config_file)
        
        if not src_path.exists():
            logger.error(f"Configuration file not found: {src_path}")
            return None
        
        # Use provided name or original filename
        if name:
            dest_name = f"{name}.ovpn"
        else:
            dest_name = src_path.name
        
        dest_path = self.config_dir / dest_name
        
        # Copy the configuration file
        try:
            shutil.copy2(src_path, dest_path)
            logger.info(f"Imported configuration file to {dest_path}")
            
            # Set as the current config file
            self.config_file = dest_path
            
            return dest_path
        except Exception as e:
            logger.error(f"Failed to import configuration file: {e}")
            return None
    
    def list_configs(self):
        """
        List available configuration files
        
        Returns:
            List of configuration file paths
        """
        return list(self.config_dir.glob('*.ovpn'))
    
    def set_active_config(self, config_file):
        """
        Set the active configuration file
        
        Args:
            config_file: Path to the configuration file to use
            
        Returns:
            True if successful, False otherwise
        """
        config_path = Path(config_file)
        
        if not config_path.exists():
            logger.error(f"Configuration file not found: {config_path}")
            return False
        
        self.config_file = config_path
        logger.info(f"Set active configuration to {config_path}")
        return True
    
    def connect(self, auth=None):
        """
        Connect to the VPN server
        
        Args:
            auth: Tuple of (username, password) for authentication
            
        Returns:
            Process object if connection succeeded, None otherwise
        """
        if not self.config_file or not self.config_file.exists():
            logger.error("No configuration file specified")
            return None
        
        # If already connected, disconnect first
        if self.is_connected():
            logger.info("Already connected, disconnecting first")
            self.disconnect()
        
        logger.info(f"Connecting to VPN using {self.config_file}")
        
        try:
            cmd = ['openvpn', '--config', str(self.config_file)]
            
            # If authentication is provided, create a temporary auth file
            auth_file = None
            if auth:
                username, password = auth
                auth_file = tempfile.NamedTemporaryFile(mode='w+', delete=False)
                auth_file.write(f"{username}\n{password}")
                auth_file.close()
                cmd.extend(['--auth-user-pass', auth_file.name])
            
            # Redirect output to log file
            with open(self.log_file, 'w') as f:
                # Start OpenVPN as a subprocess
                self.process = subprocess.Popen(
                    cmd,
                    stdout=f,
                    stderr=f,
                    universal_newlines=True
                )
            
            # Give it some time to initialize
            time.sleep(2)
            
            # Check if process is still running
            if self.process.poll() is not None:
                exitcode = self.process.returncode
                logger.error(f"Failed to connect: OpenVPN exited with code {exitcode}")
                # Read last few lines of log file for error information
                try:
                    with open(self.log_file, 'r') as f:
                        log_tail = ''.join(f.readlines()[-10:])
                        logger.error(f"OpenVPN error: {log_tail}")
                except:
                    pass
                self.process = None
                return None
            
            logger.info("VPN connection established")
            
            # Clean up auth file if used
            if auth_file:
                try:
                    os.unlink(auth_file.name)
                except:
                    pass
            
            return self.process
        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            self.process = None
            return None
    
    def disconnect(self):
        """
        Disconnect from the VPN server
        
        Returns:
            True if disconnected successfully, False otherwise
        """
        if not self.process:
            logger.info("Not connected")
            return True
        
        logger.info("Disconnecting from VPN")
        
        try:
            # Terminate the OpenVPN process
            self.process.terminate()
            
            # Wait for process to terminate (give it 5 seconds)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Force kill if it doesn't terminate gracefully
                self.process.kill()
                self.process.wait()
            
            self.process = None
            logger.info("VPN disconnected")
            return True
        except Exception as e:
            logger.error(f"Failed to disconnect: {e}")
            return False
    
    def is_connected(self):
        """
        Check if connected to the VPN
        
        Returns:
            True if connected, False otherwise
        """
        if not self.process:
            return False
        
        # Check if process is still running
        return self.process.poll() is None
    
    def get_connection_status(self):
        """
        Get the current connection status
        
        Returns:
            Dictionary with connection status information
        """
        status = {
            'connected': self.is_connected(),
            'config_file': str(self.config_file) if self.config_file else None,
            'log_file': str(self.log_file)
        }
        
        # Get additional connection info from the log file if connected
        if status['connected'] and self.log_file.exists():
            try:
                with open(self.log_file, 'r') as f:
                    log_content = f.read()
                
                # Extract the VPN IP address (if available)
                import re
                ip_match = re.search(r'ip=(\d+\.\d+\.\d+\.\d+)', log_content)
                if ip_match:
                    status['vpn_ip'] = ip_match.group(1)
                
                # Extract connection time
                init_match = re.search(r'Initialization Sequence Completed', log_content)
                if init_match:
                    status['initialized'] = True
            except Exception as e:
                logger.error(f"Failed to parse log file: {e}")
        
        return status
    
    def get_log_tail(self, lines=20):
        """
        Get the last few lines of the log file
        
        Args:
            lines: Number of lines to return
            
        Returns:
            String with the last lines of the log
        """
        if not self.log_file.exists():
            return "Log file not found"
        
        try:
            with open(self.log_file, 'r') as f:
                return ''.join(f.readlines()[-lines:])
        except Exception as e:
            logger.error(f"Failed to read log file: {e}")
            return f"Error reading log file: {e}"

def connect_vpn(config_file, auth=None):
    """
    Helper function to quickly connect to a VPN
    
    Args:
        config_file: Path to the OpenVPN configuration file
        auth: Tuple of (username, password) for authentication
        
    Returns:
        VPNConnection object if connected successfully, None otherwise
    """
    connection = VPNConnection(config_file=config_file)
    if connection.connect(auth=auth):
        return connection
    return None

if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <config_file> [username] [password]")
        sys.exit(1)
    
    config_file = sys.argv[1]
    
    # Optional authentication
    auth = None
    if len(sys.argv) >= 4:
        auth = (sys.argv[2], sys.argv[3])
    
    # Connect to VPN
    connection = VPNConnection(config_file=config_file)
    if connection.connect(auth=auth):
        print("Connected to VPN")
        print("Press Ctrl+C to disconnect")
        
        try:
            while connection.is_connected():
                time.sleep(1)
        except KeyboardInterrupt:
            connection.disconnect()
            print("Disconnected from VPN")
    else:
        print("Failed to connect to VPN")
