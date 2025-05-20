#!/usr/bin/env python3
import os
import sys
import subprocess
import logging
import time
import shutil
import ipaddress
from pathlib import Path
import socket
import click
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('vpn_server')

# Load environment variables if .env exists
load_dotenv()

class OpenVPNServer:
    def __init__(self, config_dir='./vpn_configs', 
                 server_ip=None, 
                 port=1194,
                 protocol='udp',
                 subnet='10.8.0.0',
                 subnet_mask='255.255.255.0'):
        """
        Initialize the OpenVPN server
        
        Args:
            config_dir: Directory to store OpenVPN configuration files
            server_ip: Public IP of the server (autodetected if None)
            port: Port for OpenVPN to listen on
            protocol: 'udp' or 'tcp'
            subnet: VPN subnet
            subnet_mask: VPN subnet mask
        """
        self.config_dir = Path(config_dir)
        self.server_ip = server_ip or self._get_public_ip()
        self.port = port
        self.protocol = protocol
        self.subnet = subnet
        self.subnet_mask = subnet_mask
        
        # Create config directory if it doesn't exist
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Paths for various files
        self.ca_dir = self.config_dir / 'ca'
        self.server_conf_path = self.config_dir / 'server.conf'
        
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
    
    def _get_public_ip(self):
        """Get the public IP address of this machine"""
        try:
            import pystun3
            nat_type, external_ip, external_port = pystun3.get_ip_info()
            logger.info(f"Detected public IP: {external_ip}")
            return external_ip
        except Exception as e:
            logger.warning(f"Could not automatically detect public IP: {e}")
            # Fallback to asking the user
            ip = input("Enter server public IP address: ")
            return ip
    
    def setup_pki(self):
        """Set up the Public Key Infrastructure for OpenVPN"""
        logger.info("Setting up PKI (Public Key Infrastructure)...")
        
        # Set up easy-rsa
        if not (self.ca_dir / 'vars').exists():
            os.makedirs(self.ca_dir, exist_ok=True)
            
            # Check if easy-rsa is available
            try:
                easy_rsa_path = subprocess.run(['which', 'easyrsa'], 
                                            stdout=subprocess.PIPE, 
                                            text=True,
                                            check=True).stdout.strip()
                logger.info(f"Found easy-rsa at {easy_rsa_path}")
            except subprocess.SubprocessError:
                logger.error("easy-rsa is not installed. Please install it.")
                sys.exit(1)
                
            # Initialize PKI
            subprocess.run(['easyrsa', 'init-pki'], 
                          cwd=self.ca_dir, check=True)
            
            # Build CA
            env = os.environ.copy()
            env['EASYRSA_BATCH'] = '1'  # Non-interactive mode
            subprocess.run(['easyrsa', 'build-ca', 'nopass'],
                          cwd=self.ca_dir, env=env, check=True)
                          
            # Generate server certificate and key
            subprocess.run(['easyrsa', 'build-server-full', 'server', 'nopass'],
                          cwd=self.ca_dir, env=env, check=True)
                          
            # Generate Diffie-Hellman parameters
            subprocess.run(['easyrsa', 'gen-dh'],
                          cwd=self.ca_dir, check=True)
                          
            # Generate TLS auth key
            subprocess.run(['openvpn', '--genkey', '--secret', 'ta.key'],
                          cwd=self.ca_dir, check=True)
            
            logger.info("PKI setup completed successfully")
        else:
            logger.info("PKI already set up")
    
    def create_server_config(self):
        """Create the server configuration file"""
        logger.info("Creating server configuration...")
        
        config = f"""# OpenVPN Server Configuration
port {self.port}
proto {self.protocol}
dev tun

ca {self.ca_dir}/ca.crt
cert {self.ca_dir}/issued/server.crt
key {self.ca_dir}/private/server.key
dh {self.ca_dir}/dh.pem
tls-auth {self.ca_dir}/ta.key 0

server {self.subnet} {self.subnet_mask}
ifconfig-pool-persist ipp.txt

keepalive 10 120
cipher AES-256-CBC
auth SHA256

user nobody
group nogroup

persist-key
persist-tun

status openvpn-status.log
log-append openvpn.log
verb 3
mute 20

# Push routes to client to allow it to reach other private subnets
push "route 10.8.0.0 255.255.255.0"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

# Enable compression
comp-lzo
"""
        with open(self.server_conf_path, 'w') as f:
            f.write(config)
        
        logger.info(f"Server configuration created at {self.server_conf_path}")
    
    def generate_client_config(self, client_name):
        """Generate a client configuration file"""
        logger.info(f"Generating configuration for client: {client_name}")
        
        # Check if PKI is set up
        if not (self.ca_dir / 'ca.crt').exists():
            logger.error("PKI not set up. Run setup_pki() first")
            return
        
        # Generate client certificate
        env = os.environ.copy()
        env['EASYRSA_BATCH'] = '1'  # Non-interactive mode
        subprocess.run(['easyrsa', 'build-client-full', client_name, 'nopass'],
                      cwd=self.ca_dir, env=env, check=True)
        
        # Create client config directory
        client_dir = self.config_dir / 'clients'
        client_dir.mkdir(exist_ok=True)
        
        client_conf_path = client_dir / f"{client_name}.ovpn"
        
        # Get the content of CA, client cert and key, and tls-auth key
        with open(self.ca_dir / 'ca.crt', 'r') as f:
            ca_cert = f.read()
        
        with open(self.ca_dir / f'issued/{client_name}.crt', 'r') as f:
            client_cert = f.read()
        
        with open(self.ca_dir / f'private/{client_name}.key', 'r') as f:
            client_key = f.read()
        
        with open(self.ca_dir / 'ta.key', 'r') as f:
            ta_key = f.read()
        
        # Create client config with embedded certificates
        client_config = f"""# OpenVPN Client Configuration
client
dev tun
proto {self.protocol}
remote {self.server_ip} {self.port}
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-CBC
auth SHA256
verb 3
mute 20
comp-lzo
explicit-exit-notify 1

<ca>
{ca_cert}
</ca>

<cert>
{client_cert}
</cert>

<key>
{client_key}
</key>

<tls-auth>
{ta_key}
</tls-auth>
key-direction 1
"""

        with open(client_conf_path, 'w') as f:
            f.write(client_config)
        
        logger.info(f"Client configuration created at {client_conf_path}")
        return client_conf_path
    
    def start(self):
        """Start the OpenVPN server"""
        logger.info("Starting OpenVPN server...")
        
        if not self.server_conf_path.exists():
            logger.error("Server configuration not found. Run create_server_config() first")
            return
        
        try:
            # Use subprocess to start OpenVPN as a background process
            process = subprocess.Popen(
                ['openvpn', '--config', str(self.server_conf_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            logger.info(f"OpenVPN server started with PID {process.pid}")
            logger.info(f"Server is listening on {self.server_ip}:{self.port}/{self.protocol}")
            
            # Return the process so it can be managed by the caller
            return process
        except Exception as e:
            logger.error(f"Failed to start OpenVPN server: {e}")
            return None

@click.group()
def cli():
    """Simple VPN server using OpenVPN"""
    pass

@cli.command()
@click.option('--config-dir', default='./vpn_configs', help='Directory for configuration files')
@click.option('--ip', default=None, help='Public IP address of the server')
@click.option('--port', default=1194, help='Port to listen on')
@click.option('--protocol', default='udp', type=click.Choice(['udp', 'tcp']), help='Protocol to use')
def setup(config_dir, ip, port, protocol):
    """Setup the OpenVPN server"""
    server = OpenVPNServer(config_dir=config_dir, server_ip=ip, port=port, protocol=protocol)
    server.setup_pki()
    server.create_server_config()
    click.echo("OpenVPN server setup completed. You can now start the server.")

@cli.command()
@click.option('--config-dir', default='./vpn_configs', help='Directory for configuration files')
@click.option('--ip', default=None, help='Public IP address of the server')
@click.option('--port', default=1194, help='Port to listen on')
@click.option('--protocol', default='udp', type=click.Choice(['udp', 'tcp']), help='Protocol to use')
def start(config_dir, ip, port, protocol):
    """Start the OpenVPN server"""
    server = OpenVPNServer(config_dir=config_dir, server_ip=ip, port=port, protocol=protocol)
    process = server.start()
    if process:
        click.echo("OpenVPN server started. Press Ctrl+C to stop.")
        try:
            # Keep the process running until interrupted
            process.wait()
        except KeyboardInterrupt:
            process.terminate()
            click.echo("OpenVPN server stopped.")

@cli.command()
@click.option('--config-dir', default='./vpn_configs', help='Directory for configuration files')
@click.option('--ip', default=None, help='Public IP address of the server')
@click.option('--port', default=1194, help='Port to listen on')
@click.option('--protocol', default='udp', type=click.Choice(['udp', 'tcp']), help='Protocol to use')
@click.argument('client_name')
def add_client(config_dir, ip, port, protocol, client_name):
    """Generate a client configuration"""
    server = OpenVPNServer(config_dir=config_dir, server_ip=ip, port=port, protocol=protocol)
    client_config = server.generate_client_config(client_name)
    if client_config:
        click.echo(f"Client configuration created: {client_config}")

if __name__ == "__main__":
    cli()
