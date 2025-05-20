#!/usr/bin/env python3
import os
import subprocess
import logging
import platform
import ipaddress
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('vpn_networking')

class VPNNetworking:
    def __init__(self, subnet='10.8.0.0/24', interface='tun0'):
        """
        Initialize VPN networking configuration
        
        Args:
            subnet: VPN subnet in CIDR notation
            interface: VPN interface name
        """
        self.subnet = subnet
        self.interface = interface
        self.system = platform.system().lower()
    
    def setup_routing(self):
        """Configure IP routing for VPN traffic"""
        logger.info(f"Setting up IP routing for subnet {self.subnet}")
        
        try:
            if self.system == 'linux':
                self._setup_linux_routing()
            elif self.system == 'darwin':  # macOS
                self._setup_macos_routing()
            elif self.system == 'windows':
                self._setup_windows_routing()
            else:
                logger.error(f"Unsupported operating system: {self.system}")
                return False
            
            logger.info("IP routing setup completed successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to setup IP routing: {e}")
            return False
    
    def _setup_linux_routing(self):
        """Configure IP routing on Linux"""
        # Enable IP forwarding
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')
            
        # Configure iptables for NAT
        subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', 
                      self.subnet, '-o', 'eth0', '-j', 'MASQUERADE'], check=True)
        
        # Allow forwarding between interfaces
        subprocess.run(['iptables', '-A', 'FORWARD', '-i', self.interface, '-o', 'eth0', 
                      '-j', 'ACCEPT'], check=True)
        subprocess.run(['iptables', '-A', 'FORWARD', '-i', 'eth0', '-o', self.interface, 
                      '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], check=True)
                      
        # Save iptables rules (depends on distribution)
        try:
            # Debian/Ubuntu
            subprocess.run(['iptables-save', '>', '/etc/iptables/rules.v4'], shell=True, check=True)
        except:
            try:
                # RHEL/CentOS
                subprocess.run(['service', 'iptables', 'save'], check=True)
            except:
                logger.warning("Could not save iptables rules permanently.")
                logger.warning("Rules will be lost on reboot.")
    
    def _setup_macos_routing(self):
        """Configure IP routing on macOS"""
        # Enable IP forwarding
        subprocess.run(['sysctl', '-w', 'net.inet.ip.forwarding=1'], check=True)
        
        # Configure PF for NAT (this is simplified, may need adjustment)
        pf_conf = "/etc/pf.conf"
        
        # Backup original pf.conf
        if os.path.exists(pf_conf):
            subprocess.run(['cp', pf_conf, f"{pf_conf}.bak"], check=True)
            
        # Add NAT rules
        nat_rule = f"nat on en0 from {self.subnet} to any -> (en0)"
        
        with open('/tmp/pf.conf.addon', 'w') as f:
            f.write(nat_rule + '\n')
            
        subprocess.run(['cat', '/tmp/pf.conf.addon', '>>', pf_conf], shell=True, check=True)
        
        # Reload PF
        subprocess.run(['pfctl', '-f', pf_conf], check=True)
        subprocess.run(['pfctl', '-e'], check=True)  # Enable PF if not enabled
    
    def _setup_windows_routing(self):
        """Configure IP routing on Windows"""
        # Enable IP forwarding
        subprocess.run(['netsh', 'interface', 'ipv4', 'set', 'interface', 
                      self.interface, 'forwarding=enabled'], check=True)
        
        # Get the index of the Internet-facing interface
        result = subprocess.run(['netsh', 'interface', 'ipv4', 'show', 'interfaces'], 
                             stdout=subprocess.PIPE, text=True, check=True)
        
        # Parse the output to find the index of the interface with Internet access
        # This is simplified and may need adjustment
        lines = result.stdout.split('\n')
        internet_idx = None
        for line in lines:
            if 'Connected' in line and not self.interface in line:
                parts = line.split()
                if len(parts) > 0:
                    try:
                        internet_idx = int(parts[0])
                        break
                    except:
                        pass
        
        if not internet_idx:
            raise Exception("Could not find Internet-facing interface")
            
        # Enable NAT
        subnet_obj = ipaddress.IPv4Network(self.subnet)
        subprocess.run(['netsh', 'routing', 'ip', 'nat', 'add', 'interface', 
                      str(internet_idx), 'full'], check=True)
                      
        logger.info(f"Configured NAT on interface index {internet_idx}")
    
    def configure_firewall(self, port=1194, protocol='udp'):
        """Configure firewall to allow VPN traffic"""
        logger.info(f"Configuring firewall for VPN on port {port}/{protocol}")
        
        try:
            if self.system == 'linux':
                self._configure_linux_firewall(port, protocol)
            elif self.system == 'darwin':  # macOS
                self._configure_macos_firewall(port, protocol)
            elif self.system == 'windows':
                self._configure_windows_firewall(port, protocol)
            else:
                logger.error(f"Unsupported operating system: {self.system}")
                return False
                
            logger.info("Firewall configuration completed successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to configure firewall: {e}")
            return False
    
    def _configure_linux_firewall(self, port, protocol):
        """Configure firewall on Linux"""
        # Allow VPN traffic
        subprocess.run(['iptables', '-A', 'INPUT', '-i', 'eth0', '-p', protocol, 
                      '--dport', str(port), '-j', 'ACCEPT'], check=True)
        
        # Allow traffic on the VPN interface
        subprocess.run(['iptables', '-A', 'INPUT', '-i', self.interface, '-j', 'ACCEPT'], check=True)
        subprocess.run(['iptables', '-A', 'OUTPUT', '-o', self.interface, '-j', 'ACCEPT'], check=True)
    
    def _configure_macos_firewall(self, port, protocol):
        """Configure firewall on macOS"""
        # Add rules to PF
        rules = [
            f"pass in on en0 proto {protocol} from any to any port {port}",
            f"pass in on {self.interface} all",
            f"pass out on {self.interface} all"
        ]
        
        with open('/tmp/pf.conf.addon', 'w') as f:
            for rule in rules:
                f.write(rule + '\n')
                
        pf_conf = "/etc/pf.conf"
        subprocess.run(['cat', '/tmp/pf.conf.addon', '>>', pf_conf], shell=True, check=True)
        
        # Reload PF
        subprocess.run(['pfctl', '-f', pf_conf], check=True)
    
    def _configure_windows_firewall(self, port, protocol):
        """Configure firewall on Windows"""
        # Allow OpenVPN traffic
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 
                      'name=OpenVPN', 'dir=in', 'action=allow', 
                      f'protocol={protocol}', f'localport={port}'], check=True)
        
        # Allow traffic on VPN interface
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 
                      'name=OpenVPN-TUN', 'dir=in', 'action=allow', 
                      f'interface={self.interface}'], check=True)

def setup_vpn_networking(subnet='10.8.0.0/24', interface='tun0', port=1194, protocol='udp'):
    """Helper function to set up all VPN networking components"""
    logging.info("Setting up VPN networking components...")
    
    networking = VPNNetworking(subnet=subnet, interface=interface)
    
    # Configure routing
    if not networking.setup_routing():
        return False
        
    # Configure firewall
    if not networking.configure_firewall(port=port, protocol=protocol):
        return False
        
    logging.info("VPN networking setup completed")
    return True
