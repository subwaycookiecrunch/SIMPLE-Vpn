#!/usr/bin/env python3
import os
import re
import json
import time
import logging
import subprocess
from pathlib import Path
from datetime import datetime
import threading
import socket
import psutil
import csv
from collections import defaultdict

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('vpn_monitoring')

class VPNMonitor:
    def __init__(self, status_file='./vpn_configs/openvpn-status.log', 
                 config_dir='./vpn_configs',
                 log_file='./vpn_configs/openvpn.log'):
        """
        Initialize VPN monitoring
        
        Args:
            status_file: Path to the OpenVPN status file
            config_dir: Directory containing OpenVPN configuration
            log_file: Path to the OpenVPN log file
        """
        self.status_file = Path(status_file)
        self.config_dir = Path(config_dir)
        self.log_file = Path(log_file)
        self.stats_history = defaultdict(list)
        self.stats_file = self.config_dir / 'stats_history.json'
        
        # Load stats history if it exists
        if self.stats_file.exists():
            try:
                with open(self.stats_file, 'r') as f:
                    self.stats_history = defaultdict(list, json.load(f))
            except Exception as e:
                logger.error(f"Failed to load stats history: {e}")
    
    def get_current_connections(self):
        """
        Get current VPN connections from the status file
        
        Returns:
            List of dictionaries with connection information
        """
        if not self.status_file.exists():
            logger.warning(f"Status file not found at {self.status_file}")
            return []
        
        try:
            connections = []
            current_section = None
            
            with open(self.status_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Check for section headers
                    if line.startswith('TITLE') or line.startswith('TIME'):
                        continue
                    elif line.startswith('ROUTING TABLE'):
                        current_section = 'routing'
                        continue
                    elif line.startswith('GLOBAL STATS'):
                        current_section = 'global'
                        continue
                    elif line.startswith('CLIENT LIST'):
                        current_section = 'clients'
                        continue
                    
                    # Parse client connections
                    if current_section == 'clients':
                        parts = line.split(',')
                        if len(parts) >= 5:
                            # Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
                            connection = {
                                'common_name': parts[0],
                                'real_address': parts[1].split(':')[0],  # IP without port
                                'port': int(parts[1].split(':')[1]) if ':' in parts[1] else 0,
                                'bytes_received': int(parts[2]),
                                'bytes_sent': int(parts[3]),
                                'connected_since': parts[4],
                                'connected_since_timestamp': self._parse_time(parts[4])
                            }
                            
                            # Calculate connection duration
                            if connection['connected_since_timestamp']:
                                connection['duration_seconds'] = int(time.time() - connection['connected_since_timestamp'])
                                connection['duration_str'] = self._format_duration(connection['duration_seconds'])
                            
                            connections.append(connection)
            
            return connections
        except Exception as e:
            logger.error(f"Failed to parse status file: {e}")
            return []
    
    def _parse_time(self, time_str):
        """Parse OpenVPN time string to timestamp"""
        try:
            # Example format: "Mon Apr 12 15:24:32 2021"
            timestamp = datetime.strptime(time_str, "%a %b %d %H:%M:%S %Y").timestamp()
            return timestamp
        except Exception:
            return None
    
    def _format_duration(self, seconds):
        """Format duration in seconds to a human-readable string"""
        days, remainder = divmod(seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m {seconds}s"
        elif hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    
    def get_server_status(self):
        """
        Get the status of the OpenVPN server process
        
        Returns:
            Dictionary with server status information
        """
        server_status = {
            'running': False,
            'pid': None,
            'uptime': None,
            'uptime_str': None,
            'cpu_percent': None,
            'memory_percent': None,
            'connections_count': 0,
            'bytes_sent': 0,
            'bytes_received': 0
        }
        
        # Check if OpenVPN process is running
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
            try:
                if 'openvpn' in proc.info['name'].lower() or any('openvpn' in cmd.lower() for cmd in proc.info['cmdline'] if cmd):
                    server_status['running'] = True
                    server_status['pid'] = proc.info['pid']
                    
                    # Get process details
                    process = psutil.Process(proc.info['pid'])
                    server_status['cpu_percent'] = process.cpu_percent(interval=0.1)
                    server_status['memory_percent'] = process.memory_percent()
                    
                    # Calculate uptime
                    uptime_seconds = time.time() - proc.info['create_time']
                    server_status['uptime'] = uptime_seconds
                    server_status['uptime_str'] = self._format_duration(uptime_seconds)
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        # Get connection statistics
        connections = self.get_current_connections()
        server_status['connections_count'] = len(connections)
        
        # Sum up bytes sent/received
        for conn in connections:
            server_status['bytes_sent'] += conn['bytes_sent']
            server_status['bytes_received'] += conn['bytes_received']
        
        # Format byte counts
        server_status['bytes_sent_str'] = self._format_bytes(server_status['bytes_sent'])
        server_status['bytes_received_str'] = self._format_bytes(server_status['bytes_received'])
        
        return server_status
    
    def _format_bytes(self, bytes_count):
        """Format bytes to a human-readable string"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024:
                return f"{bytes_count:.2f} {unit}"
            bytes_count /= 1024
        return f"{bytes_count:.2f} PB"
    
    def parse_logs(self, n_lines=100):
        """
        Parse OpenVPN log file
        
        Args:
            n_lines: Number of lines to read from the end of the log
            
        Returns:
            List of dictionaries with log entries
        """
        if not self.log_file.exists():
            logger.warning(f"Log file not found at {self.log_file}")
            return []
        
        try:
            log_entries = []
            
            with open(self.log_file, 'r') as f:
                # Read last n lines
                lines = f.readlines()
                for line in lines[-n_lines:]:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Parse log entry
                    entry = {'raw': line}
                    
                    # Try to extract timestamp
                    timestamp_match = re.search(r'(\w{3} \w{3} \d{1,2} \d{2}:\d{2}:\d{2} \d{4})', line)
                    if timestamp_match:
                        try:
                            entry['timestamp'] = datetime.strptime(
                                timestamp_match.group(1), "%a %b %d %H:%M:%S %Y"
                            ).timestamp()
                            entry['time'] = timestamp_match.group(1)
                        except:
                            pass
                    
                    # Categorize log entry
                    if 'connect' in line.lower() or 'connection' in line.lower():
                        entry['type'] = 'connection'
                    elif 'auth' in line.lower():
                        entry['type'] = 'auth'
                    elif 'error' in line.lower() or 'fatal' in line.lower():
                        entry['type'] = 'error'
                    elif 'warning' in line.lower() or 'warn' in line.lower():
                        entry['type'] = 'warning'
                    elif 'route' in line.lower() or 'routing' in line.lower():
                        entry['type'] = 'routing'
                    elif 'init' in line.lower() or 'initialization' in line.lower():
                        entry['type'] = 'init'
                    else:
                        entry['type'] = 'info'
                    
                    log_entries.append(entry)
            
            return log_entries
        except Exception as e:
            logger.error(f"Failed to parse log file: {e}")
            return []
    
    def collect_stats(self):
        """
        Collect current VPN statistics and add to history
        
        Returns:
            Dictionary with current stats
        """
        timestamp = int(time.time())
        
        # Get server status
        server_status = self.get_server_status()
        
        # Collect stats
        stats = {
            'timestamp': timestamp,
            'datetime': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
            'server': server_status,
            'connections': self.get_current_connections()
        }
        
        # Add to history
        self.stats_history['server'].append({
            'timestamp': timestamp,
            'connections': len(stats['connections']),
            'bytes_sent': server_status['bytes_sent'],
            'bytes_received': server_status['bytes_received'],
            'running': server_status['running']
        })
        
        # Limit history size (keep last 1000 entries)
        if len(self.stats_history['server']) > 1000:
            self.stats_history['server'] = self.stats_history['server'][-1000:]
        
        # Save stats history
        try:
            with open(self.stats_file, 'w') as f:
                json.dump(self.stats_history, f)
        except Exception as e:
            logger.error(f"Failed to save stats history: {e}")
        
        return stats
    
    def start_monitoring(self, interval=60):
        """
        Start background monitoring thread
        
        Args:
            interval: Collection interval in seconds
            
        Returns:
            Monitoring thread
        """
        def monitor_loop():
            logger.info(f"Starting VPN monitoring (interval: {interval}s)")
            while True:
                try:
                    self.collect_stats()
                except Exception as e:
                    logger.error(f"Error in monitoring loop: {e}")
                time.sleep(interval)
        
        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()
        return thread
    
    def export_stats_csv(self, output_file='./vpn_configs/stats.csv'):
        """
        Export stats history to CSV
        
        Args:
            output_file: Path to the output CSV file
            
        Returns:
            Path to the exported file
        """
        try:
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    'Timestamp', 'DateTime', 'Connections', 
                    'Bytes Sent', 'Bytes Received', 'Server Running'
                ])
                
                # Write data
                for entry in self.stats_history['server']:
                    writer.writerow([
                        entry['timestamp'],
                        datetime.fromtimestamp(entry['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
                        entry['connections'],
                        entry['bytes_sent'],
                        entry['bytes_received'],
                        entry['running']
                    ])
            
            logger.info(f"Exported stats to {output_file}")
            return output_file
        except Exception as e:
            logger.error(f"Failed to export stats: {e}")
            return None

def start_background_monitoring(interval=60, status_file='./vpn_configs/openvpn-status.log'):
    """Helper function to start background monitoring"""
    monitor = VPNMonitor(status_file=status_file)
    thread = monitor.start_monitoring(interval=interval)
    return monitor, thread

if __name__ == "__main__":
    # Example usage
    monitor = VPNMonitor()
    
    # Print current connections
    connections = monitor.get_current_connections()
    print(f"Current connections: {len(connections)}")
    for conn in connections:
        print(f"  - {conn['common_name']} from {conn['real_address']} ({conn['duration_str']})")
    
    # Print server status
    status = monitor.get_server_status()
    print(f"Server running: {status['running']}")
    if status['running']:
        print(f"  - PID: {status['pid']}")
        print(f"  - Uptime: {status['uptime_str']}")
        print(f"  - Connections: {status['connections_count']}")
        print(f"  - Traffic: {status['bytes_received_str']} received, {status['bytes_sent_str']} sent")
    
    # Start background monitoring
    thread = monitor.start_monitoring(interval=60)
    
    # Keep script running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Monitoring stopped")
