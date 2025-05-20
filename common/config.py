#!/usr/bin/env python3
import os
import json
import logging
from pathlib import Path
import platform
from .utils import get_config_dir

logger = logging.getLogger('vpn_config')

# Default configuration
DEFAULT_CONFIG = {
    'server': {
        'port': 1194,
        'protocol': 'udp',
        'subnet': '10.8.0.0',
        'subnet_mask': '255.255.255.0',
        'dns': ['8.8.8.8', '8.8.4.4'],
        'max_clients': 100,
        'config_dir': './vpn_configs',
        'log_verbosity': 3,
        'cipher': 'AES-256-CBC',
        'auth': 'SHA256',
        'compression': True,
        'monitoring': {
            'enabled': True,
            'interval': 60
        }
    },
    'client': {
        'config_dir': './vpn_client_configs',
        'auto_reconnect': True,
        'log_verbosity': 2,
        'dns_fallback': True
    }
}

class Config:
    def __init__(self, config_file=None, role='client'):
        """
        Initialize configuration
        
        Args:
            config_file: Path to configuration file (or None to use default)
            role: 'client' or 'server'
        """
        self.role = role
        
        # Determine config file path
        if config_file:
            self.config_file = Path(config_file)
        else:
            config_dir = get_config_dir()
            self.config_file = config_dir / f'simple_vpn_{role}.json'
        
        # Create config directory if it doesn't exist
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Load or create configuration
        self.config = self._load_config()
    
    def _load_config(self):
        """Load configuration from file or create default"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    logger.info(f"Loaded configuration from {self.config_file}")
                    return self._merge_with_defaults(config)
            except Exception as e:
                logger.error(f"Failed to load configuration: {e}")
                logger.info(f"Using default configuration")
                return DEFAULT_CONFIG.copy()
        else:
            logger.info(f"Configuration file not found, using defaults")
            # Save default configuration
            self.save()
            return DEFAULT_CONFIG.copy()
    
    def _merge_with_defaults(self, config):
        """Merge loaded configuration with defaults to ensure all keys exist"""
        merged = DEFAULT_CONFIG.copy()
        
        # Merge server config if it exists
        if 'server' in config and isinstance(config['server'], dict):
            for key, value in config['server'].items():
                merged['server'][key] = value
        
        # Merge client config if it exists
        if 'client' in config and isinstance(config['client'], dict):
            for key, value in config['client'].items():
                merged['client'][key] = value
        
        return merged
    
    def save(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            logger.info(f"Saved configuration to {self.config_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            return False
    
    def get(self, section, key=None, default=None):
        """
        Get a configuration value
        
        Args:
            section: 'server' or 'client'
            key: Key to get (or None to get entire section)
            default: Default value if key doesn't exist
            
        Returns:
            Configuration value or default
        """
        if section not in self.config:
            return default
        
        if key is None:
            return self.config[section]
        
        return self.config[section].get(key, default)
    
    def set(self, section, key, value):
        """
        Set a configuration value
        
        Args:
            section: 'server' or 'client'
            key: Key to set
            value: Value to set
            
        Returns:
            True if successful, False otherwise
        """
        if section not in self.config:
            self.config[section] = {}
        
        self.config[section][key] = value
        return self.save()
    
    def reset(self, section=None):
        """
        Reset configuration to defaults
        
        Args:
            section: Section to reset (or None to reset everything)
            
        Returns:
            True if successful, False otherwise
        """
        if section is None:
            self.config = DEFAULT_CONFIG.copy()
        elif section in self.config:
            self.config[section] = DEFAULT_CONFIG[section].copy()
        
        return self.save()
    
    def get_config_dir(self, role=None):
        """
        Get the configuration directory
        
        Args:
            role: 'client', 'server', or None to use the current role
            
        Returns:
            Path object for the configuration directory
        """
        role = role or self.role
        config_dir = self.get(role, 'config_dir')
        
        # If it's a relative path, make it absolute from the user's config dir
        if not os.path.isabs(config_dir):
            base_dir = get_config_dir()
            config_dir = base_dir / config_dir
        
        return Path(config_dir)

def load_config(role='client', config_file=None):
    """
    Helper function to load configuration
    
    Args:
        role: 'client' or 'server'
        config_file: Path to configuration file (or None to use default)
        
    Returns:
        Config object
    """
    return Config(config_file=config_file, role=role)

if __name__ == "__main__":
    # Simple test of configuration
    logging.basicConfig(level=logging.INFO)
    
    # Load client config
    client_config = load_config('client')
    print(f"Client config: {client_config.get('client')}")
    
    # Load server config
    server_config = load_config('server')
    print(f"Server config: {server_config.get('server')}")
    
    # Set and get a value
    client_config.set('client', 'test_key', 'test_value')
    print(f"Test value: {client_config.get('client', 'test_key')}")
    
    # Reset to defaults
    client_config.reset()
