#!/usr/bin/env python3
import sys
import os
import logging
from pathlib import Path
from .interface import cli

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(Path.home() / '.simple_vpn' / 'client.log')
        ]
    )
    
    # Create log directory if it doesn't exist
    log_dir = Path.home() / '.simple_vpn'
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Run the CLI
    cli(obj={})
