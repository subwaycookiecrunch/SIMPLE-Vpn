#!/usr/bin/env python3
import os
import sys
import click
import logging
import time
from pathlib import Path
from .connection import VPNConnection

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('vpn_client_interface')

def print_status(connection):
    """Print the current connection status"""
    status = connection.get_connection_status()
    
    click.echo(f"Connection status: {'Connected' if status['connected'] else 'Disconnected'}")
    
    if status['connected']:
        click.echo(f"  Config file: {status['config_file']}")
        if 'vpn_ip' in status:
            click.echo(f"  VPN IP: {status['vpn_ip']}")
        click.echo(f"  Initialized: {status.get('initialized', False)}")
    
    return status

@click.group()
@click.option('--config-dir', default='./vpn_client_configs', help='Directory for client configurations')
@click.pass_context
def cli(ctx, config_dir):
    """Simple VPN client using OpenVPN"""
    # Create a VPNConnection object for all commands to use
    ctx.ensure_object(dict)
    ctx.obj['connection'] = VPNConnection(config_dir=config_dir)

@cli.command()
@click.argument('config_file')
@click.option('--name', help='Name to save the configuration as')
@click.pass_context
def import_config(ctx, config_file, name):
    """Import an OpenVPN configuration file"""
    connection = ctx.obj['connection']
    
    result = connection.import_config(config_file, name=name)
    if result:
        click.echo(f"Configuration imported: {result}")
    else:
        click.echo(f"Failed to import configuration")
        sys.exit(1)

@cli.command()
@click.pass_context
def list_configs(ctx):
    """List available configuration files"""
    connection = ctx.obj['connection']
    
    configs = connection.list_configs()
    if not configs:
        click.echo("No configuration files found")
    else:
        click.echo("Available configurations:")
        for i, config in enumerate(configs, 1):
            click.echo(f"{i}. {config}")

@cli.command()
@click.argument('config_file')
@click.option('--username', help='Username for authentication')
@click.option('--password', help='Password for authentication')
@click.pass_context
def connect(ctx, config_file, username, password):
    """Connect to the VPN"""
    connection = ctx.obj['connection']
    
    # Set the active configuration file
    if not connection.set_active_config(config_file):
        click.echo(f"Failed to use configuration file: {config_file}")
        sys.exit(1)
    
    # Set up authentication if provided
    auth = None
    if username and password:
        auth = (username, password)
    elif username:
        # Prompt for password if only username is provided
        password = click.prompt("Password", hide_input=True)
        auth = (username, password)
    
    # Connect to the VPN
    click.echo("Connecting to VPN...")
    result = connection.connect(auth=auth)
    
    if result:
        status = print_status(connection)
        if status['connected']:
            click.echo("Successfully connected to VPN")
            
            # Monitor the connection in foreground mode
            click.echo("Press Ctrl+C to disconnect")
            try:
                while connection.is_connected():
                    time.sleep(1)
            except KeyboardInterrupt:
                click.echo("\nDisconnecting...")
                connection.disconnect()
                click.echo("Disconnected from VPN")
        else:
            click.echo("Failed to connect to VPN")
            click.echo("Check logs for details:")
            click.echo(connection.get_log_tail())
            sys.exit(1)
    else:
        click.echo("Failed to connect to VPN")
        sys.exit(1)

@cli.command()
@click.pass_context
def status(ctx):
    """Check VPN connection status"""
    connection = ctx.obj['connection']
    print_status(connection)

@cli.command()
@click.pass_context
def disconnect(ctx):
    """Disconnect from the VPN"""
    connection = ctx.obj['connection']
    
    if connection.is_connected():
        click.echo("Disconnecting from VPN...")
        if connection.disconnect():
            click.echo("Successfully disconnected from VPN")
        else:
            click.echo("Failed to disconnect from VPN")
            sys.exit(1)
    else:
        click.echo("Not connected to VPN")

@cli.command()
@click.option('--lines', default=20, help='Number of lines to show')
@click.pass_context
def logs(ctx, lines):
    """Show VPN connection logs"""
    connection = ctx.obj['connection']
    log_content = connection.get_log_tail(lines=lines)
    click.echo(log_content)

@cli.command()
@click.argument('config_file')
@click.option('--daemon', is_flag=True, help='Run in background mode')
@click.option('--username', help='Username for authentication')
@click.option('--password', help='Password for authentication')
@click.pass_context
def quick_connect(ctx, config_file, daemon, username, password):
    """Quickly connect to a VPN with minimal output"""
    connection = ctx.obj['connection']
    
    # Set up authentication if provided
    auth = None
    if username and password:
        auth = (username, password)
    elif username:
        # Prompt for password if only username is provided
        password = click.prompt("Password", hide_input=True)
        auth = (username, password)
    
    # Check if configuration file exists, import if it doesn't
    config_path = Path(config_file)
    
    if not config_path.exists():
        # Try to find it in config directory
        config_dir_path = Path(connection.config_dir) / config_path.name
        if config_dir_path.exists():
            config_path = config_dir_path
        else:
            click.echo(f"Configuration file not found: {config_file}")
            sys.exit(1)
    
    # Set the active configuration
    if not config_path.name.endswith('.ovpn'):
        # Try to find a matching .ovpn file
        for config in connection.list_configs():
            if config_path.name in config.name:
                config_path = config
                break
    
    connection.set_active_config(config_path)
    
    # Connect to the VPN
    click.echo(f"Connecting to {config_path}...")
    result = connection.connect(auth=auth)
    
    if result:
        if daemon:
            # Just check if connection started properly and return
            if connection.is_connected():
                click.echo("Connected to VPN in background mode")
            else:
                click.echo("Failed to connect to VPN")
                sys.exit(1)
        else:
            # Monitor the connection in foreground mode
            try:
                while connection.is_connected():
                    time.sleep(1)
                click.echo("VPN connection terminated")
            except KeyboardInterrupt:
                click.echo("\nDisconnecting...")
                connection.disconnect()
                click.echo("Disconnected from VPN")
    else:
        click.echo("Failed to connect to VPN")
        sys.exit(1)

if __name__ == '__main__':
    cli(obj={})
