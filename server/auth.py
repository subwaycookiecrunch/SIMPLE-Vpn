#!/usr/bin/env python3
import os
import subprocess
import logging
import hashlib
import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('vpn_auth')

class VPNAuth:
    def __init__(self, users_db_path='./vpn_configs/users.json'):
        """
        Initialize VPN authentication system
        
        Args:
            users_db_path: Path to the users database file
        """
        self.users_db_path = Path(users_db_path)
        self.users_db_dir = self.users_db_path.parent
        
        # Create users database directory if it doesn't exist
        self.users_db_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize or load users database
        if not self.users_db_path.exists():
            # Create an empty database
            self._save_users({})
            logger.info(f"Created new users database at {self.users_db_path}")
        else:
            logger.info(f"Using existing users database at {self.users_db_path}")
    
    def _load_users(self):
        """Load users from the database file"""
        try:
            with open(self.users_db_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load users database: {e}")
            return {}
    
    def _save_users(self, users):
        """Save users to the database file"""
        try:
            with open(self.users_db_path, 'w') as f:
                json.dump(users, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to save users database: {e}")
            return False
    
    def _hash_password(self, password, salt=None):
        """
        Hash a password using PBKDF2
        
        Args:
            password: Password to hash
            salt: Salt to use (or None to generate a new one)
            
        Returns:
            Tuple of (salt, hash) as base64 strings
        """
        if salt is None:
            salt = os.urandom(16)
        elif isinstance(salt, str):
            salt = base64.b64decode(salt)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        password_hash = kdf.derive(password.encode('utf-8'))
        
        return (
            base64.b64encode(salt).decode('utf-8'),
            base64.b64encode(password_hash).decode('utf-8')
        )
    
    def _verify_password(self, password, salt, stored_hash):
        """
        Verify a password against a stored hash
        
        Args:
            password: Password to verify
            salt: Salt as base64 string
            stored_hash: Stored hash as base64 string
            
        Returns:
            True if password matches, False otherwise
        """
        _, computed_hash = self._hash_password(password, salt)
        return computed_hash == stored_hash
    
    def add_user(self, username, password, is_admin=False):
        """
        Add a new user
        
        Args:
            username: Username
            password: Password
            is_admin: Whether the user has admin privileges
            
        Returns:
            True if user was added successfully, False otherwise
        """
        users = self._load_users()
        
        if username in users:
            logger.error(f"User '{username}' already exists")
            return False
        
        # Hash the password
        salt, password_hash = self._hash_password(password)
        
        # Add the user
        users[username] = {
            'salt': salt,
            'hash': password_hash,
            'is_admin': is_admin,
            'enabled': True,
            'created_at': int(os.path.getmtime(self.users_db_path)) if self.users_db_path.exists() else 0
        }
        
        # Save the changes
        if not self._save_users(users):
            return False
        
        logger.info(f"Added user '{username}'")
        return True
    
    def delete_user(self, username):
        """
        Delete a user
        
        Args:
            username: Username to delete
            
        Returns:
            True if user was deleted successfully, False otherwise
        """
        users = self._load_users()
        
        if username not in users:
            logger.error(f"User '{username}' does not exist")
            return False
        
        # Delete the user
        del users[username]
        
        # Save the changes
        if not self._save_users(users):
            return False
        
        logger.info(f"Deleted user '{username}'")
        return True
    
    def update_password(self, username, new_password):
        """
        Update a user's password
        
        Args:
            username: Username
            new_password: New password
            
        Returns:
            True if password was updated successfully, False otherwise
        """
        users = self._load_users()
        
        if username not in users:
            logger.error(f"User '{username}' does not exist")
            return False
        
        # Hash the new password
        salt, password_hash = self._hash_password(new_password)
        
        # Update the user
        users[username]['salt'] = salt
        users[username]['hash'] = password_hash
        
        # Save the changes
        if not self._save_users(users):
            return False
        
        logger.info(f"Updated password for user '{username}'")
        return True
    
    def disable_user(self, username):
        """
        Disable a user
        
        Args:
            username: Username to disable
            
        Returns:
            True if user was disabled successfully, False otherwise
        """
        users = self._load_users()
        
        if username not in users:
            logger.error(f"User '{username}' does not exist")
            return False
        
        # Disable the user
        users[username]['enabled'] = False
        
        # Save the changes
        if not self._save_users(users):
            return False
        
        logger.info(f"Disabled user '{username}'")
        return True
    
    def enable_user(self, username):
        """
        Enable a user
        
        Args:
            username: Username to enable
            
        Returns:
            True if user was enabled successfully, False otherwise
        """
        users = self._load_users()
        
        if username not in users:
            logger.error(f"User '{username}' does not exist")
            return False
        
        # Enable the user
        users[username]['enabled'] = True
        
        # Save the changes
        if not self._save_users(users):
            return False
        
        logger.info(f"Enabled user '{username}'")
        return True
    
    def authenticate(self, username, password):
        """
        Authenticate a user
        
        Args:
            username: Username
            password: Password
            
        Returns:
            User info dictionary if authentication succeeded, None otherwise
        """
        users = self._load_users()
        
        if username not in users:
            logger.warning(f"Authentication failed: User '{username}' does not exist")
            return None
        
        user = users[username]
        
        # Check if user is enabled
        if not user.get('enabled', True):
            logger.warning(f"Authentication failed: User '{username}' is disabled")
            return None
        
        # Verify password
        if not self._verify_password(password, user['salt'], user['hash']):
            logger.warning(f"Authentication failed: Invalid password for user '{username}'")
            return None
        
        logger.info(f"Authentication succeeded for user '{username}'")
        return user
    
    def list_users(self):
        """
        List all users
        
        Returns:
            Dictionary of all users (without password hashes)
        """
        users = self._load_users()
        
        # Remove sensitive information
        return {username: {k: v for k, v in user.items() if k != 'hash' and k != 'salt'}
                for username, user in users.items()}

def create_auth_script(auth_script_path='./vpn_configs/auth.py', users_db_path='./vpn_configs/users.json'):
    """
    Create an authentication script for OpenVPN to use
    
    Args:
        auth_script_path: Path to write the auth script to
        users_db_path: Path to the users database
        
    Returns:
        True if script was created successfully, False otherwise
    """
    try:
        script_content = f"""#!/usr/bin/env python3
import sys
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def hash_password(password, salt):
    salt = base64.b64decode(salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    password_hash = kdf.derive(password.encode('utf-8'))
    return base64.b64encode(password_hash).decode('utf-8')

def main():
    if len(sys.argv) != 2:
        sys.exit(1)
        
    username = sys.argv[1]
    password = sys.stdin.readline().strip()
    
    try:
        with open('{users_db_path}', 'r') as f:
            users = json.load(f)
    except:
        sys.exit(1)
    
    if username not in users:
        sys.exit(1)
    
    user = users[username]
    
    if not user.get('enabled', True):
        sys.exit(1)
    
    computed_hash = hash_password(password, user['salt'])
    
    if computed_hash == user['hash']:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
"""
        
        # Write the script
        with open(auth_script_path, 'w') as f:
            f.write(script_content)
        
        # Make it executable
        os.chmod(auth_script_path, 0o755)
        
        logger.info(f"Created auth script at {auth_script_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to create auth script: {e}")
        return False

if __name__ == "__main__":
    # Example usage
    auth = VPNAuth()
    auth.add_user("admin", "password", is_admin=True)
    print("Users:", auth.list_users())
    
    # Create auth script
    create_auth_script()
