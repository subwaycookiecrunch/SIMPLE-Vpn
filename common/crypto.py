#!/usr/bin/env python3
import os
import logging
import base64
import tempfile
import subprocess
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
import datetime

logger = logging.getLogger('vpn_crypto')

class CryptoUtils:
    @staticmethod
    def generate_private_key(key_size=2048):
        """
        Generate a new RSA private key
        
        Args:
            key_size: Key size in bits
            
        Returns:
            RSA private key
        """
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
    
    @staticmethod
    def generate_self_signed_cert(private_key, common_name, valid_days=365):
        """
        Generate a self-signed certificate
        
        Args:
            private_key: RSA private key
            common_name: Common name for the certificate
            valid_days: Validity period in days
            
        Returns:
            X.509 certificate
        """
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Simple VPN"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        return x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=valid_days)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(private_key, hashes.SHA256(), default_backend())
    
    @staticmethod
    def save_private_key(private_key, path, password=None):
        """
        Save a private key to a file
        
        Args:
            private_key: RSA private key
            path: Path to save key to
            password: Optional password to encrypt the key
            
        Returns:
            Path to the saved file
        """
        path = Path(path)
        
        encryption = None
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode('utf-8'))
        
        with open(path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption or serialization.NoEncryption()
            ))
        
        return path
    
    @staticmethod
    def save_certificate(certificate, path):
        """
        Save a certificate to a file
        
        Args:
            certificate: X.509 certificate
            path: Path to save certificate to
            
        Returns:
            Path to the saved file
        """
        path = Path(path)
        
        with open(path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        
        return path
    
    @staticmethod
    def load_private_key(path, password=None):
        """
        Load a private key from a file
        
        Args:
            path: Path to the private key file
            password: Optional password to decrypt the key
            
        Returns:
            RSA private key
        """
        path = Path(path)
        
        with open(path, "rb") as f:
            key_data = f.read()
        
        return load_pem_private_key(
            key_data,
            password=password.encode('utf-8') if password else None,
            backend=default_backend()
        )
    
    @staticmethod
    def load_certificate(path):
        """
        Load a certificate from a file
        
        Args:
            path: Path to the certificate file
            
        Returns:
            X.509 certificate
        """
        path = Path(path)
        
        with open(path, "rb") as f:
            cert_data = f.read()
        
        return x509.load_pem_x509_certificate(cert_data, default_backend())
    
    @staticmethod
    def generate_dh_params(path, size=2048):
        """
        Generate Diffie-Hellman parameters
        
        Args:
            path: Path to save parameters to
            size: Key size in bits
            
        Returns:
            Path to the saved file
        """
        path = Path(path)
        
        try:
            # Generate parameters using OpenSSL
            subprocess.run(
                ['openssl', 'dhparam', '-out', str(path), str(size)],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            return path
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to generate DH parameters: {e}")
            return None
    
    @staticmethod
    def generate_tls_auth_key(path):
        """
        Generate a TLS auth key for OpenVPN
        
        Args:
            path: Path to save key to
            
        Returns:
            Path to the saved file
        """
        path = Path(path)
        
        try:
            # Generate key using OpenVPN
            subprocess.run(
                ['openvpn', '--genkey', '--secret', str(path)],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            return path
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to generate TLS auth key: {e}")
            return None
    
    @staticmethod
    def extract_cert_info(cert):
        """
        Extract information from a certificate
        
        Args:
            cert: X.509 certificate
            
        Returns:
            Dictionary with certificate information
        """
        info = {
            'subject': {},
            'issuer': {},
            'valid_from': cert.not_valid_before,
            'valid_until': cert.not_valid_after,
            'serial_number': cert.serial_number,
            'version': cert.version,
            'is_ca': False
        }
        
        # Extract subject
        for attr in cert.subject:
            oid = attr.oid
            if oid == NameOID.COMMON_NAME:
                info['subject']['common_name'] = attr.value
            elif oid == NameOID.ORGANIZATION_NAME:
                info['subject']['organization'] = attr.value
            elif oid == NameOID.COUNTRY_NAME:
                info['subject']['country'] = attr.value
            elif oid == NameOID.STATE_OR_PROVINCE_NAME:
                info['subject']['state'] = attr.value
            elif oid == NameOID.LOCALITY_NAME:
                info['subject']['locality'] = attr.value
        
        # Extract issuer
        for attr in cert.issuer:
            oid = attr.oid
            if oid == NameOID.COMMON_NAME:
                info['issuer']['common_name'] = attr.value
            elif oid == NameOID.ORGANIZATION_NAME:
                info['issuer']['organization'] = attr.value
            elif oid == NameOID.COUNTRY_NAME:
                info['issuer']['country'] = attr.value
            elif oid == NameOID.STATE_OR_PROVINCE_NAME:
                info['issuer']['state'] = attr.value
            elif oid == NameOID.LOCALITY_NAME:
                info['issuer']['locality'] = attr.value
        
        # Check if certificate is a CA
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            )
            info['is_ca'] = basic_constraints.value.ca
        except x509.ExtensionNotFound:
            pass
        
        return info
    
    @staticmethod
    def validate_certificate(cert, ca_cert=None):
        """
        Validate a certificate
        
        Args:
            cert: X.509 certificate to validate
            ca_cert: CA certificate (or None to validate self-signed)
            
        Returns:
            Dictionary with validation results
        """
        now = datetime.datetime.utcnow()
        results = {
            'valid_period': now >= cert.not_valid_before and now <= cert.not_valid_after,
            'expired': now > cert.not_valid_after,
            'not_yet_valid': now < cert.not_valid_before,
            'time_remaining': (cert.not_valid_after - now).total_seconds(),
            'self_signed': False,
            'valid_signature': False
        }
        
        # Check if certificate is self-signed
        results['self_signed'] = cert.issuer == cert.subject
        
        # Validate signature
        try:
            if results['self_signed']:
                # Check self-signed cert
                cert.public_key().verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding=None,
                    algorithm=cert.signature_hash_algorithm
                )
                results['valid_signature'] = True
            elif ca_cert:
                # Check cert against CA
                ca_cert.public_key().verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding=None,
                    algorithm=cert.signature_hash_algorithm
                )
                results['valid_signature'] = True
        except Exception:
            results['valid_signature'] = False
        
        return results

def generate_vpn_certificates(output_dir, ca_name="SimpleVPN CA", server_name="server", client_names=None):
    """
    Generate certificates for OpenVPN
    
    Args:
        output_dir: Directory to save certificates to
        ca_name: Common name for the CA certificate
        server_name: Common name for the server certificate
        client_names: List of client names (or None for no clients)
        
    Returns:
        Dictionary with paths to generated files
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    crypto = CryptoUtils()
    paths = {}
    
    # Generate CA certificate
    logger.info(f"Generating CA certificate: {ca_name}")
    ca_key = crypto.generate_private_key()
    ca_cert = crypto.generate_self_signed_cert(ca_key, ca_name, valid_days=3650)
    
    paths['ca_key'] = crypto.save_private_key(ca_key, output_dir / "ca.key")
    paths['ca_cert'] = crypto.save_certificate(ca_cert, output_dir / "ca.crt")
    
    # Generate server certificate
    logger.info(f"Generating server certificate: {server_name}")
    server_key = crypto.generate_private_key()
    server_cert = crypto.generate_self_signed_cert(server_key, server_name)
    
    paths['server_key'] = crypto.save_private_key(server_key, output_dir / "server.key")
    paths['server_cert'] = crypto.save_certificate(server_cert, output_dir / "server.crt")
    
    # Generate client certificates
    paths['clients'] = {}
    if client_names:
        for client_name in client_names:
            logger.info(f"Generating client certificate: {client_name}")
            client_key = crypto.generate_private_key()
            client_cert = crypto.generate_self_signed_cert(client_key, client_name)
            
            client_dir = output_dir / "clients" / client_name
            client_dir.mkdir(parents=True, exist_ok=True)
            
            paths['clients'][client_name] = {
                'key': crypto.save_private_key(client_key, client_dir / f"{client_name}.key"),
                'cert': crypto.save_certificate(client_cert, client_dir / f"{client_name}.crt")
            }
    
    # Generate Diffie-Hellman parameters
    logger.info("Generating Diffie-Hellman parameters")
    paths['dh'] = crypto.generate_dh_params(output_dir / "dh.pem")
    
    # Generate TLS auth key
    logger.info("Generating TLS auth key")
    paths['ta'] = crypto.generate_tls_auth_key(output_dir / "ta.key")
    
    return paths

if __name__ == "__main__":
    # Simple test of crypto utilities
    logging.basicConfig(level=logging.INFO)
    
    # Create a temporary directory for testing
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"Using temporary directory: {tmpdir}")
        
        # Generate certificates
        paths = generate_vpn_certificates(
            tmpdir,
            client_names=["client1", "client2"]
        )
        
        print(f"Generated files: {paths}")
        
        # Load and validate CA certificate
        ca_cert = CryptoUtils.load_certificate(paths['ca_cert'])
        ca_info = CryptoUtils.extract_cert_info(ca_cert)
        ca_validation = CryptoUtils.validate_certificate(ca_cert)
        
        print(f"CA certificate info: {ca_info}")
        print(f"CA certificate validation: {ca_validation}")
