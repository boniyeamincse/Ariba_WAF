#!/usr/bin/env python3
"""
HTTPS Support Module for Ariba WAF

This module provides comprehensive HTTPS support for the Ariba Web Application Firewall,
including SSL certificate generation, management, and Tornado HTTPS server configuration.

Features:
- Self-signed SSL certificate generation using cryptography library
- Certificate storage and management
- HTTPS server configuration for Tornado
- Integration with existing WAF components
- Error handling and logging
- Configuration management
"""

import os
import logging
import json
import ssl
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, Union
from pathlib import Path

# Import cryptography library for SSL certificate generation
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# Import Tornado components
try:
    import tornado.web
    import tornado.httpserver
    import tornado.ioloop
    import tornado.netutil
    TORNADO_AVAILABLE = True
except ImportError:
    TORNADO_AVAILABLE = False

class HTTPSConfig:
    """Configuration management for HTTPS support"""

    DEFAULT_CONFIG = {
        'ssl': {
            'enabled': False,
            'cert_file': 'ssl/cert.pem',
            'key_file': 'ssl/key.pem',
            'cert_dir': 'ssl',
            'cert_validity_days': 365,
            'key_size': 2048,
            'country': 'US',
            'state': 'California',
            'locality': 'San Francisco',
            'organization': 'Ariba WAF',
            'common_name': 'localhost',
            'auto_generate': True,
            'force_regenerate': False
        },
        'https_server': {
            'port': 443,
            'host': '0.0.0.0',
            'ssl_options': {
                'certfile': 'ssl/cert.pem',
                'keyfile': 'ssl/key.pem',
                'ssl_version': ssl.PROTOCOL_TLS,
                'cert_reqs': ssl.CERT_NONE,
                'ciphers': None
            }
        }
    }

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize HTTPS configuration

        Args:
            config_file: Path to configuration file (optional)
        """
        self.config_file = config_file or 'https_config.json'
        self.config = self.DEFAULT_CONFIG.copy()
        self._setup_logging()

        # Load existing configuration if available
        if os.path.exists(self.config_file):
            self._load_config()
        else:
            self._save_config()

    def _setup_logging(self):
        """Setup logging for HTTPS module"""
        self.logger = logging.getLogger('ariba_waf.https')
        self.logger.setLevel(logging.INFO)

        # Create console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)

        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        # Add formatter to ch
        ch.setFormatter(formatter)

        # Add ch to logger
        self.logger.addHandler(ch)

    def _load_config(self):
        """Load configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                loaded_config = json.load(f)
                # Deep merge loaded config with defaults
                self._deep_merge(self.config, loaded_config)
            self.logger.info(f"Loaded HTTPS configuration from {self.config_file}")
        except Exception as e:
            self.logger.error(f"Error loading HTTPS configuration: {e}")
            self.logger.info("Using default configuration")

    def _save_config(self):
        """Save configuration to file"""
        try:
            # Ensure directory exists
            config_dir = os.path.dirname(self.config_file)
            if config_dir and not os.path.exists(config_dir):
                os.makedirs(config_dir)

            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            self.logger.info(f"Saved HTTPS configuration to {self.config_file}")
        except Exception as e:
            self.logger.error(f"Error saving HTTPS configuration: {e}")

    def _deep_merge(self, target: Dict, source: Dict):
        """Deep merge source dictionary into target dictionary"""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_merge(target[key], value)
            else:
                target[key] = value

    def get_config(self) -> Dict[str, Any]:
        """Get current configuration"""
        return self.config

    def update_config(self, new_config: Dict[str, Any]):
        """Update configuration"""
        self._deep_merge(self.config, new_config)
        self._save_config()

    def enable_ssl(self, enabled: bool = True):
        """Enable or disable SSL"""
        self.config['ssl']['enabled'] = enabled
        self._save_config()

    def set_cert_paths(self, cert_file: str, key_file: str):
        """Set certificate and key file paths"""
        self.config['ssl']['cert_file'] = cert_file
        self.config['ssl']['key_file'] = key_file
        self.config['https_server']['ssl_options']['certfile'] = cert_file
        self.config['https_server']['ssl_options']['keyfile'] = key_file
        self._save_config()

    def set_server_config(self, host: str, port: int):
        """Set HTTPS server configuration"""
        self.config['https_server']['host'] = host
        self.config['https_server']['port'] = port
        self._save_config()

class SSLCertificateManager:
    """SSL Certificate Management for Ariba WAF"""

    def __init__(self, config: HTTPSConfig):
        """
        Initialize SSL Certificate Manager

        Args:
            config: HTTPSConfig instance
        """
        self.config = config
        self.logger = config.logger

    def _ensure_cert_dir(self):
        """Ensure certificate directory exists"""
        cert_dir = self.config.config['ssl']['cert_dir']
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)
            self.logger.info(f"Created certificate directory: {cert_dir}")

    def generate_self_signed_cert(self) -> Tuple[bool, Optional[str]]:
        """
        Generate self-signed SSL certificate

        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            error_msg = "cryptography library is not available. Please install it with: pip install cryptography"
            self.logger.error(error_msg)
            return False, error_msg

        try:
            self._ensure_cert_dir()

            # Get configuration
            ssl_config = self.config.config['ssl']
            cert_file = ssl_config['cert_file']
            key_file = ssl_config['key_file']
            key_size = ssl_config['key_size']
            validity_days = ssl_config['cert_validity_days']

            # Check if certificates already exist and auto_generate is False
            cert_exists = os.path.exists(cert_file) and os.path.exists(key_file)
            if cert_exists and not ssl_config['auto_generate'] and not ssl_config['force_regenerate']:
                self.logger.info(f"SSL certificates already exist at {cert_file} and {key_file}")
                return True, None

            self.logger.info("Generating self-signed SSL certificate...")

            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )

            # Generate self-signed certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, ssl_config['country']),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ssl_config['state']),
                x509.NameAttribute(NameOID.LOCALITY_NAME, ssl_config['locality']),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, ssl_config['organization']),
                x509.NameAttribute(NameOID.COMMON_NAME, ssl_config['common_name']),
            ])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=validity_days)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(ssl_config['common_name'])]),
                critical=False,
            ).sign(private_key, hashes.SHA256(), default_backend())

            # Write private key
            with open(key_file, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))

            # Write certificate
            with open(cert_file, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            self.logger.info(f"Successfully generated SSL certificate: {cert_file}")
            self.logger.info(f"Successfully generated SSL private key: {key_file}")

            return True, None

        except Exception as e:
            error_msg = f"Error generating SSL certificate: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg

    def validate_certificates(self) -> Tuple[bool, Optional[str]]:
        """
        Validate SSL certificates

        Returns:
            Tuple of (valid: bool, error_message: Optional[str])
        """
        ssl_config = self.config.config['ssl']
        cert_file = ssl_config['cert_file']
        key_file = ssl_config['key_file']

        # Check if files exist
        if not os.path.exists(cert_file):
            return False, f"Certificate file not found: {cert_file}"

        if not os.path.exists(key_file):
            return False, f"Private key file not found: {key_file}"

        try:
            # Try to load and validate the certificate
            with open(cert_file, 'rb') as f:
                cert_data = f.read()

            cert = x509.load_pem_x509_certificate(cert_data, default_backend())

            # Check if certificate is expired
            now = datetime.utcnow()
            if now < cert.not_valid_before or now > cert.not_valid_after:
                return False, "Certificate is expired or not yet valid"

            # Try to load the private key
            with open(key_file, 'rb') as f:
                key_data = f.read()

            private_key = serialization.load_pem_private_key(
                key_data,
                password=None,
                backend=default_backend()
            )

            # Verify that the private key matches the certificate
            cert_public_key = cert.public_key()
            private_key_public = private_key.public_key()

            # Compare public keys
            if not cert_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ) == private_key_public.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ):
                return False, "Private key does not match certificate"

            self.logger.info("SSL certificates are valid")
            return True, None

        except Exception as e:
            error_msg = f"Error validating SSL certificates: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg

    def get_ssl_context(self) -> Optional[ssl.SSLContext]:
        """
        Get SSL context for Tornado HTTPS server

        Returns:
            ssl.SSLContext instance or None if error occurs
        """
        if not TORNADO_AVAILABLE:
            self.logger.error("Tornado is not available")
            return None

        ssl_config = self.config.config['ssl']
        server_config = self.config.config['https_server']['ssl_options']

        try:
            # Create SSL context
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_ctx.load_cert_chain(
                certfile=server_config['certfile'],
                keyfile=server_config['keyfile']
            )

            # Configure SSL options
            if server_config.get('cert_reqs') is not None:
                ssl_ctx.verify_mode = server_config['cert_reqs']

            if server_config.get('ciphers'):
                ssl_ctx.set_ciphers(server_config['ciphers'])

            if server_config.get('ssl_version'):
                ssl_ctx.protocol = server_config['ssl_version']

            self.logger.info("SSL context created successfully")
            return ssl_ctx

        except Exception as e:
            self.logger.error(f"Error creating SSL context: {str(e)}")
            return None

class HTTPSServer:
    """HTTPS Server for Ariba WAF using Tornado"""

    def __init__(self, config: HTTPSConfig, request_handler_class: type):
        """
        Initialize HTTPS Server

        Args:
            config: HTTPSConfig instance
            request_handler_class: Tornado RequestHandler class to use
        """
        self.config = config
        self.logger = config.logger
        self.request_handler_class = request_handler_class
        self.cert_manager = SSLCertificateManager(config)
        self.http_server = None
        self.io_loop = None

    def setup_https_server(self, security_engine=None) -> Tuple[bool, Optional[str]]:
        """
        Setup and configure HTTPS server

        Args:
            security_engine: Optional security engine to pass to request handler

        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        if not TORNADO_AVAILABLE:
            error_msg = "Tornado is not available. Please install it with: pip install tornado"
            self.logger.error(error_msg)
            return False, error_msg

        try:
            # Generate or validate certificates
            if self.config.config['ssl']['enabled']:
                cert_valid, cert_error = self.cert_manager.validate_certificates()
                if not cert_valid:
                    if self.config.config['ssl']['auto_generate']:
                        self.logger.warning(f"Certificate validation failed: {cert_error}. Attempting to generate new certificates...")
                        gen_success, gen_error = self.cert_manager.generate_self_signed_cert()
                        if not gen_success:
                            return False, f"Failed to generate certificates: {gen_error}"
                    else:
                        return False, f"Certificate validation failed: {cert_error}"

            # Create Tornado application
            app = tornado.web.Application([
                (r".*", self.request_handler_class, {"security_engine": security_engine}),
            ])

            # Get SSL context if HTTPS is enabled
            ssl_ctx = None
            if self.config.config['ssl']['enabled']:
                ssl_ctx = self.cert_manager.get_ssl_context()
                if not ssl_ctx:
                    return False, "Failed to create SSL context"

            # Get server configuration
            server_config = self.config.config['https_server']
            host = server_config['host']
            port = server_config['port']

            # Create HTTP server
            self.http_server = tornado.httpserver.HTTPServer(app, ssl_options=ssl_ctx)

            # Bind to port
            self.http_server.listen(port, address=host)

            self.logger.info(f"HTTPS server configured successfully on {host}:{port}")
            self.logger.info(f"SSL enabled: {self.config.config['ssl']['enabled']}")

            return True, None

        except Exception as e:
            error_msg = f"Error setting up HTTPS server: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg

    def start_server(self) -> Tuple[bool, Optional[str]]:
        """
        Start the HTTPS server

        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        try:
            if not self.http_server:
                return False, "Server not configured. Call setup_https_server() first."

            self.logger.info("Starting HTTPS server...")
            self.io_loop = tornado.ioloop.IOLoop.current()
            self.io_loop.start()

            return True, None

        except Exception as e:
            error_msg = f"Error starting HTTPS server: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg

    def stop_server(self):
        """Stop the HTTPS server"""
        try:
            if self.io_loop:
                self.io_loop.stop()
                self.logger.info("HTTPS server stopped")
        except Exception as e:
            self.logger.error(f"Error stopping HTTPS server: {str(e)}")

    def get_server_info(self) -> Dict[str, Any]:
        """Get server information"""
        server_config = self.config.config['https_server']
        ssl_config = self.config.config['ssl']

        return {
            'host': server_config['host'],
            'port': server_config['port'],
            'ssl_enabled': ssl_config['enabled'],
            'cert_file': ssl_config['cert_file'],
            'key_file': ssl_config['key_file'],
            'auto_generate': ssl_config['auto_generate'],
            'server_running': self.io_loop is not None and self.io_loop._running if self.io_loop else False
        }

class HTTPSIntegration:
    """Integration layer for HTTPS support with Ariba WAF components"""

    def __init__(self, config: Optional[HTTPSConfig] = None):
        """
        Initialize HTTPS Integration

        Args:
            config: Optional HTTPSConfig instance
        """
        self.config = config or HTTPSConfig()
        self.logger = self.config.logger
        self.cert_manager = SSLCertificateManager(self.config)

    def integrate_with_waf(self, waf_components: Dict[str, Any]) -> Dict[str, Any]:
        """
        Integrate HTTPS support with WAF components

        Args:
            waf_components: Dictionary of WAF components

        Returns:
            Updated WAF components with HTTPS integration
        """
        try:
            # Add HTTPS configuration to WAF components
            waf_components['https_config'] = self.config
            waf_components['ssl_cert_manager'] = self.cert_manager

            # Add HTTPS server factory
            waf_components['https_server_factory'] = lambda request_handler_class, security_engine=None: HTTPSServer(
                self.config, request_handler_class, security_engine
            )

            self.logger.info("HTTPS support successfully integrated with WAF components")

            return waf_components

        except Exception as e:
            self.logger.error(f"Error integrating HTTPS with WAF: {str(e)}")
            return waf_components

    def create_https_server(self, request_handler_class: type, security_engine=None) -> HTTPSServer:
        """
        Create HTTPS server instance

        Args:
            request_handler_class: Tornado RequestHandler class
            security_engine: Optional security engine

        Returns:
            Configured HTTPSServer instance
        """
        return HTTPSServer(self.config, request_handler_class, security_engine)

# Main function for standalone usage
def main():
    """Main function for standalone HTTPS support"""
    print("Ariba WAF HTTPS Support Module")
    print("This module provides HTTPS support for the Ariba Web Application Firewall")
    print("Use it by importing and integrating with your WAF components")

if __name__ == "__main__":
    main()