#!/usr/bin/env python3
"""
GPG Key Server startup script with initialization
"""

import os
import sys
import logging
import argparse
from pathlib import Path

# Add current directory and lib to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)
sys.path.insert(0, os.path.join(os.path.dirname(current_dir), 'lib'))

from lib.config import get_config, Config
from lib.models import create_database, check_database_health
from api_key_manager import APIKeyManager
from master_key_manager import MasterKeyManager
from gpg_server import run_server


def setup_logging():
    """Setup logging for startup"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)


def initialize_database():
    """Initialize database and tables"""
    logger = logging.getLogger(__name__)
    try:
        logger.info("Initializing database...")
        create_database()

        # Test database connection
        if check_database_health():
            logger.info("Database initialized and healthy")
            return True
        else:
            logger.error("Database health check failed")
            return False

    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return False


def create_admin_api_key():
    """Create initial admin API key if none exists"""
    logger = logging.getLogger(__name__)
    try:
        config = get_config()
        if not config.server.admin_api_key:
            logger.warning("No admin API key configured in environment")
            return False

        # Check if admin key already exists by trying to create one
        api_key_manager = APIKeyManager()

        # Create admin permissions
        admin_permissions = {
            'operations': ['admin', 'read', 'list', 'sign', 'encrypt', 'info', 'search'],
            'keys': '*'
        }

        # Try to create admin API key (will fail if already exists)
        try:
            result = api_key_manager.create_api_key(
                name="Admin API Key",
                owner="system",
                permissions=admin_permissions,
                rate_limit=10000,
                notes="System-generated admin key"
            )
            logger.info(f"Created admin API key with ID: {result['id']}")
            return True

        except Exception as e:
            if "already exists" in str(e):
                logger.info("Admin API key already exists")
                return True
            else:
                logger.error(f"Failed to create admin API key: {e}")
                return False

    except Exception as e:
        logger.error(f"Error setting up admin API key: {e}")
        return False


def create_organizational_keys():
    """Create default organizational keys if none exist"""
    logger = logging.getLogger(__name__)
    try:
        master_key_manager = MasterKeyManager()

        # Check if we have default organizational keys
        default_signing = master_key_manager.get_default_key('signing', 'organizational')
        default_encryption = master_key_manager.get_default_key('encryption', 'organizational')

        if default_signing and default_encryption:
            logger.info("Default organizational keys already exist")
            return True

        # Get organization info from environment or use defaults
        organization = os.getenv('ORGANIZATION_NAME', 'Default Organization')
        admin_email = os.getenv('ADMIN_EMAIL', 'admin@organization.com')

        logger.info(f"Creating organizational keys for: {organization}")

        # Create organizational key pair
        result = master_key_manager.create_organizational_key_pair(
            organization=organization,
            name=f"{organization} Keys",
            email=admin_email
        )

        logger.info(f"Created organizational signing key: {result['signing_key']['fingerprint']}")
        logger.info(f"Created organizational encryption key: {result['encryption_key']['fingerprint']}")

        return True

    except Exception as e:
        logger.error(f"Failed to create organizational keys: {e}")
        return False


def validate_configuration():
    """Validate server configuration"""
    logger = logging.getLogger(__name__)
    try:
        config = get_config()

        # Check critical configuration
        if config.server.enabled:
            logger.info("GPG Server is enabled")

            # Check admin API key
            if not config.server.admin_api_key:
                logger.warning("No admin API key configured (GPG_SERVER_ADMIN_API_KEY)")

            # Check SSL configuration
            if config.server.require_ssl:
                if not config.server.ssl_cert_file or not config.server.ssl_key_file:
                    logger.warning("SSL required but certificate files not configured")

            # Check directories
            directories = [
                config.gpg.home,
                os.path.dirname(config.database.path),
            ]

            if config.backup.enabled:
                directories.append(config.backup.path)

            if config.master_keys.backup_enabled:
                directories.append(config.master_keys.backup_path)

            for directory in directories:
                if directory and not os.path.exists(directory):
                    try:
                        os.makedirs(directory, exist_ok=True)
                        logger.info(f"Created directory: {directory}")
                    except OSError as e:
                        logger.error(f"Failed to create directory {directory}: {e}")
                        return False

        return True

    except Exception as e:
        logger.error(f"Configuration validation failed: {e}")
        return False


def main():
    """Main startup function"""
    parser = argparse.ArgumentParser(description="GPG Key Server Startup")
    parser.add_argument('--init-only', action='store_true',
                       help='Only initialize database and keys, don\'t start server')
    parser.add_argument('--skip-org-keys', action='store_true',
                       help='Skip organizational key creation')
    parser.add_argument('--config-file', help='Configuration file path')

    args = parser.parse_args()

    logger = setup_logging()
    logger.info("Starting GPG Key Server initialization...")

    # Load configuration
    if args.config_file:
        from lib.config import reload_config
        config = reload_config(args.config_file)
        logger.info(f"Loaded configuration from: {args.config_file}")
    else:
        config = get_config()

    # Setup logging from config
    config.setup_logging()

    # Validate configuration
    if not validate_configuration():
        logger.error("Configuration validation failed")
        return 1

    # Initialize database
    if not initialize_database():
        logger.error("Database initialization failed")
        return 1

    # Create admin API key
    if not create_admin_api_key():
        logger.warning("Admin API key setup failed - admin functions may not work")

    # Create organizational keys (unless skipped)
    if not args.skip_org_keys:
        if not create_organizational_keys():
            logger.warning("Organizational key creation failed - master key validation may not work")

    if args.init_only:
        logger.info("Initialization complete (init-only mode)")
        return 0

    # Start server
    logger.info("Starting GPG Key Server...")
    try:
        run_server()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())