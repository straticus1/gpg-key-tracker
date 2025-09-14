#!/usr/bin/env python3
"""
Master Key Management System for GPG Key Server
Handles organizational signing and encryption keys for key validation
"""

import os
import gnupg
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from contextlib import contextmanager
import tempfile
import shutil
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy import and_, or_
import sys
import os
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)
sys.path.append(os.path.join(parent_dir, 'lib'))

from lib.models import MasterKey, GPGKey, KeySignature, get_session
from lib.config import get_config

logger = logging.getLogger(__name__)


class MasterKeyManager:
    """Manages master keys for GPG Key Server validation"""

    def __init__(self, config=None):
        """Initialize master key manager"""
        self.config = config or get_config()
        self.gpg_home = self.config.get('GPG_HOME', os.path.expanduser('~/.gnupg'))
        self.gpg = gnupg.GPG(gnupghome=self.gpg_home)

    @contextmanager
    def _get_db_session(self):
        """Context manager for database sessions"""
        session = get_session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def _validate_key_type(self, key_type: str) -> bool:
        """Validate key type"""
        return key_type in ['signing', 'encryption']

    def _validate_key_role(self, key_role: str) -> bool:
        """Validate key role"""
        return key_role in ['organizational', 'master']

    def create_master_key(self, name: str, key_type: str, key_role: str = 'master',
                         organization: Optional[str] = None, email: Optional[str] = None,
                         key_size: int = 4096, algorithm: str = 'RSA',
                         expires_days: Optional[int] = None,
                         set_as_default: bool = False) -> Dict[str, Any]:
        """Create a new master key"""
        try:
            # Validate inputs
            if not name:
                raise ValueError("Name is required")

            if not self._validate_key_type(key_type):
                raise ValueError(f"Invalid key type: {key_type}")

            if not self._validate_key_role(key_role):
                raise ValueError(f"Invalid key role: {key_role}")

            # Calculate expiration
            expires_at = None
            if expires_days:
                expires_at = datetime.utcnow() + timedelta(days=expires_days)

            # Generate GPG key
            key_params = {
                'name_real': name,
                'key_type': algorithm,
                'key_length': key_size,
                'name_comment': f"{key_role.title()} {key_type} Key",
                'expire_date': f"{expires_days}d" if expires_days else '0'
            }

            if email:
                key_params['name_email'] = email

            if organization and key_role == 'organizational':
                key_params['name_comment'] = f"{organization} {key_type.title()} Key"

            logger.info(f"Generating {key_role} {key_type} key: {name}")
            key_result = self.gpg.gen_key(self.gpg.gen_key_input(**key_params))

            if not key_result.fingerprint:
                raise RuntimeError("Failed to generate GPG key")

            fingerprint = key_result.fingerprint

            with self._get_db_session() as session:
                # Check if setting as default, clear other defaults of same type/role
                if set_as_default:
                    existing_defaults = session.query(MasterKey).filter_by(
                        key_type=key_type,
                        key_role=key_role,
                        is_default=True,
                        is_active=True
                    ).all()
                    for existing in existing_defaults:
                        existing.is_default = False
                        logger.info(f"Removed default status from key {existing.fingerprint}")

                # Create master key record
                master_key = MasterKey(
                    fingerprint=fingerprint,
                    key_type=key_type,
                    key_role=key_role,
                    name=name,
                    organization=organization,
                    email=email,
                    key_size=key_size,
                    algorithm=algorithm,
                    expires_at=expires_at,
                    is_default=set_as_default
                )

                session.add(master_key)
                session.flush()

                logger.info(f"Created {key_role} {key_type} master key {fingerprint}")

                return {
                    'id': master_key.id,
                    'fingerprint': fingerprint,
                    'name': name,
                    'key_type': key_type,
                    'key_role': key_role,
                    'organization': organization,
                    'email': email,
                    'key_size': key_size,
                    'algorithm': algorithm,
                    'expires_at': expires_at,
                    'is_default': set_as_default,
                    'created_at': master_key.created_at
                }

        except (SQLAlchemyError, IntegrityError) as e:
            logger.error(f"Database error creating master key: {e}")
            raise
        except Exception as e:
            logger.error(f"Error creating master key: {e}")
            raise

    def create_organizational_key_pair(self, organization: str, name: str,
                                     email: Optional[str] = None,
                                     key_size: int = 4096,
                                     expires_days: Optional[int] = None) -> Dict[str, Any]:
        """Create organizational signing and encryption key pair"""
        try:
            # Create signing key
            signing_key = self.create_master_key(
                name=f"{name} Signing",
                key_type='signing',
                key_role='organizational',
                organization=organization,
                email=email,
                key_size=key_size,
                expires_days=expires_days,
                set_as_default=True
            )

            # Create encryption key
            encryption_key = self.create_master_key(
                name=f"{name} Encryption",
                key_type='encryption',
                key_role='organizational',
                organization=organization,
                email=email,
                key_size=key_size,
                expires_days=expires_days,
                set_as_default=True
            )

            logger.info(f"Created organizational key pair for {organization}")

            return {
                'signing_key': signing_key,
                'encryption_key': encryption_key,
                'organization': organization
            }

        except Exception as e:
            logger.error(f"Error creating organizational key pair: {e}")
            raise

    def get_default_key(self, key_type: str, key_role: str = 'organizational') -> Optional[Dict[str, Any]]:
        """Get default key of specified type and role"""
        try:
            if not self._validate_key_type(key_type):
                raise ValueError(f"Invalid key type: {key_type}")

            if not self._validate_key_role(key_role):
                raise ValueError(f"Invalid key role: {key_role}")

            with self._get_db_session() as session:
                master_key = session.query(MasterKey).filter_by(
                    key_type=key_type,
                    key_role=key_role,
                    is_default=True,
                    is_active=True
                ).first()

                if not master_key:
                    return None

                return {
                    'id': master_key.id,
                    'fingerprint': master_key.fingerprint,
                    'name': master_key.name,
                    'key_type': master_key.key_type,
                    'key_role': master_key.key_role,
                    'organization': master_key.organization,
                    'email': master_key.email,
                    'algorithm': master_key.algorithm,
                    'key_size': master_key.key_size,
                    'created_at': master_key.created_at,
                    'expires_at': master_key.expires_at,
                    'is_default': master_key.is_default
                }

        except Exception as e:
            logger.error(f"Error getting default key: {e}")
            return None

    def set_default_key(self, fingerprint: str) -> bool:
        """Set a master key as default for its type and role"""
        try:
            with self._get_db_session() as session:
                master_key = session.query(MasterKey).filter_by(
                    fingerprint=fingerprint,
                    is_active=True
                ).first()

                if not master_key:
                    logger.error(f"Master key {fingerprint} not found")
                    return False

                # Clear existing defaults of same type and role
                existing_defaults = session.query(MasterKey).filter_by(
                    key_type=master_key.key_type,
                    key_role=master_key.key_role,
                    is_default=True,
                    is_active=True
                ).all()

                for existing in existing_defaults:
                    existing.is_default = False

                # Set new default
                master_key.is_default = True
                logger.info(f"Set {fingerprint} as default {master_key.key_role} {master_key.key_type} key")

                return True

        except (SQLAlchemyError, IntegrityError) as e:
            logger.error(f"Database error setting default key: {e}")
            return False
        except Exception as e:
            logger.error(f"Error setting default key: {e}")
            return False

    def list_master_keys(self, key_type: Optional[str] = None, key_role: Optional[str] = None,
                        include_inactive: bool = False) -> List[Dict[str, Any]]:
        """List master keys"""
        try:
            with self._get_db_session() as session:
                query = session.query(MasterKey)

                if key_type:
                    query = query.filter_by(key_type=key_type)

                if key_role:
                    query = query.filter_by(key_role=key_role)

                if not include_inactive:
                    query = query.filter_by(is_active=True)

                keys = query.order_by(MasterKey.created_at.desc()).all()

                return [
                    {
                        'id': key.id,
                        'fingerprint': key.fingerprint,
                        'name': key.name,
                        'key_type': key.key_type,
                        'key_role': key.key_role,
                        'organization': key.organization,
                        'email': key.email,
                        'algorithm': key.algorithm,
                        'key_size': key.key_size,
                        'created_at': key.created_at,
                        'expires_at': key.expires_at,
                        'is_active': key.is_active,
                        'is_default': key.is_default
                    }
                    for key in keys
                ]

        except Exception as e:
            logger.error(f"Error listing master keys: {e}")
            return []

    def sign_key(self, key_fingerprint: str, master_fingerprint: Optional[str] = None) -> bool:
        """Sign a key with a master signing key"""
        try:
            # Get default organizational signing key if not specified
            if not master_fingerprint:
                default_key = self.get_default_key('signing', 'organizational')
                if not default_key:
                    logger.error("No default organizational signing key found")
                    return False
                master_fingerprint = default_key['fingerprint']

            # Verify master key exists and is active
            with self._get_db_session() as session:
                master_key = session.query(MasterKey).filter_by(
                    fingerprint=master_fingerprint,
                    key_type='signing',
                    is_active=True
                ).first()

                if not master_key:
                    logger.error(f"Master signing key {master_fingerprint} not found or inactive")
                    return False

                # Sign the key using GPG
                sign_result = self.gpg.sign_key(
                    keyid=key_fingerprint,
                    local=True,  # Local signature
                    sign_keyid=master_fingerprint
                )

                if not sign_result:
                    logger.error(f"Failed to sign key {key_fingerprint}")
                    return False

                # Record signature in database
                key_signature = KeySignature(
                    key_fingerprint=key_fingerprint,
                    master_key_fingerprint=master_fingerprint,
                    signature_data=str(sign_result)
                )

                session.add(key_signature)
                logger.info(f"Signed key {key_fingerprint} with master key {master_fingerprint}")

                return True

        except Exception as e:
            logger.error(f"Error signing key {key_fingerprint}: {e}")
            return False

    def verify_key_signature(self, key_fingerprint: str) -> bool:
        """Verify if a key has valid master signature"""
        try:
            with self._get_db_session() as session:
                # Check if key has valid signature from active master key
                signature = session.query(KeySignature).join(MasterKey).filter(
                    and_(
                        KeySignature.key_fingerprint == key_fingerprint,
                        KeySignature.is_valid == True,
                        MasterKey.is_active == True,
                        MasterKey.key_type == 'signing'
                    )
                ).first()

                if signature:
                    # Update verification timestamp
                    signature.verified_at = datetime.utcnow()
                    return True

                return False

        except Exception as e:
            logger.error(f"Error verifying key signature {key_fingerprint}: {e}")
            return False

    def export_master_key(self, fingerprint: str, secret: bool = False) -> Optional[str]:
        """Export master key"""
        try:
            with self._get_db_session() as session:
                master_key = session.query(MasterKey).filter_by(
                    fingerprint=fingerprint,
                    is_active=True
                ).first()

                if not master_key:
                    logger.error(f"Master key {fingerprint} not found")
                    return None

                # Export from GPG
                if secret:
                    key_data = self.gpg.export_keys(fingerprint, secret=True)
                else:
                    key_data = self.gpg.export_keys(fingerprint)

                if not key_data:
                    logger.error(f"Failed to export master key {fingerprint}")
                    return None

                return key_data

        except Exception as e:
            logger.error(f"Error exporting master key {fingerprint}: {e}")
            return None

    def backup_master_keys(self, backup_path: str) -> bool:
        """Backup all master keys to specified path"""
        try:
            backup_dir = Path(backup_path)
            backup_dir.mkdir(parents=True, exist_ok=True)

            master_keys = self.list_master_keys()

            for key in master_keys:
                fingerprint = key['fingerprint']

                # Export public key
                public_key = self.export_master_key(fingerprint, secret=False)
                if public_key:
                    pub_file = backup_dir / f"{fingerprint}_public.asc"
                    pub_file.write_text(public_key)

                # Export secret key
                secret_key = self.export_master_key(fingerprint, secret=True)
                if secret_key:
                    sec_file = backup_dir / f"{fingerprint}_secret.asc"
                    sec_file.write_text(secret_key)
                    sec_file.chmod(0o600)  # Restrict permissions

            logger.info(f"Backed up {len(master_keys)} master keys to {backup_path}")
            return True

        except Exception as e:
            logger.error(f"Error backing up master keys: {e}")
            return False

    def rotate_master_key(self, old_fingerprint: str, new_key_data: str) -> bool:
        """Rotate a master key"""
        try:
            with self._get_db_session() as session:
                old_key = session.query(MasterKey).filter_by(
                    fingerprint=old_fingerprint,
                    is_active=True
                ).first()

                if not old_key:
                    logger.error(f"Master key {old_fingerprint} not found")
                    return False

                # Import new key
                import_result = self.gpg.import_keys(new_key_data)
                if not import_result.fingerprints:
                    logger.error("Failed to import new master key")
                    return False

                new_fingerprint = import_result.fingerprints[0]

                # Create new master key record
                new_key = MasterKey(
                    fingerprint=new_fingerprint,
                    key_type=old_key.key_type,
                    key_role=old_key.key_role,
                    name=f"{old_key.name} (Rotated)",
                    organization=old_key.organization,
                    email=old_key.email,
                    algorithm=old_key.algorithm,
                    key_size=old_key.key_size,
                    is_default=old_key.is_default
                )

                session.add(new_key)

                # Deactivate old key
                old_key.is_active = False
                old_key.is_default = False

                logger.info(f"Rotated master key from {old_fingerprint} to {new_fingerprint}")
                return True

        except Exception as e:
            logger.error(f"Error rotating master key: {e}")
            return False


def create_organizational_keys(organization: str, name: str, email: str = None) -> Dict[str, Any]:
    """Utility function to create organizational key pair"""
    manager = MasterKeyManager()
    return manager.create_organizational_key_pair(organization, name, email)


if __name__ == '__main__':
    # Test master key management
    manager = MasterKeyManager()

    # Test organizational key creation
    try:
        keys = create_organizational_keys(
            organization="Example Corp",
            name="Example Corp Keys",
            email="admin@example.com"
        )
        print(f"Created organizational keys:")
        print(f"Signing: {keys['signing_key']['fingerprint']}")
        print(f"Encryption: {keys['encryption_key']['fingerprint']}")

        # Test default key retrieval
        default_signing = manager.get_default_key('signing', 'organizational')
        if default_signing:
            print(f"Default signing key: {default_signing['fingerprint']}")

    except Exception as e:
        print(f"Error: {e}")