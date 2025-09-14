#!/usr/bin/env python3
"""
GPG Key Manager for server operations
Extended version of GPGManager with server-specific functionality
"""

import gnupg
import os
import re
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Union, Any
from contextlib import contextmanager
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy import and_, or_, desc
import sys
import os
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)
sys.path.append(os.path.join(parent_dir, 'lib'))

from lib.models import GPGKey, UsageLog, get_session
from lib.config import get_config

logger = logging.getLogger(__name__)


class GPGKeyManager:
    """Extended GPG key manager for server operations"""

    def __init__(self, gpg_home: Optional[str] = None, config=None):
        """Initialize GPG key manager"""
        self.config = config or get_config()
        self.gpg_home = gpg_home or self.config.gpg.home
        self.gpg = gnupg.GPG(gnupghome=self.gpg_home)
        logger.info(f"Initialized GPG key manager with home: {self.gpg_home}")

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

    def _validate_fingerprint(self, fingerprint: str) -> bool:
        """Validate GPG key fingerprint format"""
        if not fingerprint:
            return False
        # Support both 40-char (SHA-1) and 64-char (SHA-256) fingerprints
        return bool(re.match(r'^[A-F0-9]{40}$|^[A-F0-9]{64}$', fingerprint.upper()))

    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    def _sanitize_input(self, input_str: str, max_length: int = 255) -> str:
        """Sanitize user input"""
        if not input_str:
            return ""

        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>&"\'\x00-\x1f\x7f-\x9f]', '', str(input_str))
        return sanitized[:max_length].strip()

    def _extract_email(self, uid: str) -> Optional[str]:
        """Extract email from GPG UID"""
        match = re.search(r'<([^>]+@[^>]+)>', uid)
        return match.group(1) if match else None

    def _extract_name(self, uid: str) -> Optional[str]:
        """Extract name from GPG UID"""
        match = re.match(r'^([^<(]+)', uid)
        return match.group(1).strip() if match else None

    def _get_key_expiry_date(self, fingerprint: str) -> Optional[datetime]:
        """Get key expiration date from GPG"""
        try:
            keys = self.gpg.list_keys(keys=fingerprint)
            if keys and keys[0].get('expires'):
                expires_timestamp = keys[0]['expires']
                if expires_timestamp:
                    return datetime.fromtimestamp(float(expires_timestamp))
        except Exception as e:
            logger.warning(f"Failed to get expiry date for {fingerprint}: {e}")
        return None

    def import_key(self, key_data: str, owner: str, requester: str,
                   jira_ticket: Optional[str] = None, notes: Optional[str] = None) -> Dict[str, Any]:
        """Import a GPG key from data string"""
        # Validate and sanitize inputs
        owner = self._sanitize_input(owner)
        requester = self._sanitize_input(requester)
        jira_ticket = self._sanitize_input(jira_ticket) if jira_ticket else None
        notes = self._sanitize_input(notes, max_length=1000) if notes else None

        if not owner or not requester:
            return {'success': False, 'error': 'Owner and requester are required'}

        if not key_data or len(key_data.strip()) == 0:
            return {'success': False, 'error': 'Key data is required'}

        try:
            # Validate key data format
            if not ('-----BEGIN PGP' in key_data and '-----END PGP' in key_data):
                return {'success': False, 'error': 'Invalid GPG key format'}

            # Validate size
            if len(key_data.encode()) > self.config.gpg.max_key_size:
                return {'success': False, 'error': f'Key data too large (max {self.config.gpg.max_key_size} bytes)'}

            # Import the key
            import_result = self.gpg.import_keys(key_data)

            if not import_result.imported or not import_result.fingerprints:
                return {'success': False, 'error': f'Failed to import key: {import_result.stderr}'}

            fingerprint = import_result.fingerprints[0]

            # Validate fingerprint
            if not self._validate_fingerprint(fingerprint):
                return {'success': False, 'error': f'Invalid fingerprint format: {fingerprint}'}

            # Get key information
            keys = self.gpg.list_keys(keys=fingerprint)
            if not keys:
                return {'success': False, 'error': 'Failed to retrieve imported key information'}

            key_info = keys[0]
            key_expiry = self._get_key_expiry_date(fingerprint)

            # Check for duplicate key
            with self._get_db_session() as session:
                existing_key = session.query(GPGKey).filter_by(fingerprint=fingerprint).first()
                if existing_key:
                    return {'success': False, 'error': f'Key with fingerprint {fingerprint} already exists'}

                # Extract and validate email if present
                extracted_email = None
                if key_info.get('uids'):
                    extracted_email = self._extract_email(key_info['uids'][0])
                    if extracted_email and not self._validate_email(extracted_email):
                        logger.warning(f"Invalid email format in key UID: {extracted_email}")
                        extracted_email = None

                # Create database record
                gpg_key = GPGKey(
                    fingerprint=fingerprint,
                    key_id=key_info.get('keyid', ''),
                    user_id=key_info['uids'][0][:255] if key_info.get('uids') else '',
                    email=extracted_email,
                    name=self._extract_name(key_info['uids'][0])[:255] if key_info.get('uids') else None,
                    owner=owner,
                    requester=requester,
                    jira_ticket=jira_ticket,
                    notes=notes,
                    expires_at=key_expiry,
                    is_expired=key_expiry and key_expiry < datetime.utcnow() if key_expiry else False
                )

                session.add(gpg_key)
                logger.info(f"Successfully imported key {fingerprint} for owner {owner}")

                return {
                    'success': True,
                    'fingerprint': fingerprint,
                    'key_id': key_info.get('keyid', ''),
                    'user_id': key_info['uids'][0] if key_info.get('uids') else '',
                    'imported': import_result.imported
                }

        except gnupg.GPGError as e:
            logger.error(f"GPG error while importing key: {e}")
            return {'success': False, 'error': f'GPG error: {e}'}
        except (SQLAlchemyError, IntegrityError) as e:
            logger.error(f"Database error while importing key: {e}")
            return {'success': False, 'error': 'Database error occurred'}
        except Exception as e:
            logger.error(f"Unexpected error importing key: {e}")
            return {'success': False, 'error': 'An unexpected error occurred'}

    def get_key_info(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        """Get GPG key information"""
        if not self._validate_fingerprint(fingerprint):
            return None

        try:
            with self._get_db_session() as session:
                key = session.query(GPGKey).filter_by(fingerprint=fingerprint).first()
                if not key:
                    return None

                return {
                    'id': key.id,
                    'fingerprint': key.fingerprint,
                    'key_id': key.key_id,
                    'user_id': key.user_id,
                    'email': key.email,
                    'name': key.name,
                    'owner': key.owner,
                    'requester': key.requester,
                    'jira_ticket': key.jira_ticket,
                    'created_at': key.created_at,
                    'updated_at': key.updated_at,
                    'expires_at': key.expires_at,
                    'last_used_at': key.last_used_at,
                    'usage_count': key.usage_count,
                    'is_active': key.is_active,
                    'is_expired': key.is_expired,
                    'notes': key.notes
                }

        except Exception as e:
            logger.error(f"Error getting key info {fingerprint}: {e}")
            return None

    def list_keys(self, limit: int = 50, offset: int = 0, owner: Optional[str] = None,
                  active_only: bool = True) -> List[Dict[str, Any]]:
        """List GPG keys"""
        try:
            with self._get_db_session() as session:
                query = session.query(GPGKey)

                if owner:
                    query = query.filter_by(owner=owner)

                if active_only:
                    query = query.filter_by(is_active=True)

                keys = query.order_by(desc(GPGKey.created_at)).limit(limit).offset(offset).all()

                return [
                    {
                        'id': key.id,
                        'fingerprint': key.fingerprint,
                        'key_id': key.key_id,
                        'user_id': key.user_id,
                        'email': key.email,
                        'name': key.name,
                        'owner': key.owner,
                        'requester': key.requester,
                        'jira_ticket': key.jira_ticket,
                        'created_at': key.created_at,
                        'updated_at': key.updated_at,
                        'expires_at': key.expires_at,
                        'last_used_at': key.last_used_at,
                        'usage_count': key.usage_count,
                        'is_active': key.is_active,
                        'is_expired': key.is_expired,
                        'notes': key.notes
                    }
                    for key in keys
                ]

        except Exception as e:
            logger.error(f"Error listing keys: {e}")
            return []

    def search_keys(self, query: str, search_type: str = "text",
                   fields: Optional[List[str]] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Enhanced search GPG keys with different search types"""
        if not query or len(query.strip()) == 0:
            return []

        search_fields = fields or ['fingerprint', 'key_id', 'user_id', 'email', 'name', 'owner']

        try:
            with self._get_db_session() as session:
                db_query = session.query(GPGKey).filter(GPGKey.is_active == True)
                conditions = []
                sanitized_query = self._sanitize_input(query)

                if search_type == "fingerprint":
                    # Exact or partial fingerprint search
                    conditions.append(GPGKey.fingerprint.like(f'%{sanitized_query.upper()}%'))

                elif search_type == "key_id":
                    # Exact or partial key ID search
                    conditions.append(GPGKey.key_id.like(f'%{sanitized_query.upper()}%'))

                elif search_type == "email":
                    # Email search
                    conditions.append(GPGKey.email.like(f'%{sanitized_query}%'))
                    conditions.append(GPGKey.user_id.like(f'%{sanitized_query}%'))

                elif search_type == "name":
                    # Name search
                    conditions.append(GPGKey.name.like(f'%{sanitized_query}%'))
                    conditions.append(GPGKey.user_id.like(f'%{sanitized_query}%'))

                elif search_type == "owner":
                    # Owner search
                    conditions.append(GPGKey.owner.like(f'%{sanitized_query}%'))

                else:  # search_type == "text" or any other value
                    # Full text search across specified fields
                    for field in search_fields:
                        if hasattr(GPGKey, field):
                            attr = getattr(GPGKey, field)
                            conditions.append(attr.like(f'%{sanitized_query}%'))

                if conditions:
                    db_query = db_query.filter(or_(*conditions))

                keys = db_query.limit(limit).all()

                return [self._key_to_dict(key) for key in keys]

        except Exception as e:
            logger.error(f"Error searching keys: {e}")
            return []

    def check_key_exists(self, key_data: str) -> Dict[str, Any]:
        """Check if a key exists by parsing the key data and searching for it"""
        try:
            if not key_data or not ('-----BEGIN PGP' in key_data and '-----END PGP' in key_data):
                return {
                    'found': False,
                    'message': 'Invalid GPG key format',
                    'fingerprint': None
                }

            # Parse the key data to extract fingerprint
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.asc', delete=False) as temp_file:
                temp_file.write(key_data)
                temp_file_path = temp_file.name

            try:
                # Import to temporary GPG instance to get fingerprint
                import gnupg
                temp_gpg = gnupg.GPG()
                import_result = temp_gpg.import_keys(key_data)

                if not import_result.fingerprints:
                    return {
                        'found': False,
                        'message': 'Failed to parse GPG key data',
                        'fingerprint': None
                    }

                fingerprint = import_result.fingerprints[0]

                # Clean up temporary import
                temp_gpg.delete_keys(fingerprint, secret=True)
                temp_gpg.delete_keys(fingerprint, secret=False)

                # Check if key exists in our database
                key_info = self.get_key_info(fingerprint)

                if key_info:
                    return {
                        'found': True,
                        'message': f'Key {fingerprint} is already in the system',
                        'fingerprint': fingerprint,
                        'key_info': key_info
                    }
                else:
                    return {
                        'found': False,
                        'message': f'Key {fingerprint} is not in the system',
                        'fingerprint': fingerprint,
                        'how_to_add': {
                            'method': 'POST',
                            'endpoint': '/keys',
                            'description': 'Add the key by sending key_data, owner, and requester information',
                            'example_curl': f'curl -X POST -H "X-API-Key: YOUR_API_KEY" -H "Content-Type: application/json" -d \'{{ "key_data": "YOUR_KEY_DATA", "owner": "owner@example.com", "requester": "requester@example.com" }}\' {self._get_server_url()}/keys',
                            'required_fields': ['key_data', 'owner', 'requester'],
                            'optional_fields': ['jira_ticket', 'notes']
                        }
                    }

            finally:
                # Clean up temporary file
                import os
                os.unlink(temp_file_path)

        except Exception as e:
            logger.error(f"Error checking key existence: {e}")
            return {
                'found': False,
                'message': f'Error checking key: {str(e)}',
                'fingerprint': None
            }

    def _key_to_dict(self, key) -> Dict[str, Any]:
        """Convert GPGKey model to dictionary"""
        return {
            'id': key.id,
            'fingerprint': key.fingerprint,
            'key_id': key.key_id,
            'user_id': key.user_id,
            'email': key.email,
            'name': key.name,
            'owner': key.owner,
            'requester': key.requester,
            'jira_ticket': key.jira_ticket,
            'created_at': key.created_at,
            'updated_at': key.updated_at,
            'expires_at': key.expires_at,
            'last_used_at': key.last_used_at,
            'usage_count': key.usage_count,
            'is_active': key.is_active,
            'is_expired': key.is_expired,
            'notes': key.notes
        }

    def _get_server_url(self) -> str:
        """Get server URL for documentation purposes"""
        config = self.config if hasattr(self, 'config') else get_config()
        protocol = "https" if config.server.require_ssl else "http"
        return f"{protocol}://{config.server.host}:{config.server.port}"

    def update_key(self, fingerprint: str, **kwargs) -> bool:
        """Update key metadata in database"""
        if not self._validate_fingerprint(fingerprint):
            return False

        try:
            with self._get_db_session() as session:
                key = session.query(GPGKey).filter_by(fingerprint=fingerprint).first()
                if not key:
                    return False

                # Update allowed fields with sanitization
                allowed_fields = ['owner', 'requester', 'jira_ticket', 'notes', 'is_active']
                updated = False

                for field, value in kwargs.items():
                    if field in allowed_fields and hasattr(key, field):
                        if field in ['owner', 'requester', 'jira_ticket', 'notes'] and value:
                            max_len = 1000 if field == 'notes' else 255
                            value = self._sanitize_input(str(value), max_len)
                        setattr(key, field, value)
                        updated = True

                if updated:
                    key.updated_at = datetime.utcnow()

                return updated

        except Exception as e:
            logger.error(f"Error updating key {fingerprint}: {e}")
            return False

    def delete_key(self, fingerprint: str, hard_delete: bool = False) -> bool:
        """Delete GPG key"""
        if not self._validate_fingerprint(fingerprint):
            return False

        try:
            with self._get_db_session() as session:
                key = session.query(GPGKey).filter_by(fingerprint=fingerprint).first()
                if not key:
                    return False

                if hard_delete:
                    # Hard delete - remove from database and keyring
                    session.delete(key)

                    # Also remove from GPG keyring
                    try:
                        self.gpg.delete_keys(fingerprint, secret=True)
                        self.gpg.delete_keys(fingerprint, secret=False)
                    except Exception as e:
                        logger.warning(f"Failed to remove key from keyring: {e}")

                    logger.info(f"Hard deleted key {fingerprint}")
                else:
                    # Soft delete - just deactivate
                    key.is_active = False
                    key.updated_at = datetime.utcnow()
                    logger.info(f"Soft deleted (deactivated) key {fingerprint}")

                return True

        except Exception as e:
            logger.error(f"Error deleting key {fingerprint}: {e}")
            return False

    def sign_data(self, data: str, key_fingerprint: str, detached: bool = True) -> Dict[str, Any]:
        """Sign data with GPG key"""
        if not self._validate_fingerprint(key_fingerprint):
            return {'success': False, 'error': 'Invalid fingerprint format'}

        try:
            # Update key usage
            self._log_key_usage(key_fingerprint, 'sign')

            # Sign the data
            sign_result = self.gpg.sign(
                data,
                keyid=key_fingerprint,
                detach=detached,
                clearsign=not detached
            )

            if not sign_result:
                return {'success': False, 'error': f'Failed to sign data: {sign_result.stderr}'}

            return {
                'success': True,
                'signature': str(sign_result),
                'fingerprint': key_fingerprint
            }

        except Exception as e:
            logger.error(f"Error signing data with key {key_fingerprint}: {e}")
            return {'success': False, 'error': f'Signing failed: {e}'}

    def encrypt_data(self, data: str, recipients: List[str]) -> Dict[str, Any]:
        """Encrypt data for recipients"""
        if not recipients:
            return {'success': False, 'error': 'No recipients specified'}

        # Validate all recipient fingerprints
        for recipient in recipients:
            if not self._validate_fingerprint(recipient):
                return {'success': False, 'error': f'Invalid recipient fingerprint: {recipient}'}

        try:
            # Update key usage for all recipients
            for recipient in recipients:
                self._log_key_usage(recipient, 'encrypt')

            # Encrypt the data
            encrypt_result = self.gpg.encrypt(data, recipients)

            if not encrypt_result.ok:
                return {'success': False, 'error': f'Failed to encrypt data: {encrypt_result.stderr}'}

            return {
                'success': True,
                'encrypted_data': str(encrypt_result),
                'recipients': recipients
            }

        except Exception as e:
            logger.error(f"Error encrypting data: {e}")
            return {'success': False, 'error': f'Encryption failed: {e}'}

    def _log_key_usage(self, fingerprint: str, operation: str, success: bool = True,
                      error_message: Optional[str] = None):
        """Log key usage in database"""
        try:
            with self._get_db_session() as session:
                # Update usage count in GPGKey
                key = session.query(GPGKey).filter_by(fingerprint=fingerprint).first()
                if key:
                    key.usage_count = (key.usage_count or 0) + 1
                    key.last_used_at = datetime.utcnow()

                # Create usage log entry
                usage_log = UsageLog(
                    fingerprint=fingerprint,
                    operation=operation,
                    user='server',  # Server operations
                    success=success,
                    error_message=error_message
                )
                session.add(usage_log)

        except Exception as e:
            logger.error(f"Error logging key usage: {e}")

    def get_key_usage_stats(self, fingerprint: Optional[str] = None,
                           days: int = 30) -> Dict[str, Any]:
        """Get key usage statistics"""
        try:
            start_date = datetime.utcnow() - timedelta(days=days)

            with self._get_db_session() as session:
                query = session.query(UsageLog).filter(
                    UsageLog.timestamp >= start_date
                )

                if fingerprint:
                    query = query.filter_by(fingerprint=fingerprint)

                usage_logs = query.all()

                # Calculate statistics
                total_operations = len(usage_logs)
                successful_operations = len([log for log in usage_logs if log.success])
                error_operations = total_operations - successful_operations

                # Group by operation
                operation_stats = {}
                for log in usage_logs:
                    operation = log.operation
                    if operation not in operation_stats:
                        operation_stats[operation] = {'count': 0, 'errors': 0}
                    operation_stats[operation]['count'] += 1
                    if not log.success:
                        operation_stats[operation]['errors'] += 1

                return {
                    'period_days': days,
                    'total_operations': total_operations,
                    'successful_operations': successful_operations,
                    'error_operations': error_operations,
                    'success_rate': (successful_operations / total_operations * 100) if total_operations > 0 else 0,
                    'operation_stats': operation_stats
                }

        except Exception as e:
            logger.error(f"Error getting usage statistics: {e}")
            return {}

    def cleanup_expired_keys(self) -> int:
        """Mark expired keys as expired"""
        try:
            with self._get_db_session() as session:
                now = datetime.utcnow()
                expired_keys = session.query(GPGKey).filter(
                    and_(
                        GPGKey.expires_at <= now,
                        GPGKey.is_expired == False,
                        GPGKey.is_active == True
                    )
                ).all()

                count = 0
                for key in expired_keys:
                    key.is_expired = True
                    key.updated_at = now
                    count += 1

                if count > 0:
                    logger.info(f"Marked {count} keys as expired")

                return count

        except Exception as e:
            logger.error(f"Error cleaning up expired keys: {e}")
            return 0