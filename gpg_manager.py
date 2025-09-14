import gnupg
import os
import re
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Union
from contextlib import contextmanager
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy import and_, or_
from models import GPGKey, UsageLog, get_session
from config import get_config
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GPGManager:
    """Manages GPG keys and operations with database integration"""

    def __init__(self, gpg_home: Optional[str] = None, config=None):
        """Initialize GPG manager"""
        self.config = config or get_config()
        self.gpg_home = gpg_home or self.config.gpg.home
        self.gpg = gnupg.GPG(gnupghome=self.gpg_home)
        logger.info(f"Initialized GPG manager with home: {self.gpg_home}")
    
    def add_key(self, key_file: str, owner: str, requester: str,
                jira_ticket: Optional[str] = None, notes: Optional[str] = None) -> bool:
        """Add a GPG key to the keyring and database"""
        # Validate and sanitize inputs
        if not os.path.exists(key_file) or not os.path.isfile(key_file):
            logger.error(f"Key file does not exist or is not a file: {key_file}")
            return False

        owner = self._sanitize_input(owner)
        requester = self._sanitize_input(requester)
        jira_ticket = self._sanitize_input(jira_ticket) if jira_ticket else None
        notes = self._sanitize_input(notes, max_length=1000) if notes else None

        if not owner or not requester:
            logger.error("Owner and requester are required and cannot be empty")
            return False

        try:
            # Validate file size (prevent DoS)
            file_size = os.path.getsize(key_file)
            if file_size > self.config.gpg.max_key_size:
                logger.error(f"Key file too large: {file_size} bytes (max {self.config.gpg.max_key_size})")
                return False

            # Import the key
            with open(key_file, 'rb') as f:
                key_data = f.read()
                # Basic validation of key format
                if not (b'-----BEGIN PGP' in key_data and b'-----END PGP' in key_data):
                    logger.error("Invalid GPG key format")
                    return False
                import_result = self.gpg.import_keys(key_data)
            
            if not import_result.imported:
                logger.error(f"Failed to import key from {key_file}")
                return False
            
            # Get key information
            key_data = self.gpg.list_keys(keys=import_result.fingerprints[0])[0]
            
            # Validate fingerprint
            fingerprint = key_data['fingerprint']
            if not self._validate_fingerprint(fingerprint):
                logger.error(f"Invalid fingerprint format: {fingerprint}")
                return False

            # Get key expiration date from GPG
            key_expiry = self._get_key_expiry_date(fingerprint)

            # Check for duplicate key
            with self._get_db_session() as session:
                existing_key = session.query(GPGKey).filter_by(fingerprint=fingerprint).first()
                if existing_key:
                    logger.error(f"Key with fingerprint {fingerprint} already exists")
                    return False

                # Extract and validate email if present
                extracted_email = None
                if key_data['uids']:
                    extracted_email = self._extract_email(key_data['uids'][0])
                    if extracted_email and not self._validate_email(extracted_email):
                        logger.warning(f"Invalid email format in key UID: {extracted_email}")
                        extracted_email = None

                gpg_key = GPGKey(
                    fingerprint=fingerprint,
                    key_id=key_data['keyid'],
                    user_id=key_data['uids'][0][:255] if key_data['uids'] else '',
                    email=extracted_email,
                    name=self._extract_name(key_data['uids'][0])[:255] if key_data['uids'] else None,
                    owner=owner,
                    requester=requester,
                    jira_ticket=jira_ticket,
                    notes=notes,
                    expires_at=key_expiry,
                    is_expired=key_expiry and key_expiry < datetime.utcnow() if key_expiry else False
                )
                session.add(gpg_key)
                logger.info(f"Successfully added key {fingerprint} for owner {owner}")
                return True
                
        except (OSError, IOError) as e:
            logger.error(f"File I/O error while adding key: {e}")
            return False
        except gnupg.GPGError as e:
            logger.error(f"GPG error while adding key: {e}")
            return False
        except (SQLAlchemyError, IntegrityError) as e:
            logger.error(f"Database error while adding key: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error adding key: {e}")
            return False
    
    def delete_key(self, fingerprint: str) -> bool:
        """Delete a GPG key from keyring and database"""
        if not self._validate_fingerprint(fingerprint):
            logger.error(f"Invalid fingerprint format: {fingerprint}")
            return False

        try:
            # First try to delete secret key if it exists
            secret_delete_result = self.gpg.delete_keys(fingerprint, secret=True)

            # Then delete public key (this will work even if no secret key exists)
            public_delete_result = self.gpg.delete_keys(fingerprint, secret=False)

            # Consider successful if either deletion worked
            if not (secret_delete_result or public_delete_result):
                logger.error(f"Failed to delete key {fingerprint} from keyring")
                return False
            
            # Remove from database
            with self._get_db_session() as session:
                key = session.query(GPGKey).filter_by(fingerprint=fingerprint).first()
                if key:
                    session.delete(key)
                    logger.info(f"Successfully deleted key {fingerprint}")
                    return True
                else:
                    logger.warning(f"Key {fingerprint} not found in database")
                    return False
                
        except gnupg.GPGError as e:
            logger.error(f"GPG error while deleting key {fingerprint}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error deleting key {fingerprint}: {e}")
            return False
    
    def edit_key(self, fingerprint: str, **kwargs) -> bool:
        """Edit key metadata in database"""
        if not self._validate_fingerprint(fingerprint):
            logger.error(f"Invalid fingerprint format: {fingerprint}")
            return False

        try:
            with self._get_db_session() as session:
                key = session.query(GPGKey).filter_by(fingerprint=fingerprint).first()
                if not key:
                    logger.error(f"Key {fingerprint} not found")
                    return False

                # Update allowed fields with sanitization
                allowed_fields = ['owner', 'requester', 'jira_ticket', 'notes', 'is_active']
                for field, value in kwargs.items():
                    if field in allowed_fields and hasattr(key, field):
                        if field in ['owner', 'requester', 'jira_ticket', 'notes'] and value:
                            max_len = 1000 if field == 'notes' else 255
                            value = self._sanitize_input(str(value), max_len)
                        setattr(key, field, value)

                key.updated_at = datetime.utcnow()
                logger.info(f"Successfully updated key {fingerprint}")
                return True

        except (SQLAlchemyError, IntegrityError) as e:
            logger.error(f"Database error updating key {fingerprint}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error updating key {fingerprint}: {e}")
            return False
    
    def activate_key(self, fingerprint: str) -> bool:
        """Activate a deactivated key"""
        return self.edit_key(fingerprint, is_active=True)
    
    def deactivate_key(self, fingerprint: str) -> bool:
        """Deactivate an active key"""
        return self.edit_key(fingerprint, is_active=False)
    
    def replace_key(self, old_fingerprint: str, new_key_file: str,
                   owner: Optional[str] = None, requester: Optional[str] = None,
                   jira_ticket: Optional[str] = None, notes: Optional[str] = None,
                   delete_old: bool = False) -> bool:
        """Replace an existing key with a new one"""
        if not self._validate_fingerprint(old_fingerprint):
            logger.error(f"Invalid old fingerprint format: {old_fingerprint}")
            return False

        if not os.path.exists(new_key_file) or not os.path.isfile(new_key_file):
            logger.error(f"New key file does not exist: {new_key_file}")
            return False

        # Sanitize inputs
        owner = self._sanitize_input(owner) if owner else None
        requester = self._sanitize_input(requester) if requester else None
        jira_ticket = self._sanitize_input(jira_ticket) if jira_ticket else None
        notes = self._sanitize_input(notes, 1000) if notes else None

        try:
            # Get old key info
            old_key_info = self.get_key_by_fingerprint(old_fingerprint)
            if not old_key_info:
                logger.error(f"Old key {old_fingerprint} not found")
                return False

            # Validate file size
            file_size = os.path.getsize(new_key_file)
            if file_size > 1024 * 1024:  # 1MB limit
                logger.error(f"New key file too large: {file_size} bytes (max 1MB)")
                return False

            # Import new key
            with open(new_key_file, 'rb') as f:
                key_data = f.read()
                if not (b'-----BEGIN PGP' in key_data and b'-----END PGP' in key_data):
                    logger.error("Invalid GPG key format in new key file")
                    return False
                import_result = self.gpg.import_keys(key_data)

            if not import_result.imported:
                logger.error(f"Failed to import new key from {new_key_file}")
                return False

            # Get new key information
            new_key_data = self.gpg.list_keys(keys=import_result.fingerprints[0])[0]
            new_fingerprint = new_key_data['fingerprint']

            if not self._validate_fingerprint(new_fingerprint):
                logger.error(f"Invalid new fingerprint format: {new_fingerprint}")
                return False

            # Deactivate old key
            if not self.deactivate_key(old_fingerprint):
                logger.warning(f"Failed to deactivate old key {old_fingerprint}")

            # Add new key with old key's metadata (or new if provided)
            try:
                with self._get_db_session() as session:
                    # Check if new key already exists
                    existing_key = session.query(GPGKey).filter_by(fingerprint=new_fingerprint).first()
                    if existing_key:
                        logger.error(f"New key with fingerprint {new_fingerprint} already exists")
                        return False

                    # Extract and validate email
                    extracted_email = None
                    if new_key_data['uids']:
                        extracted_email = self._extract_email(new_key_data['uids'][0])
                        if extracted_email and not self._validate_email(extracted_email):
                            logger.warning(f"Invalid email in new key UID: {extracted_email}")
                            extracted_email = None

                    gpg_key = GPGKey(
                        fingerprint=new_fingerprint,
                        key_id=new_key_data['keyid'],
                        user_id=new_key_data['uids'][0][:255] if new_key_data['uids'] else '',
                        email=extracted_email,
                        name=self._extract_name(new_key_data['uids'][0])[:255] if new_key_data['uids'] else None,
                        owner=owner or old_key_info['owner'],
                        requester=requester or old_key_info['requester'],
                        jira_ticket=jira_ticket or old_key_info['jira_ticket'],
                        notes=notes or f"Replaced key {old_fingerprint[:16]}..."
                    )
                    session.add(gpg_key)

                    # Optionally delete old key from keyring
                    if delete_old:
                        try:
                            self.gpg.delete_keys(old_fingerprint, secret=True)
                            self.gpg.delete_keys(old_fingerprint, secret=False)
                            logger.info(f"Deleted old key {old_fingerprint} from keyring")
                        except Exception as e:
                            logger.warning(f"Failed to delete old key from keyring: {e}")

                    logger.info(f"Successfully replaced key {old_fingerprint[:16]}... with {new_fingerprint[:16]}...")
                    return True

            except (SQLAlchemyError, IntegrityError) as e:
                logger.error(f"Database error during key replacement: {e}")
                return False

        except (OSError, IOError) as e:
            logger.error(f"File I/O error during key replacement: {e}")
            return False
        except gnupg.GPGError as e:
            logger.error(f"GPG error during key replacement: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error replacing key: {e}")
            return False
    
    def list_keys(self, include_inactive: bool = False) -> List[Dict]:
        """List all keys with metadata"""
        try:
            with self._get_db_session() as session:
                query = session.query(GPGKey)
                if not include_inactive:
                    query = query.filter_by(is_active=True)

                keys = query.all()
                return [
                    {
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
                        'usage_count': key.usage_count or 0,
                        'is_active': key.is_active,
                        'is_expired': key.is_expired,
                        'notes': key.notes
                    }
                    for key in keys
                ]
        except (SQLAlchemyError, IntegrityError) as e:
            logger.error(f"Database error listing keys: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing keys: {e}")
            return []
    
    def get_key_by_fingerprint(self, fingerprint: str) -> Optional[Dict]:
        """Get key metadata by fingerprint"""
        if not self._validate_fingerprint(fingerprint):
            logger.error(f"Invalid fingerprint format: {fingerprint}")
            return None

        try:
            with self._get_db_session() as session:
                key = session.query(GPGKey).filter_by(fingerprint=fingerprint).first()
                if key:
                    return {
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
                        'usage_count': key.usage_count or 0,
                        'is_active': key.is_active,
                        'is_expired': key.is_expired,
                        'notes': key.notes
                    }
                return None
        except (SQLAlchemyError, IntegrityError) as e:
            logger.error(f"Database error getting key {fingerprint}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting key {fingerprint}: {e}")
            return None
    
    def log_usage(self, fingerprint: str, operation: str, user: str,
                  file_path: Optional[str] = None, recipient: Optional[str] = None,
                  success: bool = True, error_message: Optional[str] = None) -> bool:
        """Log GPG key usage"""
        if not self._validate_fingerprint(fingerprint):
            logger.error(f"Invalid fingerprint format for logging: {fingerprint}")
            return False

        # Validate and sanitize inputs
        if operation not in self.config.gpg.valid_operations:
            logger.error(f"Invalid operation type: {operation}")
            return False

        user = self._sanitize_input(user)
        if not user:
            logger.error("User is required for usage logging")
            return False

        try:
            with self._get_db_session() as session:
                log_entry = UsageLog(
                    fingerprint=fingerprint,
                    operation=operation,
                    user=user,
                    file_path=self._sanitize_input(file_path, 500) if file_path else None,
                    recipient=self._sanitize_input(recipient) if recipient else None,
                    success=success,
                    error_message=self._sanitize_input(error_message, 1000) if error_message else None
                )
                session.add(log_entry)

                # Update key usage statistics if operation was successful
                if success:
                    key = session.query(GPGKey).filter_by(fingerprint=fingerprint).first()
                    if key:
                        key.last_used_at = datetime.utcnow()
                        key.usage_count = (key.usage_count or 0) + 1
                        key.updated_at = datetime.utcnow()

                logger.info(f"Logged {operation} operation for key {fingerprint[:16]}... by user {user}")
                return True
        except (SQLAlchemyError, IntegrityError) as e:
            logger.error(f"Database error logging usage: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error logging usage: {e}")
            return False
    
    def get_usage_logs(self, fingerprint: Optional[str] = None,
                      limit: int = 100) -> List[Dict]:
        """Get usage logs, optionally filtered by fingerprint"""
        if fingerprint and not self._validate_fingerprint(fingerprint):
            logger.error(f"Invalid fingerprint format for log query: {fingerprint}")
            return []

        # Validate limit to prevent resource exhaustion
        if limit <= 0 or limit > 10000:
            logger.warning(f"Invalid limit {limit}, using default 100")
            limit = 100

        try:
            with self._get_db_session() as session:
                query = session.query(UsageLog)
                if fingerprint:
                    query = query.filter_by(fingerprint=fingerprint)

                logs = query.order_by(UsageLog.timestamp.desc()).limit(limit).all()
                return [
                    {
                        'id': log.id,
                        'fingerprint': log.fingerprint,
                        'operation': log.operation,
                        'user': log.user,
                        'timestamp': log.timestamp,
                        'file_path': log.file_path,
                        'recipient': log.recipient,
                        'success': log.success,
                        'error_message': log.error_message
                    }
                    for log in logs
                ]
        except (SQLAlchemyError, IntegrityError) as e:
            logger.error(f"Database error getting usage logs: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error getting usage logs: {e}")
            return []

    def get_expiring_keys(self, days_ahead: int = 30) -> List[Dict]:
        """Get keys that will expire within the specified number of days"""
        try:
            with self._get_db_session() as session:
                future_date = datetime.utcnow() + timedelta(days=days_ahead)
                expiring_keys = session.query(GPGKey).filter(
                    and_(
                        GPGKey.is_active == True,
                        GPGKey.expires_at != None,
                        GPGKey.expires_at <= future_date,
                        GPGKey.expires_at > datetime.utcnow()  # Not already expired
                    )
                ).order_by(GPGKey.expires_at).all()

                return [
                    {
                        'fingerprint': key.fingerprint,
                        'key_id': key.key_id,
                        'owner': key.owner,
                        'email': key.email,
                        'expires_at': key.expires_at,
                        'days_until_expiry': (key.expires_at - datetime.utcnow()).days,
                        'last_used_at': key.last_used_at,
                        'usage_count': key.usage_count
                    }
                    for key in expiring_keys
                ]
        except (SQLAlchemyError, IntegrityError) as e:
            logger.error(f"Database error getting expiring keys: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error getting expiring keys: {e}")
            return []

    def get_expired_keys(self) -> List[Dict]:
        """Get keys that have already expired"""
        try:
            with self._get_db_session() as session:
                expired_keys = session.query(GPGKey).filter(
                    and_(
                        GPGKey.is_active == True,
                        GPGKey.expires_at != None,
                        GPGKey.expires_at <= datetime.utcnow()
                    )
                ).order_by(GPGKey.expires_at).all()

                return [
                    {
                        'fingerprint': key.fingerprint,
                        'key_id': key.key_id,
                        'owner': key.owner,
                        'email': key.email,
                        'expires_at': key.expires_at,
                        'days_since_expiry': (datetime.utcnow() - key.expires_at).days,
                        'last_used_at': key.last_used_at,
                        'usage_count': key.usage_count
                    }
                    for key in expired_keys
                ]
        except (SQLAlchemyError, IntegrityError) as e:
            logger.error(f"Database error getting expired keys: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error getting expired keys: {e}")
            return []

    def update_key_expiry_status(self) -> int:
        """Update the is_expired status for all keys based on current date"""
        try:
            updated_count = 0
            with self._get_db_session() as session:
                # Mark keys as expired if their expiry date has passed
                expired_keys = session.query(GPGKey).filter(
                    and_(
                        GPGKey.expires_at != None,
                        GPGKey.expires_at <= datetime.utcnow(),
                        GPGKey.is_expired == False
                    )
                ).all()

                for key in expired_keys:
                    key.is_expired = True
                    key.updated_at = datetime.utcnow()
                    updated_count += 1

                # Mark keys as not expired if their expiry date is in the future
                # (handles cases where keys were renewed)
                not_expired_keys = session.query(GPGKey).filter(
                    and_(
                        GPGKey.expires_at != None,
                        GPGKey.expires_at > datetime.utcnow(),
                        GPGKey.is_expired == True
                    )
                ).all()

                for key in not_expired_keys:
                    key.is_expired = False
                    key.updated_at = datetime.utcnow()
                    updated_count += 1

                if updated_count > 0:
                    logger.info(f"Updated expiry status for {updated_count} keys")

                return updated_count
        except (SQLAlchemyError, IntegrityError) as e:
            logger.error(f"Database error updating key expiry status: {e}")
            return 0
        except Exception as e:
            logger.error(f"Unexpected error updating key expiry status: {e}")
            return 0

    def refresh_key_expiry_dates(self) -> int:
        """Refresh expiry dates for all active keys from GPG keyring"""
        try:
            updated_count = 0
            with self._get_db_session() as session:
                active_keys = session.query(GPGKey).filter(GPGKey.is_active == True).all()

                for key in active_keys:
                    new_expiry = self._get_key_expiry_date(key.fingerprint)
                    if new_expiry != key.expires_at:
                        key.expires_at = new_expiry
                        key.is_expired = new_expiry and new_expiry < datetime.utcnow() if new_expiry else False
                        key.updated_at = datetime.utcnow()
                        updated_count += 1

                if updated_count > 0:
                    logger.info(f"Refreshed expiry dates for {updated_count} keys")

                return updated_count
        except (SQLAlchemyError, IntegrityError) as e:
            logger.error(f"Database error refreshing key expiry dates: {e}")
            return 0
        except Exception as e:
            logger.error(f"Unexpected error refreshing key expiry dates: {e}")
            return 0
    
    def _extract_email(self, user_id: str) -> Optional[str]:
        """Extract email from GPG user ID"""
        if '<' in user_id and '>' in user_id:
            start = user_id.find('<') + 1
            end = user_id.find('>')
            return user_id[start:end]
        return None
    
    def _extract_name(self, user_id: str) -> Optional[str]:
        """Extract name from GPG user ID"""
        if '<' in user_id:
            return user_id[:user_id.find('<')].strip()
        return user_id.strip()

    def _validate_fingerprint(self, fingerprint: str) -> bool:
        """Validate GPG key fingerprint format"""
        if not fingerprint or not isinstance(fingerprint, str):
            return False

        # GPG fingerprints are 40 hex characters (SHA-1) or 64 hex characters (SHA-256)
        pattern = r'^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$'
        return bool(re.match(pattern, fingerprint))

    def _validate_email(self, email: str) -> bool:
        """Validate email address format"""
        if not email or not isinstance(email, str):
            return False

        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    def _sanitize_input(self, value: str, max_length: int = 255) -> str:
        """Sanitize input string to prevent injection attacks"""
        if not value:
            return ""

        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\';\\]', '', str(value))
        return sanitized[:max_length].strip()

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

    def _get_key_expiry_date(self, fingerprint: str) -> Optional[datetime]:
        """Get key expiration date from GPG"""
        try:
            keys = self.gpg.list_keys(keys=fingerprint)
            if keys:
                key_info = keys[0]
                expires = key_info.get('expires')
                if expires and expires != '':
                    # GPG returns expiry as epoch timestamp string
                    return datetime.fromtimestamp(int(expires))
            return None
        except (ValueError, TypeError, IndexError) as e:
            logger.warning(f"Failed to get expiry date for key {fingerprint}: {e}")
            return None
