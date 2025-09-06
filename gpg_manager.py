import gnupg
import os
import logging
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from models import GPGKey, UsageLog, get_session
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GPGManager:
    """Manages GPG keys and operations with database integration"""
    
    def __init__(self, gpg_home: Optional[str] = None):
        """Initialize GPG manager"""
        self.gpg_home = gpg_home or os.getenv('GPG_HOME', os.path.expanduser('~/.gnupg'))
        self.gpg = gnupg.GPG(gnupghome=self.gpg_home)
        logger.info(f"Initialized GPG manager with home: {self.gpg_home}")
    
    def add_key(self, key_file: str, owner: str, requester: str, 
                jira_ticket: Optional[str] = None, notes: Optional[str] = None) -> bool:
        """Add a GPG key to the keyring and database"""
        try:
            # Import the key
            with open(key_file, 'rb') as f:
                import_result = self.gpg.import_keys(f.read())
            
            if not import_result.imported:
                logger.error(f"Failed to import key from {key_file}")
                return False
            
            # Get key information
            key_data = self.gpg.list_keys(keys=import_result.fingerprints[0])[0]
            
            # Store in database
            session = get_session()
            try:
                gpg_key = GPGKey(
                    fingerprint=key_data['fingerprint'],
                    key_id=key_data['keyid'],
                    user_id=key_data['uids'][0] if key_data['uids'] else '',
                    email=self._extract_email(key_data['uids'][0]) if key_data['uids'] else None,
                    name=self._extract_name(key_data['uids'][0]) if key_data['uids'] else None,
                    owner=owner,
                    requester=requester,
                    jira_ticket=jira_ticket,
                    notes=notes
                )
                session.add(gpg_key)
                session.commit()
                logger.info(f"Successfully added key {key_data['fingerprint']} for owner {owner}")
                return True
            except Exception as e:
                session.rollback()
                logger.error(f"Database error: {e}")
                return False
            finally:
                session.close()
                
        except Exception as e:
            logger.error(f"Error adding key: {e}")
            return False
    
    def delete_key(self, fingerprint: str) -> bool:
        """Delete a GPG key from keyring and database"""
        try:
            # Remove from GPG keyring
            delete_result = self.gpg.delete_keys(fingerprint, secret=True)
            if not delete_result:
                logger.error(f"Failed to delete key {fingerprint} from keyring")
                return False
            
            # Remove from database
            session = get_session()
            try:
                key = session.query(GPGKey).filter_by(fingerprint=fingerprint).first()
                if key:
                    session.delete(key)
                    session.commit()
                    logger.info(f"Successfully deleted key {fingerprint}")
                    return True
                else:
                    logger.warning(f"Key {fingerprint} not found in database")
                    return False
            except Exception as e:
                session.rollback()
                logger.error(f"Database error: {e}")
                return False
            finally:
                session.close()
                
        except Exception as e:
            logger.error(f"Error deleting key: {e}")
            return False
    
    def edit_key(self, fingerprint: str, **kwargs) -> bool:
        """Edit key metadata in database"""
        session = get_session()
        try:
            key = session.query(GPGKey).filter_by(fingerprint=fingerprint).first()
            if not key:
                logger.error(f"Key {fingerprint} not found")
                return False
            
            # Update allowed fields
            allowed_fields = ['owner', 'requester', 'jira_ticket', 'notes', 'is_active']
            for field, value in kwargs.items():
                if field in allowed_fields and hasattr(key, field):
                    setattr(key, field, value)
            
            key.updated_at = datetime.utcnow()
            session.commit()
            logger.info(f"Successfully updated key {fingerprint}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Error updating key: {e}")
            return False
        finally:
            session.close()
    
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
        try:
            # Get old key info
            old_key_info = self.get_key_by_fingerprint(old_fingerprint)
            if not old_key_info:
                logger.error(f"Old key {old_fingerprint} not found")
                return False
            
            # Import new key
            with open(new_key_file, 'rb') as f:
                import_result = self.gpg.import_keys(f.read())
            
            if not import_result.imported:
                logger.error(f"Failed to import new key from {new_key_file}")
                return False
            
            # Get new key information
            new_key_data = self.gpg.list_keys(keys=import_result.fingerprints[0])[0]
            new_fingerprint = new_key_data['fingerprint']
            
            # Deactivate old key
            self.deactivate_key(old_fingerprint)
            
            # Add new key with old key's metadata (or new if provided)
            session = get_session()
            try:
                gpg_key = GPGKey(
                    fingerprint=new_fingerprint,
                    key_id=new_key_data['keyid'],
                    user_id=new_key_data['uids'][0] if new_key_data['uids'] else '',
                    email=self._extract_email(new_key_data['uids'][0]) if new_key_data['uids'] else None,
                    name=self._extract_name(new_key_data['uids'][0]) if new_key_data['uids'] else None,
                    owner=owner or old_key_info['owner'],
                    requester=requester or old_key_info['requester'],
                    jira_ticket=jira_ticket or old_key_info['jira_ticket'],
                    notes=notes or f"Replaced key {old_fingerprint}"
                )
                session.add(gpg_key)
                session.commit()
                
                # Optionally delete old key from keyring
                if delete_old:
                    self.gpg.delete_keys(old_fingerprint, secret=True)
                    logger.info(f"Deleted old key {old_fingerprint} from keyring")
                
                logger.info(f"Successfully replaced key {old_fingerprint} with {new_fingerprint}")
                return True
                
            except Exception as e:
                session.rollback()
                logger.error(f"Database error during key replacement: {e}")
                return False
            finally:
                session.close()
                
        except Exception as e:
            logger.error(f"Error replacing key: {e}")
            return False
    
    def list_keys(self, include_inactive: bool = False) -> List[Dict]:
        """List all keys with metadata"""
        session = get_session()
        try:
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
                    'is_active': key.is_active,
                    'notes': key.notes
                }
                for key in keys
            ]
        finally:
            session.close()
    
    def get_key_by_fingerprint(self, fingerprint: str) -> Optional[Dict]:
        """Get key metadata by fingerprint"""
        session = get_session()
        try:
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
                    'notes': key.notes
                }
            return None
        finally:
            session.close()
    
    def log_usage(self, fingerprint: str, operation: str, user: str, 
                  file_path: Optional[str] = None, recipient: Optional[str] = None,
                  success: bool = True, error_message: Optional[str] = None):
        """Log GPG key usage"""
        session = get_session()
        try:
            log_entry = UsageLog(
                fingerprint=fingerprint,
                operation=operation,
                user=user,
                file_path=file_path,
                recipient=recipient,
                success=success,
                error_message=error_message
            )
            session.add(log_entry)
            session.commit()
            logger.info(f"Logged {operation} operation for key {fingerprint} by user {user}")
        except Exception as e:
            session.rollback()
            logger.error(f"Error logging usage: {e}")
        finally:
            session.close()
    
    def get_usage_logs(self, fingerprint: Optional[str] = None, 
                      limit: int = 100) -> List[Dict]:
        """Get usage logs, optionally filtered by fingerprint"""
        session = get_session()
        try:
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
        finally:
            session.close()
    
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
