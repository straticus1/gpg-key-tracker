#!/usr/bin/env python3
"""
API Key Management System for GPG Key Server
"""

import os
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from contextlib import contextmanager
import json

from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy import and_, or_

import sys
import os
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)
sys.path.append(os.path.join(parent_dir, 'lib'))

from lib.models import APIKey, APIKeyUsage, get_session
from lib.config import get_config

logger = logging.getLogger(__name__)


class APIKeyManager:
    """Manages API keys for GPG Key Server"""

    def __init__(self, config=None):
        """Initialize API key manager"""
        self.config = config or get_config()

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

    def _generate_api_key(self) -> str:
        """Generate a cryptographically secure API key"""
        # Generate 32 bytes of random data and encode as hex
        return secrets.token_hex(32)

    def _hash_api_key(self, api_key: str) -> str:
        """Create SHA-256 hash of API key for storage"""
        return hashlib.sha256(api_key.encode()).hexdigest()

    def _validate_permissions(self, permissions: Dict[str, Any]) -> bool:
        """Validate permissions structure"""
        required_fields = ['operations', 'keys']
        valid_operations = ['read', 'list', 'sign', 'encrypt', 'info', 'search', 'admin']

        if not isinstance(permissions, dict):
            return False

        for field in required_fields:
            if field not in permissions:
                return False

        # Validate operations
        operations = permissions.get('operations', [])
        if not isinstance(operations, list):
            return False

        for op in operations:
            if op not in valid_operations:
                return False

        # Validate keys (can be "*" for all keys or list of fingerprints)
        keys = permissions.get('keys')
        if keys != "*" and not isinstance(keys, list):
            return False

        return True

    def create_api_key(self, name: str, owner: str, permissions: Dict[str, Any],
                      expires_days: Optional[int] = None, rate_limit: int = 100,
                      notes: Optional[str] = None) -> Dict[str, Any]:
        """Create a new API key"""
        try:
            # Validate inputs
            if not name or not owner:
                raise ValueError("Name and owner are required")

            if not self._validate_permissions(permissions):
                raise ValueError("Invalid permissions structure")

            # Generate API key
            api_key = self._generate_api_key()
            key_hash = self._hash_api_key(api_key)

            # Calculate expiration
            expires_at = None
            if expires_days:
                expires_at = datetime.utcnow() + timedelta(days=expires_days)

            with self._get_db_session() as session:
                # Check for duplicate name for the same owner
                existing = session.query(APIKey).filter_by(
                    name=name, owner=owner, is_active=True
                ).first()
                if existing:
                    raise ValueError(f"API key with name '{name}' already exists for owner '{owner}'")

                # Create new API key record
                new_key = APIKey(
                    key_hash=key_hash,
                    name=name,
                    owner=owner,
                    permissions=permissions,
                    expires_at=expires_at,
                    rate_limit=rate_limit,
                    notes=notes
                )

                session.add(new_key)
                session.flush()  # Get the ID

                logger.info(f"Created API key '{name}' for owner '{owner}' with ID {new_key.id}")

                return {
                    'id': new_key.id,
                    'api_key': api_key,  # Return the actual key only during creation
                    'name': name,
                    'owner': owner,
                    'permissions': permissions,
                    'expires_at': expires_at,
                    'rate_limit': rate_limit,
                    'created_at': new_key.created_at,
                    'notes': notes
                }

        except (SQLAlchemyError, IntegrityError) as e:
            logger.error(f"Database error creating API key: {e}")
            raise
        except Exception as e:
            logger.error(f"Error creating API key: {e}")
            raise

    def authenticate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Authenticate and return API key information"""
        try:
            key_hash = self._hash_api_key(api_key)

            with self._get_db_session() as session:
                key_record = session.query(APIKey).filter_by(
                    key_hash=key_hash, is_active=True
                ).first()

                if not key_record:
                    return None

                # Check expiration
                if key_record.expires_at and key_record.expires_at < datetime.utcnow():
                    logger.warning(f"Expired API key used: {key_record.name}")
                    return None

                # Update last used timestamp
                key_record.last_used_at = datetime.utcnow()

                return {
                    'id': key_record.id,
                    'name': key_record.name,
                    'owner': key_record.owner,
                    'permissions': key_record.permissions,
                    'rate_limit': key_record.rate_limit,
                    'last_used_at': key_record.last_used_at
                }

        except Exception as e:
            logger.error(f"Error authenticating API key: {e}")
            return None

    def check_permission(self, api_key_info: Dict[str, Any], operation: str,
                        key_fingerprint: Optional[str] = None) -> bool:
        """Check if API key has permission for operation"""
        try:
            permissions = api_key_info.get('permissions', {})
            allowed_operations = permissions.get('operations', [])
            allowed_keys = permissions.get('keys', [])

            # Check operation permission
            if operation not in allowed_operations:
                return False

            # Check key access permission
            if key_fingerprint:
                if allowed_keys != "*" and key_fingerprint not in allowed_keys:
                    return False

            return True

        except Exception as e:
            logger.error(f"Error checking permission: {e}")
            return False

    def list_api_keys(self, owner: Optional[str] = None, include_inactive: bool = False) -> List[Dict[str, Any]]:
        """List API keys"""
        try:
            with self._get_db_session() as session:
                query = session.query(APIKey)

                if owner:
                    query = query.filter_by(owner=owner)

                if not include_inactive:
                    query = query.filter_by(is_active=True)

                keys = query.order_by(APIKey.created_at.desc()).all()

                return [
                    {
                        'id': key.id,
                        'name': key.name,
                        'owner': key.owner,
                        'permissions': key.permissions,
                        'created_at': key.created_at,
                        'expires_at': key.expires_at,
                        'last_used_at': key.last_used_at,
                        'is_active': key.is_active,
                        'rate_limit': key.rate_limit,
                        'notes': key.notes
                    }
                    for key in keys
                ]

        except Exception as e:
            logger.error(f"Error listing API keys: {e}")
            return []

    def get_api_key(self, key_id: int) -> Optional[Dict[str, Any]]:
        """Get API key by ID"""
        try:
            with self._get_db_session() as session:
                key = session.query(APIKey).filter_by(id=key_id).first()

                if not key:
                    return None

                return {
                    'id': key.id,
                    'name': key.name,
                    'owner': key.owner,
                    'permissions': key.permissions,
                    'created_at': key.created_at,
                    'expires_at': key.expires_at,
                    'last_used_at': key.last_used_at,
                    'is_active': key.is_active,
                    'rate_limit': key.rate_limit,
                    'notes': key.notes
                }

        except Exception as e:
            logger.error(f"Error getting API key {key_id}: {e}")
            return None

    def update_api_key(self, key_id: int, **kwargs) -> bool:
        """Update API key properties"""
        try:
            allowed_fields = ['name', 'permissions', 'expires_at', 'rate_limit', 'notes', 'is_active']

            with self._get_db_session() as session:
                key = session.query(APIKey).filter_by(id=key_id).first()

                if not key:
                    logger.error(f"API key {key_id} not found")
                    return False

                # Update allowed fields
                updated = False
                for field, value in kwargs.items():
                    if field in allowed_fields and hasattr(key, field):
                        if field == 'permissions' and not self._validate_permissions(value):
                            raise ValueError("Invalid permissions structure")
                        setattr(key, field, value)
                        updated = True

                if updated:
                    logger.info(f"Updated API key {key_id}")
                    return True
                else:
                    return False

        except (SQLAlchemyError, IntegrityError) as e:
            logger.error(f"Database error updating API key {key_id}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error updating API key {key_id}: {e}")
            return False

    def delete_api_key(self, key_id: int, soft_delete: bool = True) -> bool:
        """Delete API key (soft or hard delete)"""
        try:
            with self._get_db_session() as session:
                key = session.query(APIKey).filter_by(id=key_id).first()

                if not key:
                    logger.error(f"API key {key_id} not found")
                    return False

                if soft_delete:
                    # Soft delete - just deactivate
                    key.is_active = False
                    logger.info(f"Soft deleted API key {key_id}")
                else:
                    # Hard delete - remove from database
                    session.delete(key)
                    logger.info(f"Hard deleted API key {key_id}")

                return True

        except (SQLAlchemyError, IntegrityError) as e:
            logger.error(f"Database error deleting API key {key_id}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error deleting API key {key_id}: {e}")
            return False

    def log_api_usage(self, api_key_id: int, endpoint: str, method: str,
                     response_status: int, ip_address: Optional[str] = None,
                     user_agent: Optional[str] = None, response_time_ms: Optional[int] = None,
                     request_size: Optional[int] = None, response_size: Optional[int] = None) -> bool:
        """Log API key usage"""
        try:
            with self._get_db_session() as session:
                usage_log = APIKeyUsage(
                    api_key_id=api_key_id,
                    endpoint=endpoint,
                    method=method,
                    response_status=response_status,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    response_time_ms=response_time_ms,
                    request_size=request_size,
                    response_size=response_size
                )
                session.add(usage_log)
                return True

        except Exception as e:
            logger.error(f"Error logging API usage: {e}")
            return False

    def get_api_usage_stats(self, api_key_id: Optional[int] = None,
                           days: int = 30) -> Dict[str, Any]:
        """Get API usage statistics"""
        try:
            start_date = datetime.utcnow() - timedelta(days=days)

            with self._get_db_session() as session:
                query = session.query(APIKeyUsage).filter(
                    APIKeyUsage.timestamp >= start_date
                )

                if api_key_id:
                    query = query.filter_by(api_key_id=api_key_id)

                usage_logs = query.all()

                # Calculate statistics
                total_requests = len(usage_logs)
                successful_requests = len([log for log in usage_logs if 200 <= log.response_status < 300])
                error_requests = total_requests - successful_requests

                # Group by endpoint
                endpoint_stats = {}
                for log in usage_logs:
                    endpoint = log.endpoint
                    if endpoint not in endpoint_stats:
                        endpoint_stats[endpoint] = {'count': 0, 'errors': 0}
                    endpoint_stats[endpoint]['count'] += 1
                    if log.response_status >= 400:
                        endpoint_stats[endpoint]['errors'] += 1

                # Group by API key
                api_key_stats = {}
                for log in usage_logs:
                    key_id = log.api_key_id
                    if key_id not in api_key_stats:
                        api_key_stats[key_id] = {'count': 0, 'errors': 0}
                    api_key_stats[key_id]['count'] += 1
                    if log.response_status >= 400:
                        api_key_stats[key_id]['errors'] += 1

                return {
                    'period_days': days,
                    'total_requests': total_requests,
                    'successful_requests': successful_requests,
                    'error_requests': error_requests,
                    'success_rate': (successful_requests / total_requests * 100) if total_requests > 0 else 0,
                    'endpoint_stats': endpoint_stats,
                    'api_key_stats': api_key_stats
                }

        except Exception as e:
            logger.error(f"Error getting API usage stats: {e}")
            return {}

    def cleanup_expired_keys(self) -> int:
        """Cleanup expired API keys"""
        try:
            with self._get_db_session() as session:
                expired_keys = session.query(APIKey).filter(
                    and_(
                        APIKey.expires_at <= datetime.utcnow(),
                        APIKey.is_active == True
                    )
                ).all()

                count = 0
                for key in expired_keys:
                    key.is_active = False
                    count += 1

                if count > 0:
                    logger.info(f"Deactivated {count} expired API keys")

                return count

        except Exception as e:
            logger.error(f"Error cleaning up expired keys: {e}")
            return 0

    def rotate_api_key(self, key_id: int) -> Optional[str]:
        """Rotate an existing API key (generate new key, keep metadata)"""
        try:
            new_api_key = self._generate_api_key()
            new_key_hash = self._hash_api_key(new_api_key)

            with self._get_db_session() as session:
                key = session.query(APIKey).filter_by(id=key_id).first()

                if not key:
                    logger.error(f"API key {key_id} not found for rotation")
                    return None

                # Update with new hash
                key.key_hash = new_key_hash
                key.last_used_at = None  # Reset usage timestamp

                logger.info(f"Rotated API key {key_id}")
                return new_api_key

        except Exception as e:
            logger.error(f"Error rotating API key {key_id}: {e}")
            return None


# Utility functions for CLI
def create_default_permissions(operations: List[str], keys: Union[str, List[str]] = "*") -> Dict[str, Any]:
    """Create a default permissions structure"""
    return {
        'operations': operations,
        'keys': keys,
        'rate_limit': 100
    }


def validate_api_key_format(api_key: str) -> bool:
    """Validate API key format"""
    # API keys should be 64 character hex strings
    if len(api_key) != 64:
        return False

    try:
        int(api_key, 16)  # Check if it's valid hex
        return True
    except ValueError:
        return False


if __name__ == '__main__':
    # Test API key management
    manager = APIKeyManager()

    # Test permissions
    permissions = create_default_permissions(['read', 'list'], '*')
    print(f"Default permissions: {permissions}")
    print(f"Valid permissions: {manager._validate_permissions(permissions)}")

    # Test key generation
    api_key = manager._generate_api_key()
    print(f"Generated API key: {api_key}")
    print(f"Valid format: {validate_api_key_format(api_key)}")