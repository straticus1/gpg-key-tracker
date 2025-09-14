#!/usr/bin/env python3
"""
Authentication middleware for GPG Key Server
"""

import logging
import sys
import os
from typing import Optional, Dict, Any, Callable, List
from datetime import datetime, timedelta
from fastapi import HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
import time

# Add paths for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)
sys.path.append(os.path.join(parent_dir, 'lib'))

from api_key_manager import APIKeyManager
from lib.config import get_config

logger = logging.getLogger(__name__)


class APIKeyAuth(HTTPBearer):
    """API Key authentication using HTTP Bearer or X-API-Key header"""

    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)
        self.api_key_manager = APIKeyManager()
        self.config = get_config()

        # Rate limiting storage (in-memory for simplicity)
        self.rate_limit_storage: Dict[str, List[float]] = {}

    async def __call__(self, request: Request) -> Optional[Dict[str, Any]]:
        """Authenticate API key from request"""
        # Skip authentication for certain endpoints
        if self._is_public_endpoint(request.url.path):
            return None

        api_key = self._extract_api_key(request)

        if not api_key:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="API key required",
                    headers={"WWW-Authenticate": "Bearer"}
                )
            return None

        # Authenticate API key
        api_key_info = self.api_key_manager.authenticate_api_key(api_key)
        if not api_key_info:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid API key",
                    headers={"WWW-Authenticate": "Bearer"}
                )
            return None

        # Check rate limiting
        if self.config.security.rate_limit_enabled:
            if not self._check_rate_limit(api_key_info):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded"
                )

        # Store in request state for use in endpoints
        request.state.api_key_info = api_key_info
        request.state.api_key = api_key

        return api_key_info

    def _extract_api_key(self, request: Request) -> Optional[str]:
        """Extract API key from request headers"""
        # Try X-API-Key header first
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return api_key.strip()

        # Try Authorization header with Bearer
        authorization = request.headers.get("Authorization")
        if authorization:
            try:
                scheme, token = authorization.split(" ", 1)
                if scheme.lower() == "bearer":
                    return token.strip()
            except ValueError:
                pass

        return None

    def _is_public_endpoint(self, path: str) -> bool:
        """Check if endpoint is public (no authentication required)"""
        public_endpoints = [
            "/",
            "/health",
            "/docs",
            "/openapi.json",
            "/redoc"
        ]
        return path in public_endpoints

    def _check_rate_limit(self, api_key_info: Dict[str, Any]) -> bool:
        """Check rate limiting for API key"""
        api_key_id = str(api_key_info['id'])
        rate_limit = api_key_info.get('rate_limit', self.config.api_keys.default_rate_limit)
        window_seconds = 60  # 1 minute window

        now = time.time()
        window_start = now - window_seconds

        # Clean old requests
        if api_key_id in self.rate_limit_storage:
            self.rate_limit_storage[api_key_id] = [
                req_time for req_time in self.rate_limit_storage[api_key_id]
                if req_time > window_start
            ]
        else:
            self.rate_limit_storage[api_key_id] = []

        # Check if rate limit exceeded
        if len(self.rate_limit_storage[api_key_id]) >= rate_limit:
            logger.warning(f"Rate limit exceeded for API key {api_key_id}: {len(self.rate_limit_storage[api_key_id])}/{rate_limit}")
            return False

        # Add current request
        self.rate_limit_storage[api_key_id].append(now)
        return True


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Middleware for handling authentication and authorization"""

    def __init__(self, app, api_key_auth: APIKeyAuth):
        super().__init__(app)
        self.api_key_auth = api_key_auth
        self.api_key_manager = APIKeyManager()

    async def dispatch(self, request: Request, call_next: Callable):
        """Process request through authentication"""
        start_time = time.time()

        try:
            # Authenticate if required
            api_key_info = await self.api_key_auth(request)

            # Process request
            response = await call_next(request)

            # Log API usage if authenticated
            if hasattr(request.state, 'api_key_info'):
                await self._log_api_usage(request, response, start_time)

            return response

        except HTTPException as e:
            # Log failed authentication attempts
            logger.warning(f"Authentication failed for {request.url.path}: {e.detail}")

            # Log the failed attempt
            if hasattr(request.state, 'api_key_info'):
                await self._log_api_usage(request, None, start_time, e.status_code)

            raise e
        except Exception as e:
            logger.error(f"Unexpected error in authentication middleware: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )

    async def _log_api_usage(self, request: Request, response, start_time: float,
                           status_code: Optional[int] = None):
        """Log API key usage"""
        try:
            api_key_info = request.state.api_key_info
            response_time_ms = int((time.time() - start_time) * 1000)

            # Get client info
            ip_address = request.client.host if request.client else None
            user_agent = request.headers.get("User-Agent")

            # Get response info
            if response:
                response_status = response.status_code
                response_size = len(response.body) if hasattr(response, 'body') else None
            else:
                response_status = status_code or 500
                response_size = None

            # Get request info
            request_size = None
            if hasattr(request, 'body'):
                try:
                    body = await request.body()
                    request_size = len(body) if body else 0
                except:
                    pass

            # Log usage
            self.api_key_manager.log_api_usage(
                api_key_id=api_key_info['id'],
                endpoint=str(request.url.path),
                method=request.method,
                response_status=response_status,
                ip_address=ip_address,
                user_agent=user_agent,
                response_time_ms=response_time_ms,
                request_size=request_size,
                response_size=response_size
            )

        except Exception as e:
            logger.error(f"Failed to log API usage: {e}")


def check_permission(operation: str, key_fingerprint: Optional[str] = None):
    """Decorator to check API key permissions"""
    def decorator(func):
        def wrapper(request: Request, *args, **kwargs):
            if not hasattr(request.state, 'api_key_info'):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )

            api_key_info = request.state.api_key_info
            api_key_manager = APIKeyManager()

            if not api_key_manager.check_permission(api_key_info, operation, key_fingerprint):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions for operation: {operation}"
                )

            return func(request, *args, **kwargs)
        return wrapper
    return decorator


def require_admin_key(request: Request):
    """Check if request uses admin API key"""
    if not hasattr(request.state, 'api_key'):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )

    config = get_config()
    api_key = request.state.api_key

    if not config.server.admin_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin functionality not configured"
        )

    if api_key != config.server.admin_api_key:
        # Check if user has admin operation permission
        if hasattr(request.state, 'api_key_info'):
            api_key_info = request.state.api_key_info
            permissions = api_key_info.get('permissions', {})
            operations = permissions.get('operations', [])

            if 'admin' not in operations:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Admin permissions required"
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin API key required"
            )


# Utility functions for permission checking
def has_operation_permission(api_key_info: Dict[str, Any], operation: str) -> bool:
    """Check if API key has permission for operation"""
    permissions = api_key_info.get('permissions', {})
    operations = permissions.get('operations', [])
    return operation in operations


def has_key_access(api_key_info: Dict[str, Any], key_fingerprint: str) -> bool:
    """Check if API key has access to specific key"""
    permissions = api_key_info.get('permissions', {})
    allowed_keys = permissions.get('keys', [])

    # Wildcard access
    if allowed_keys == "*":
        return True

    # Specific key access
    if isinstance(allowed_keys, list):
        return key_fingerprint in allowed_keys

    return False


def get_api_key_info(request: Request) -> Optional[Dict[str, Any]]:
    """Get API key info from request"""
    if hasattr(request.state, 'api_key_info'):
        return request.state.api_key_info
    return None