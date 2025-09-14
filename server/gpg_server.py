#!/usr/bin/env python3
"""
GPG Key Server - HTTP API for GPG key management
"""

import os
import logging
import uvicorn
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

# Import our modules
import sys
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)
sys.path.append(os.path.join(parent_dir, 'lib'))

from lib.config import get_config
from lib.models import create_database, check_database_health
from server.api_key_manager import APIKeyManager
from server.master_key_manager import MasterKeyManager
from server.gpg_key_manager import GPGKeyManager
from server.auth_middleware import APIKeyAuth, AuthenticationMiddleware, require_admin_key, check_permission, get_api_key_info
from server.server_models import (
    # Request models
    APIKeyCreateRequest, APIKeyUpdateRequest,
    MasterKeyCreateRequest, OrganizationalKeyPairRequest,
    GPGKeyCreateRequest, GPGKeyUpdateRequest,
    GPGSignRequest, GPGEncryptRequest, GPGSearchRequest, GPGKeyCheckRequest,
    # Response models
    APIKeyResponse, APIKeyCreateResponse, APIKeyListResponse,
    MasterKeyResponse, MasterKeyListResponse, OrganizationalKeyPairResponse,
    GPGKeyResponse, GPGKeyListResponse,
    GPGSignResponse, GPGEncryptResponse, GPGKeyCheckResponse,
    ServerInfoResponse, HealthResponse, UsageStatsResponse,
    ErrorResponse, ValidationErrorResponse, OperationType
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    config = get_config()
    logger.info("Starting GPG Key Server")

    # Initialize database
    try:
        create_database()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

    # Check GPG environment
    try:
        gpg_manager = GPGKeyManager()
        logger.info(f"GPG environment initialized: {gpg_manager.gpg_home}")
    except Exception as e:
        logger.error(f"Failed to initialize GPG environment: {e}")
        raise

    yield

    # Shutdown
    logger.info("Shutting down GPG Key Server")


# Create FastAPI app
app = FastAPI(
    title="GPG Key Server",
    description="Secure GPG Key Management Server with API key authentication",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Configuration
config = get_config()

# CORS middleware
if config.server.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.server.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"]
    )

# Authentication
api_key_auth = APIKeyAuth()

# Authentication middleware
app.add_middleware(AuthenticationMiddleware, api_key_auth=api_key_auth)

# Managers
api_key_manager = APIKeyManager()
master_key_manager = MasterKeyManager()
gpg_manager = GPGKeyManager()


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=exc.detail,
            detail=getattr(exc, 'headers', None)
        ).dict()
    )


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """Handle validation errors"""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content=ErrorResponse(
            error="Bad Request",
            detail=str(exc)
        ).dict()
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected errors"""
    logger.error(f"Unexpected error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error="Internal Server Error",
            detail="An unexpected error occurred"
        ).dict()
    )


# Root endpoint (public)
@app.get("/", response_model=ServerInfoResponse)
async def server_info():
    """Get server information"""
    return ServerInfoResponse(
        supported_operations=[op.value for op in OperationType],
        endpoints={
            "keys": "/keys",
            "api_keys": "/api-keys",
            "master_keys": "/master-keys",
            "health": "/health",
            "documentation": "/docs"
        }
    )


# Health endpoint (public)
@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    database_healthy = check_database_health()
    gpg_healthy = True  # Basic check - could be expanded

    try:
        gpg_manager.list_keys(limit=1)
    except Exception:
        gpg_healthy = False

    status_msg = "healthy" if database_healthy and gpg_healthy else "unhealthy"

    return HealthResponse(
        status=status_msg,
        timestamp=datetime.utcnow(),
        database=database_healthy,
        gpg=gpg_healthy,
        version="1.0.0"
    )


# GPG Key Management Endpoints
@app.get("/keys", response_model=GPGKeyListResponse)
async def list_keys(
    request: Request,
    page: int = 1,
    per_page: int = 50,
    owner: Optional[str] = None,
    active_only: bool = True
):
    """List GPG keys"""
    api_key_info = get_api_key_info(request)
    if not api_key_info or not api_key_manager.check_permission(api_key_info, "list"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    try:
        keys = gpg_manager.list_keys(
            limit=per_page,
            offset=(page - 1) * per_page,
            owner=owner,
            active_only=active_only
        )

        # Filter keys based on API key permissions
        if api_key_info:
            permissions = api_key_info.get('permissions', {})
            allowed_keys = permissions.get('keys', [])

            if allowed_keys != "*":
                keys = [key for key in keys if key['fingerprint'] in allowed_keys]

        # Convert to response models
        key_responses = [GPGKeyResponse(**key) for key in keys]

        return GPGKeyListResponse(
            keys=key_responses,
            total=len(key_responses),
            page=page,
            per_page=per_page
        )

    except Exception as e:
        logger.error(f"Error listing keys: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to list keys")


@app.get("/keys/{fingerprint}", response_model=GPGKeyResponse)
async def get_key(request: Request, fingerprint: str):
    """Get specific GPG key"""
    api_key_info = get_api_key_info(request)
    if not api_key_info or not api_key_manager.check_permission(api_key_info, "read", fingerprint):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    try:
        key_info = gpg_manager.get_key_info(fingerprint)
        if not key_info:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")

        return GPGKeyResponse(**key_info)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting key {fingerprint}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get key")


@app.post("/keys", response_model=GPGKeyResponse, status_code=status.HTTP_201_CREATED)
async def add_key(request: Request, key_request: GPGKeyCreateRequest):
    """Add new GPG key (requires master signature validation)"""
    api_key_info = get_api_key_info(request)
    if not api_key_info or not api_key_manager.check_permission(api_key_info, "admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin permissions required")

    try:
        # Import and validate key
        result = gpg_manager.import_key(
            key_data=key_request.key_data,
            owner=key_request.owner,
            requester=key_request.requester,
            jira_ticket=key_request.jira_ticket,
            notes=key_request.notes
        )

        if not result['success']:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result['error'])

        fingerprint = result['fingerprint']

        # Require master signature validation
        if config.master_keys.require_master_signature:
            if not master_key_manager.sign_key(fingerprint):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to validate key with master signature")

        # Get key info
        key_info = gpg_manager.get_key_info(fingerprint)
        if not key_info:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve added key")

        return GPGKeyResponse(**key_info)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding key: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to add key")


@app.put("/keys/{fingerprint}", response_model=GPGKeyResponse)
async def update_key(request: Request, fingerprint: str, key_update: GPGKeyUpdateRequest):
    """Update GPG key metadata"""
    api_key_info = get_api_key_info(request)
    if not api_key_info or not api_key_manager.check_permission(api_key_info, "admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin permissions required")

    try:
        # Update key
        update_data = key_update.dict(exclude_unset=True)
        success = gpg_manager.update_key(fingerprint, **update_data)

        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found or update failed")

        # Return updated key info
        key_info = gpg_manager.get_key_info(fingerprint)
        return GPGKeyResponse(**key_info)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating key {fingerprint}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update key")


@app.delete("/keys/{fingerprint}")
async def delete_key(request: Request, fingerprint: str, hard_delete: bool = False):
    """Delete GPG key"""
    api_key_info = get_api_key_info(request)
    if not api_key_info or not api_key_manager.check_permission(api_key_info, "admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin permissions required")

    try:
        success = gpg_manager.delete_key(fingerprint, hard_delete=hard_delete)
        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")

        return {"message": "Key deleted successfully", "fingerprint": fingerprint}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting key {fingerprint}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete key")


@app.post("/keys/search", response_model=GPGKeyListResponse)
async def search_keys(request: Request, search_request: GPGSearchRequest):
    """Search GPG keys"""
    api_key_info = get_api_key_info(request)
    if not api_key_info or not api_key_manager.check_permission(api_key_info, "search"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    try:
        keys = gpg_manager.search_keys(
            query=search_request.query,
            search_type=search_request.search_type,
            fields=search_request.fields,
            limit=search_request.limit
        )

        # Filter based on permissions
        if api_key_info:
            permissions = api_key_info.get('permissions', {})
            allowed_keys = permissions.get('keys', [])

            if allowed_keys != "*":
                keys = [key for key in keys if key['fingerprint'] in allowed_keys]

        key_responses = [GPGKeyResponse(**key) for key in keys]

        return GPGKeyListResponse(
            keys=key_responses,
            total=len(key_responses),
            page=1,
            per_page=search_request.limit
        )

    except Exception as e:
        logger.error(f"Error searching keys: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to search keys")


@app.post("/keys/check", response_model=GPGKeyCheckResponse)
async def check_key_exists(request: Request, key_check: GPGKeyCheckRequest):
    """Check if a GPG key exists by uploading key data"""
    api_key_info = get_api_key_info(request)
    if not api_key_info or not api_key_manager.check_permission(api_key_info, "search"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    try:
        result = gpg_manager.check_key_exists(key_check.key_data)

        return GPGKeyCheckResponse(
            found=result['found'],
            fingerprint=result.get('fingerprint'),
            key_info=GPGKeyResponse(**result['key_info']) if result.get('key_info') else None,
            message=result['message'],
            how_to_add=result.get('how_to_add')
        )

    except Exception as e:
        logger.error(f"Error checking key existence: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to check key")


@app.post("/keys/{fingerprint}/sign", response_model=GPGSignResponse)
async def sign_data(request: Request, fingerprint: str, sign_request: GPGSignRequest):
    """Sign data with GPG key"""
    api_key_info = get_api_key_info(request)
    if not api_key_info or not api_key_manager.check_permission(api_key_info, "sign", fingerprint):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    try:
        # Verify key signature before use
        if config.master_keys.require_master_signature:
            if not master_key_manager.verify_key_signature(fingerprint):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Key signature validation failed")

        result = gpg_manager.sign_data(
            data=sign_request.data,
            key_fingerprint=fingerprint,
            detached=sign_request.detached
        )

        if not result['success']:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result['error'])

        return GPGSignResponse(
            signature=result['signature'],
            fingerprint=fingerprint,
            timestamp=datetime.utcnow()
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error signing with key {fingerprint}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to sign data")


@app.post("/keys/{fingerprint}/encrypt", response_model=GPGEncryptResponse)
async def encrypt_data(request: Request, fingerprint: str, encrypt_request: GPGEncryptRequest):
    """Encrypt data with GPG key"""
    api_key_info = get_api_key_info(request)
    if not api_key_info or not api_key_manager.check_permission(api_key_info, "encrypt", fingerprint):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    try:
        # Verify key signature before use
        if config.master_keys.require_master_signature:
            if not master_key_manager.verify_key_signature(fingerprint):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Key signature validation failed")

        recipients = encrypt_request.recipients or [fingerprint]

        result = gpg_manager.encrypt_data(
            data=encrypt_request.data,
            recipients=recipients
        )

        if not result['success']:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result['error'])

        return GPGEncryptResponse(
            encrypted_data=result['encrypted_data'],
            recipients=recipients,
            timestamp=datetime.utcnow()
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error encrypting with key {fingerprint}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to encrypt data")


# API Key Management Endpoints (Admin)
@app.get("/api-keys", response_model=APIKeyListResponse)
async def list_api_keys(request: Request, page: int = 1, per_page: int = 50, owner: Optional[str] = None):
    """List API keys (admin only)"""
    require_admin_key(request)

    try:
        api_keys = api_key_manager.list_api_keys(owner=owner, include_inactive=True)

        # Pagination
        start = (page - 1) * per_page
        end = start + per_page
        paginated_keys = api_keys[start:end]

        key_responses = [APIKeyResponse(**key) for key in paginated_keys]

        return APIKeyListResponse(
            api_keys=key_responses,
            total=len(api_keys),
            page=page,
            per_page=per_page
        )

    except Exception as e:
        logger.error(f"Error listing API keys: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to list API keys")


@app.post("/api-keys", response_model=APIKeyCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(request: Request, key_request: APIKeyCreateRequest):
    """Create new API key (admin only)"""
    require_admin_key(request)

    try:
        result = api_key_manager.create_api_key(
            name=key_request.name,
            owner=key_request.owner,
            permissions=key_request.permissions,
            expires_days=key_request.expires_days,
            rate_limit=key_request.rate_limit,
            notes=key_request.notes
        )

        return APIKeyCreateResponse(**result)

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating API key: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create API key")


@app.get("/api-keys/{key_id}", response_model=APIKeyResponse)
async def get_api_key(request: Request, key_id: int):
    """Get API key by ID (admin only)"""
    require_admin_key(request)

    try:
        api_key = api_key_manager.get_api_key(key_id)
        if not api_key:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

        return APIKeyResponse(**api_key)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting API key {key_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get API key")


@app.put("/api-keys/{key_id}", response_model=APIKeyResponse)
async def update_api_key(request: Request, key_id: int, key_update: APIKeyUpdateRequest):
    """Update API key (admin only)"""
    require_admin_key(request)

    try:
        update_data = key_update.dict(exclude_unset=True)
        success = api_key_manager.update_api_key(key_id, **update_data)

        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found or update failed")

        # Return updated API key info
        api_key = api_key_manager.get_api_key(key_id)
        return APIKeyResponse(**api_key)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating API key {key_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update API key")


@app.delete("/api-keys/{key_id}")
async def delete_api_key(request: Request, key_id: int, hard_delete: bool = False):
    """Delete API key (admin only)"""
    require_admin_key(request)

    try:
        success = api_key_manager.delete_api_key(key_id, soft_delete=not hard_delete)
        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

        return {"message": "API key deleted successfully", "id": key_id}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting API key {key_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete API key")


# Master Key Management Endpoints (Admin)
@app.get("/master-keys", response_model=MasterKeyListResponse)
async def list_master_keys(request: Request, page: int = 1, per_page: int = 50, key_type: Optional[str] = None):
    """List master keys (admin only)"""
    require_admin_key(request)

    try:
        master_keys = master_key_manager.list_master_keys(key_type=key_type, include_inactive=True)

        # Pagination
        start = (page - 1) * per_page
        end = start + per_page
        paginated_keys = master_keys[start:end]

        key_responses = [MasterKeyResponse(**key) for key in paginated_keys]

        return MasterKeyListResponse(
            master_keys=key_responses,
            total=len(master_keys),
            page=page,
            per_page=per_page
        )

    except Exception as e:
        logger.error(f"Error listing master keys: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to list master keys")


@app.post("/master-keys", response_model=MasterKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_master_key(request: Request, key_request: MasterKeyCreateRequest):
    """Create master key (admin only)"""
    require_admin_key(request)

    try:
        result = master_key_manager.create_master_key(
            name=key_request.name,
            key_type=key_request.key_type,
            key_role=key_request.key_role,
            organization=key_request.organization,
            email=key_request.email,
            key_size=key_request.key_size,
            algorithm=key_request.algorithm,
            expires_days=key_request.expires_days,
            set_as_default=key_request.set_as_default
        )

        return MasterKeyResponse(**result)

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating master key: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create master key")


@app.post("/master-keys/organizational", response_model=OrganizationalKeyPairResponse, status_code=status.HTTP_201_CREATED)
async def create_organizational_keys(request: Request, key_request: OrganizationalKeyPairRequest):
    """Create organizational key pair (admin only)"""
    require_admin_key(request)

    try:
        result = master_key_manager.create_organizational_key_pair(
            organization=key_request.organization,
            name=key_request.name,
            email=key_request.email,
            key_size=key_request.key_size,
            expires_days=key_request.expires_days
        )

        return OrganizationalKeyPairResponse(**result)

    except Exception as e:
        logger.error(f"Error creating organizational keys: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create organizational keys")


# Usage Statistics
@app.get("/usage", response_model=UsageStatsResponse)
async def get_usage_stats(request: Request, days: int = 30, api_key_id: Optional[int] = None):
    """Get API usage statistics (admin only)"""
    require_admin_key(request)

    try:
        stats = api_key_manager.get_api_usage_stats(api_key_id=api_key_id, days=days)
        return UsageStatsResponse(**stats)

    except Exception as e:
        logger.error(f"Error getting usage stats: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get usage statistics")


def create_server_app(config_file: Optional[str] = None) -> FastAPI:
    """Create and configure the FastAPI application"""
    if config_file:
        global config
        from lib.config import reload_config
        config = reload_config(config_file)

    # Setup logging
    config.setup_logging()

    return app


def run_server():
    """Run the GPG Key Server"""
    config = get_config()

    # SSL configuration
    ssl_keyfile = config.server.ssl_key_file
    ssl_certfile = config.server.ssl_cert_file

    if config.server.require_ssl and not (ssl_keyfile and ssl_certfile):
        logger.warning("SSL required but certificate/key not configured. Running without SSL.")
        ssl_keyfile = ssl_certfile = None

    # Run server
    uvicorn.run(
        "gpg_server:app",
        host=config.server.host,
        port=config.server.port,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
        workers=config.server.workers,
        reload=False,
        access_log=True
    )


if __name__ == "__main__":
    run_server()