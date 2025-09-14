#!/usr/bin/env python3
"""
Pydantic models for GPG Key Server API requests and responses
"""

from pydantic import BaseModel, Field, validator
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from enum import Enum


class OperationType(str, Enum):
    """Valid GPG operations"""
    READ = "read"
    LIST = "list"
    SIGN = "sign"
    ENCRYPT = "encrypt"
    INFO = "info"
    SEARCH = "search"
    ADMIN = "admin"


class KeyType(str, Enum):
    """Master key types"""
    SIGNING = "signing"
    ENCRYPTION = "encryption"


class KeyRole(str, Enum):
    """Master key roles"""
    ORGANIZATIONAL = "organizational"
    MASTER = "master"


# Request Models
class APIKeyCreateRequest(BaseModel):
    """Request model for creating API keys"""
    name: str = Field(..., min_length=1, max_length=255, description="Human-readable name for the API key")
    owner: str = Field(..., min_length=1, max_length=255, description="Owner of the API key")
    permissions: Dict[str, Any] = Field(..., description="Permission structure for the API key")
    expires_days: Optional[int] = Field(None, ge=1, le=3650, description="Expiration in days")
    rate_limit: int = Field(100, ge=1, le=10000, description="Rate limit per minute")
    notes: Optional[str] = Field(None, max_length=1000, description="Optional notes")

    @validator('permissions')
    def validate_permissions(cls, v):
        """Validate permissions structure"""
        if not isinstance(v, dict):
            raise ValueError("Permissions must be a dictionary")

        if 'operations' not in v:
            raise ValueError("Permissions must include 'operations' field")

        if 'keys' not in v:
            raise ValueError("Permissions must include 'keys' field")

        operations = v.get('operations', [])
        if not isinstance(operations, list):
            raise ValueError("Operations must be a list")

        valid_ops = [op.value for op in OperationType]
        for op in operations:
            if op not in valid_ops:
                raise ValueError(f"Invalid operation: {op}. Must be one of {valid_ops}")

        keys = v.get('keys')
        if keys != "*" and not isinstance(keys, list):
            raise ValueError("Keys must be '*' or a list of fingerprints")

        return v


class APIKeyUpdateRequest(BaseModel):
    """Request model for updating API keys"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    permissions: Optional[Dict[str, Any]] = None
    expires_at: Optional[datetime] = None
    rate_limit: Optional[int] = Field(None, ge=1, le=10000)
    notes: Optional[str] = Field(None, max_length=1000)
    is_active: Optional[bool] = None

    @validator('permissions')
    def validate_permissions(cls, v):
        """Validate permissions structure"""
        if v is None:
            return v
        return APIKeyCreateRequest.validate_permissions(v)


class MasterKeyCreateRequest(BaseModel):
    """Request model for creating master keys"""
    name: str = Field(..., min_length=1, max_length=255, description="Key name")
    key_type: KeyType = Field(..., description="Key type (signing or encryption)")
    key_role: KeyRole = Field(KeyRole.MASTER, description="Key role (organizational or master)")
    organization: Optional[str] = Field(None, max_length=255, description="Organization name")
    email: Optional[str] = Field(None, max_length=255, description="Contact email")
    key_size: int = Field(4096, ge=2048, le=8192, description="Key size in bits")
    algorithm: str = Field("RSA", description="Key algorithm")
    expires_days: Optional[int] = Field(None, ge=1, le=3650, description="Expiration in days")
    set_as_default: bool = Field(False, description="Set as default key for this type/role")


class OrganizationalKeyPairRequest(BaseModel):
    """Request model for creating organizational key pair"""
    organization: str = Field(..., min_length=1, max_length=255, description="Organization name")
    name: str = Field(..., min_length=1, max_length=255, description="Key name")
    email: Optional[str] = Field(None, max_length=255, description="Contact email")
    key_size: int = Field(4096, ge=2048, le=8192, description="Key size in bits")
    expires_days: Optional[int] = Field(None, ge=1, le=3650, description="Expiration in days")


class GPGKeyCreateRequest(BaseModel):
    """Request model for adding GPG keys"""
    key_data: str = Field(..., description="GPG key data (ASCII armored)")
    owner: str = Field(..., min_length=1, max_length=255, description="Key owner")
    requester: str = Field(..., min_length=1, max_length=255, description="Person requesting key addition")
    jira_ticket: Optional[str] = Field(None, max_length=50, description="Associated JIRA ticket")
    notes: Optional[str] = Field(None, max_length=1000, description="Optional notes")


class GPGKeyUpdateRequest(BaseModel):
    """Request model for updating GPG keys"""
    owner: Optional[str] = Field(None, min_length=1, max_length=255)
    requester: Optional[str] = Field(None, min_length=1, max_length=255)
    jira_ticket: Optional[str] = Field(None, max_length=50)
    notes: Optional[str] = Field(None, max_length=1000)
    is_active: Optional[bool] = None


class GPGSignRequest(BaseModel):
    """Request model for signing data"""
    data: str = Field(..., description="Data to sign")
    detached: bool = Field(True, description="Create detached signature")


class GPGEncryptRequest(BaseModel):
    """Request model for encrypting data"""
    data: str = Field(..., description="Data to encrypt")
    recipients: Optional[List[str]] = Field(None, description="Recipient fingerprints (uses key if not provided)")


class GPGSearchRequest(BaseModel):
    """Request model for searching keys"""
    query: str = Field(..., min_length=1, max_length=255, description="Search query (fingerprint, key_id, email, name, etc.)")
    search_type: str = Field("text", description="Search type: 'text', 'fingerprint', 'key_id', 'email'")
    fields: Optional[List[str]] = Field(None, description="Specific fields to search in")
    limit: int = Field(50, ge=1, le=1000, description="Maximum results")

    @validator('search_type')
    def validate_search_type(cls, v):
        """Validate search type"""
        valid_types = ['text', 'fingerprint', 'key_id', 'email', 'name', 'owner']
        if v not in valid_types:
            raise ValueError(f"Search type must be one of: {valid_types}")
        return v


class GPGKeyCheckRequest(BaseModel):
    """Request model for checking if a key exists by uploading key data"""
    key_data: str = Field(..., description="GPG key data (ASCII armored)")
    check_only: bool = Field(True, description="Only check existence, don't import")


# Response Models
class APIKeyResponse(BaseModel):
    """Response model for API key information"""
    id: int
    name: str
    owner: str
    permissions: Dict[str, Any]
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    is_active: bool
    rate_limit: int
    notes: Optional[str]


class APIKeyCreateResponse(APIKeyResponse):
    """Response model for API key creation (includes actual key)"""
    api_key: str = Field(..., description="The actual API key (only shown during creation)")


class MasterKeyResponse(BaseModel):
    """Response model for master key information"""
    id: int
    fingerprint: str
    name: str
    key_type: KeyType
    key_role: KeyRole
    organization: Optional[str]
    email: Optional[str]
    algorithm: Optional[str]
    key_size: Optional[int]
    created_at: datetime
    expires_at: Optional[datetime]
    is_active: bool
    is_default: bool


class OrganizationalKeyPairResponse(BaseModel):
    """Response model for organizational key pair creation"""
    signing_key: MasterKeyResponse
    encryption_key: MasterKeyResponse
    organization: str


class GPGKeyResponse(BaseModel):
    """Response model for GPG key information"""
    id: int
    fingerprint: str
    key_id: str
    user_id: str
    email: Optional[str]
    name: Optional[str]
    owner: str
    requester: str
    jira_ticket: Optional[str]
    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    usage_count: int
    is_active: bool
    is_expired: bool
    notes: Optional[str]


class GPGSignResponse(BaseModel):
    """Response model for signing operation"""
    signature: str
    fingerprint: str
    timestamp: datetime


class GPGEncryptResponse(BaseModel):
    """Response model for encryption operation"""
    encrypted_data: str
    recipients: List[str]
    timestamp: datetime


class GPGKeyCheckResponse(BaseModel):
    """Response model for key check operation"""
    found: bool
    fingerprint: Optional[str] = None
    key_info: Optional[GPGKeyResponse] = None
    message: str
    how_to_add: Optional[Dict[str, str]] = None


class ServerInfoResponse(BaseModel):
    """Response model for server information"""
    name: str = "GPG Key Server"
    version: str = "1.0.0"
    description: str = "Secure GPG Key Management Server"
    supported_operations: List[str]
    authentication_required: bool = True
    endpoints: Dict[str, str]


class HealthResponse(BaseModel):
    """Response model for health check"""
    status: str
    timestamp: datetime
    database: bool
    gpg: bool
    version: str


class UsageStatsResponse(BaseModel):
    """Response model for API usage statistics"""
    period_days: int
    total_requests: int
    successful_requests: int
    error_requests: int
    success_rate: float
    endpoint_stats: Dict[str, Dict[str, int]]
    api_key_stats: Dict[str, Dict[str, int]]


class ErrorResponse(BaseModel):
    """Response model for errors"""
    error: str
    detail: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ValidationErrorResponse(BaseModel):
    """Response model for validation errors"""
    error: str = "Validation Error"
    detail: List[Dict[str, Any]]
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# List response models
class APIKeyListResponse(BaseModel):
    """Response model for listing API keys"""
    api_keys: List[APIKeyResponse]
    total: int
    page: int
    per_page: int


class MasterKeyListResponse(BaseModel):
    """Response model for listing master keys"""
    master_keys: List[MasterKeyResponse]
    total: int
    page: int
    per_page: int


class GPGKeyListResponse(BaseModel):
    """Response model for listing GPG keys"""
    keys: List[GPGKeyResponse]
    total: int
    page: int
    per_page: int