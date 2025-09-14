from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, Index, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.pool import StaticPool
from datetime import datetime
from typing import Optional
import os
import logging
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

load_dotenv()

# Import event for SQLite pragmas
from sqlalchemy import event

Base = declarative_base()

class GPGKey(Base):
    """Model for storing GPG key metadata"""
    __tablename__ = 'gpg_keys'

    id = Column(Integer, primary_key=True, autoincrement=True)
    fingerprint = Column(String(64), unique=True, nullable=False, index=True)  # Support SHA-256 fingerprints
    key_id = Column(String(16), nullable=False, index=True)
    user_id = Column(String(255), nullable=False)
    email = Column(String(255), index=True)
    name = Column(String(255), index=True)
    owner = Column(String(255), nullable=False, index=True)
    requester = Column(String(255), nullable=False, index=True)
    jira_ticket = Column(String(50), index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, index=True)  # Key expiration date
    last_used_at = Column(DateTime, index=True)  # Last time key was used
    usage_count = Column(Integer, default=0, nullable=False)  # Number of times key was used
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    is_expired = Column(Boolean, default=False, nullable=False, index=True)  # Computed field for expired keys
    notes = Column(Text)

    # Composite indexes for common queries
    __table_args__ = (
        Index('idx_owner_active', 'owner', 'is_active'),
        Index('idx_created_active', 'created_at', 'is_active'),
        Index('idx_requester_active', 'requester', 'is_active'),
        Index('idx_expires_active', 'expires_at', 'is_active'),
        Index('idx_expired_active', 'is_expired', 'is_active'),
        Index('idx_last_used_active', 'last_used_at', 'is_active'),
    )
    
    def __repr__(self):
        return f"<GPGKey(fingerprint='{self.fingerprint}', owner='{self.owner}')>"

class UsageLog(Base):
    """Model for logging GPG key usage"""
    __tablename__ = 'usage_logs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    fingerprint = Column(String(64), nullable=False, index=True)  # Support SHA-256 fingerprints
    operation = Column(String(50), nullable=False, index=True)  # encrypt, decrypt, sign, verify, import, export
    user = Column(String(255), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    file_path = Column(String(500))
    recipient = Column(String(255), index=True)
    success = Column(Boolean, default=True, nullable=False, index=True)
    error_message = Column(Text)

    # Composite indexes for common queries
    __table_args__ = (
        Index('idx_fingerprint_timestamp', 'fingerprint', 'timestamp'),
        Index('idx_user_timestamp', 'user', 'timestamp'),
        Index('idx_operation_success', 'operation', 'success'),
        Index('idx_timestamp_success', 'timestamp', 'success'),
    )
    
    def __repr__(self):
        return f"<UsageLog(fingerprint='{self.fingerprint}', operation='{self.operation}', user='{self.user}')>"


class APIKey(Base):
    """Model for API key management"""
    __tablename__ = 'api_keys'

    id = Column(Integer, primary_key=True, autoincrement=True)
    key_hash = Column(String(64), unique=True, nullable=False, index=True)  # SHA-256 hash of the API key
    name = Column(String(255), nullable=False)  # Human-readable name for the key
    owner = Column(String(255), nullable=False, index=True)  # Key owner
    permissions = Column(JSON, nullable=False)  # Permissions JSON object
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, index=True)  # Optional expiration date
    last_used_at = Column(DateTime, index=True)  # Last usage timestamp
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    rate_limit = Column(Integer, default=100, nullable=False)  # Requests per minute
    notes = Column(Text)

    # Relationships
    usage_logs = relationship("APIKeyUsage", back_populates="api_key")

    # Composite indexes
    __table_args__ = (
        Index('idx_owner_active', 'owner', 'is_active'),
        Index('idx_expires_active', 'expires_at', 'is_active'),
    )

    def __repr__(self):
        return f"<APIKey(name='{self.name}', owner='{self.owner}')>"


class MasterKey(Base):
    """Model for master key management"""
    __tablename__ = 'master_keys'

    id = Column(Integer, primary_key=True, autoincrement=True)
    fingerprint = Column(String(64), unique=True, nullable=False, index=True)
    key_type = Column(String(20), nullable=False, index=True)  # 'signing' or 'encryption'
    key_role = Column(String(20), nullable=False, index=True)  # 'organizational' or 'master'
    name = Column(String(255), nullable=False)
    description = Column(Text)
    organization = Column(String(255))  # Organization name
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    is_default = Column(Boolean, default=False, nullable=False, index=True)  # Default org key
    key_size = Column(Integer)  # Key size in bits
    algorithm = Column(String(50))  # Key algorithm (RSA, EdDSA, etc.)
    email = Column(String(255))  # Contact email for key
    expires_at = Column(DateTime, index=True)  # Key expiration

    # Composite indexes
    __table_args__ = (
        Index('idx_type_active', 'key_type', 'is_active'),
        Index('idx_role_active', 'key_role', 'is_active'),
        Index('idx_type_default', 'key_type', 'is_default'),
        Index('idx_role_default', 'key_role', 'is_default'),
    )

    def __repr__(self):
        return f"<MasterKey(name='{self.name}', type='{self.key_type}', role='{self.key_role}')>"


class APIKeyUsage(Base):
    """Model for API key usage logging"""
    __tablename__ = 'api_key_usage'

    id = Column(Integer, primary_key=True, autoincrement=True)
    api_key_id = Column(Integer, ForeignKey('api_keys.id'), nullable=False, index=True)
    endpoint = Column(String(255), nullable=False, index=True)
    method = Column(String(10), nullable=False)  # HTTP method
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    ip_address = Column(String(45))  # IPv4 or IPv6
    user_agent = Column(Text)
    response_status = Column(Integer, nullable=False, index=True)
    response_time_ms = Column(Integer)  # Response time in milliseconds
    request_size = Column(Integer)  # Request size in bytes
    response_size = Column(Integer)  # Response size in bytes

    # Relationships
    api_key = relationship("APIKey", back_populates="usage_logs")

    # Composite indexes
    __table_args__ = (
        Index('idx_api_key_timestamp', 'api_key_id', 'timestamp'),
        Index('idx_endpoint_status', 'endpoint', 'response_status'),
        Index('idx_timestamp_status', 'timestamp', 'response_status'),
    )

    def __repr__(self):
        return f"<APIKeyUsage(api_key_id={self.api_key_id}, endpoint='{self.endpoint}')>"


class KeySignature(Base):
    """Model for tracking key signatures by master keys"""
    __tablename__ = 'key_signatures'

    id = Column(Integer, primary_key=True, autoincrement=True)
    key_fingerprint = Column(String(64), ForeignKey('gpg_keys.fingerprint'), nullable=False, index=True)
    master_key_fingerprint = Column(String(64), ForeignKey('master_keys.fingerprint'), nullable=False, index=True)
    signature_data = Column(Text, nullable=False)  # The actual signature
    signed_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_valid = Column(Boolean, default=True, nullable=False, index=True)
    verified_at = Column(DateTime)  # Last verification timestamp

    # Composite indexes
    __table_args__ = (
        Index('idx_key_master', 'key_fingerprint', 'master_key_fingerprint'),
        Index('idx_master_valid', 'master_key_fingerprint', 'is_valid'),
    )

    def __repr__(self):
        return f"<KeySignature(key='{self.key_fingerprint[:16]}...', master='{self.master_key_fingerprint[:16]}...')>"

# Database setup
def get_database_url() -> str:
    """Get database URL from environment or use default"""
    db_path = os.getenv('DATABASE_PATH', './gpg_tracker.db')
    # Ensure directory exists
    db_dir = os.path.dirname(os.path.abspath(db_path))
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    return f"sqlite:///{db_path}"

def create_engine_with_options():
    """Create SQLAlchemy engine with optimized settings"""
    database_url = get_database_url()

    # SQLite-specific optimizations
    engine = create_engine(
        database_url,
        poolclass=StaticPool,
        connect_args={
            'check_same_thread': False,  # Allow multi-threading
            'timeout': 30,  # 30 second timeout
            'isolation_level': None,  # Enable autocommit mode
        },
        echo=os.getenv('SQL_ECHO', 'false').lower() == 'true',  # Enable SQL logging if requested
        pool_pre_ping=True,  # Validate connections before use
    )

    # Enable WAL mode and other optimizations for SQLite
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        # Enable WAL mode for better concurrency
        cursor.execute("PRAGMA journal_mode=WAL")
        # Enable foreign key constraints
        cursor.execute("PRAGMA foreign_keys=ON")
        # Optimize synchronous mode
        cursor.execute("PRAGMA synchronous=NORMAL")
        # Set cache size (in KB)
        cursor.execute("PRAGMA cache_size=10000")
        # Set timeout for busy database
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()

    return engine

def create_database():
    """Create database and tables"""
    try:
        engine = create_engine_with_options()
        Base.metadata.create_all(engine)
        logger.info("Database and tables created successfully")
        return engine
    except Exception as e:
        logger.error(f"Failed to create database: {e}")
        raise

def get_session() -> Session:
    """Get database session"""
    engine = create_engine_with_options()
    SessionClass = sessionmaker(bind=engine)
    return SessionClass()

def check_database_health() -> bool:
    """Check if database is accessible and healthy"""
    try:
        session = get_session()
        # Try a simple query
        session.execute('SELECT 1')
        session.close()
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False
