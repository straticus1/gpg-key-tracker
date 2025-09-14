from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
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
