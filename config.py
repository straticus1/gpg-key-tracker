#!/usr/bin/env python3
"""
Configuration management for GPG Key Tracker
"""

import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from dotenv import load_dotenv
import json

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)


@dataclass
class DatabaseConfig:
    """Database configuration settings"""
    path: str = field(default_factory=lambda: os.getenv('DATABASE_PATH', './gpg_tracker.db'))
    echo_sql: bool = field(default_factory=lambda: os.getenv('SQL_ECHO', 'false').lower() == 'true')
    pool_timeout: int = field(default_factory=lambda: int(os.getenv('DB_POOL_TIMEOUT', '30')))
    cache_size: int = field(default_factory=lambda: int(os.getenv('DB_CACHE_SIZE', '10000')))


@dataclass
class GPGConfig:
    """GPG configuration settings"""
    home: str = field(default_factory=lambda: os.getenv('GPG_HOME', os.path.expanduser('~/.gnupg')))
    max_key_size: int = field(default_factory=lambda: int(os.getenv('MAX_KEY_SIZE_MB', '1')) * 1024 * 1024)
    valid_operations: List[str] = field(default_factory=lambda: ['encrypt', 'decrypt', 'sign', 'verify', 'import', 'export'])
    key_validation: bool = field(default_factory=lambda: os.getenv('VALIDATE_KEYS', 'true').lower() == 'true')


@dataclass
class SecurityConfig:
    """Security configuration settings"""
    input_sanitization: bool = field(default_factory=lambda: os.getenv('SANITIZE_INPUT', 'true').lower() == 'true')
    max_input_length: int = field(default_factory=lambda: int(os.getenv('MAX_INPUT_LENGTH', '255')))
    max_notes_length: int = field(default_factory=lambda: int(os.getenv('MAX_NOTES_LENGTH', '1000')))
    rate_limit_enabled: bool = field(default_factory=lambda: os.getenv('RATE_LIMIT_ENABLED', 'true').lower() == 'true')
    rate_limit_requests: int = field(default_factory=lambda: int(os.getenv('RATE_LIMIT_REQUESTS', '100')))
    rate_limit_window: int = field(default_factory=lambda: int(os.getenv('RATE_LIMIT_WINDOW', '3600')))  # seconds


@dataclass
class LoggingConfig:
    """Logging configuration settings"""
    level: str = field(default_factory=lambda: os.getenv('LOG_LEVEL', 'INFO'))
    format: str = field(default_factory=lambda: os.getenv('LOG_FORMAT', '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    file: Optional[str] = field(default_factory=lambda: os.getenv('LOG_FILE'))
    json_format: bool = field(default_factory=lambda: os.getenv('LOG_JSON', 'false').lower() == 'true')
    max_bytes: int = field(default_factory=lambda: int(os.getenv('LOG_MAX_BYTES', '10485760')))  # 10MB
    backup_count: int = field(default_factory=lambda: int(os.getenv('LOG_BACKUP_COUNT', '5')))


@dataclass
class EmailConfig:
    """Email configuration settings"""
    smtp_server: Optional[str] = field(default_factory=lambda: os.getenv('SMTP_SERVER'))
    smtp_port: int = field(default_factory=lambda: int(os.getenv('SMTP_PORT', '587')))
    smtp_username: Optional[str] = field(default_factory=lambda: os.getenv('SMTP_USERNAME'))
    smtp_password: Optional[str] = field(default_factory=lambda: os.getenv('SMTP_PASSWORD'))
    use_tls: bool = field(default_factory=lambda: os.getenv('SMTP_USE_TLS', 'true').lower() == 'true')
    from_address: Optional[str] = field(default_factory=lambda: os.getenv('EMAIL_FROM_ADDRESS'))
    timeout: int = field(default_factory=lambda: int(os.getenv('EMAIL_TIMEOUT', '30')))


@dataclass
class AWSConfig:
    """AWS configuration settings"""
    access_key_id: Optional[str] = field(default_factory=lambda: os.getenv('AWS_ACCESS_KEY_ID'))
    secret_access_key: Optional[str] = field(default_factory=lambda: os.getenv('AWS_SECRET_ACCESS_KEY'))
    region: str = field(default_factory=lambda: os.getenv('AWS_DEFAULT_REGION', 'us-east-1'))
    s3_bucket: Optional[str] = field(default_factory=lambda: os.getenv('S3_BUCKET'))
    s3_prefix: str = field(default_factory=lambda: os.getenv('S3_PREFIX', 'gpg-reports/'))


@dataclass
class BackupConfig:
    """Backup configuration settings"""
    enabled: bool = field(default_factory=lambda: os.getenv('BACKUP_ENABLED', 'false').lower() == 'true')
    schedule: str = field(default_factory=lambda: os.getenv('BACKUP_SCHEDULE', '0 2 * * *'))  # Daily at 2 AM
    retention_days: int = field(default_factory=lambda: int(os.getenv('BACKUP_RETENTION_DAYS', '30')))
    path: str = field(default_factory=lambda: os.getenv('BACKUP_PATH', './backups'))
    compress: bool = field(default_factory=lambda: os.getenv('BACKUP_COMPRESS', 'true').lower() == 'true')


@dataclass
class MonitoringConfig:
    """Monitoring configuration settings"""
    enabled: bool = field(default_factory=lambda: os.getenv('MONITORING_ENABLED', 'false').lower() == 'true')
    prometheus_port: int = field(default_factory=lambda: int(os.getenv('PROMETHEUS_PORT', '8000')))
    health_check_port: int = field(default_factory=lambda: int(os.getenv('HEALTH_CHECK_PORT', '8001')))
    metrics_path: str = field(default_factory=lambda: os.getenv('METRICS_PATH', '/metrics'))


@dataclass
class Config:
    """Main configuration class that aggregates all settings"""
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    gpg: GPGConfig = field(default_factory=GPGConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    email: EmailConfig = field(default_factory=EmailConfig)
    aws: AWSConfig = field(default_factory=AWSConfig)
    backup: BackupConfig = field(default_factory=BackupConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)

    def __post_init__(self):
        """Validate configuration after initialization"""
        self.validate()

    def validate(self) -> None:
        """Validate configuration settings"""
        # Validate database path directory exists or can be created
        db_dir = os.path.dirname(os.path.abspath(self.database.path))
        if db_dir and not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, exist_ok=True)
            except OSError as e:
                raise ValueError(f"Cannot create database directory {db_dir}: {e}")

        # Validate GPG home directory
        if not os.path.exists(self.gpg.home):
            logger.warning(f"GPG home directory does not exist: {self.gpg.home}")

        # Validate backup path if backup is enabled
        if self.backup.enabled:
            if not os.path.exists(self.backup.path):
                try:
                    os.makedirs(self.backup.path, exist_ok=True)
                except OSError as e:
                    raise ValueError(f"Cannot create backup directory {self.backup.path}: {e}")

        # Validate email configuration if SMTP server is set
        if self.email.smtp_server:
            if not self.email.from_address:
                raise ValueError("EMAIL_FROM_ADDRESS is required when SMTP_SERVER is configured")

        # Validate logging level
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.logging.level.upper() not in valid_levels:
            raise ValueError(f"Invalid log level: {self.logging.level}. Must be one of {valid_levels}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        def _dataclass_to_dict(obj):
            if hasattr(obj, '__dataclass_fields__'):
                return {k: _dataclass_to_dict(v) for k, v in obj.__dict__.items()}
            elif isinstance(obj, list):
                return [_dataclass_to_dict(item) for item in obj]
            else:
                return obj

        return _dataclass_to_dict(self)

    def save_to_file(self, file_path: str) -> None:
        """Save configuration to JSON file"""
        config_dict = self.to_dict()
        # Remove sensitive information
        if 'smtp_password' in config_dict.get('email', {}):
            config_dict['email']['smtp_password'] = '***REDACTED***'
        if 'secret_access_key' in config_dict.get('aws', {}):
            config_dict['aws']['secret_access_key'] = '***REDACTED***'

        with open(file_path, 'w') as f:
            json.dump(config_dict, f, indent=2, default=str)

    @classmethod
    def load_from_file(cls, file_path: str) -> 'Config':
        """Load configuration from JSON file"""
        if not os.path.exists(file_path):
            logger.warning(f"Configuration file not found: {file_path}. Using defaults.")
            return cls()

        try:
            with open(file_path, 'r') as f:
                config_data = json.load(f)

            # Convert nested dictionaries back to dataclass instances
            database_config = DatabaseConfig(**config_data.get('database', {}))
            gpg_config = GPGConfig(**config_data.get('gpg', {}))
            security_config = SecurityConfig(**config_data.get('security', {}))
            logging_config = LoggingConfig(**config_data.get('logging', {}))
            email_config = EmailConfig(**config_data.get('email', {}))
            aws_config = AWSConfig(**config_data.get('aws', {}))
            backup_config = BackupConfig(**config_data.get('backup', {}))
            monitoring_config = MonitoringConfig(**config_data.get('monitoring', {}))

            return cls(
                database=database_config,
                gpg=gpg_config,
                security=security_config,
                logging=logging_config,
                email=email_config,
                aws=aws_config,
                backup=backup_config,
                monitoring=monitoring_config
            )
        except Exception as e:
            logger.error(f"Failed to load configuration from {file_path}: {e}")
            logger.info("Using default configuration")
            return cls()

    def setup_logging(self) -> None:
        """Configure logging based on configuration settings"""
        import logging.handlers

        # Create logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, self.logging.level.upper()))

        # Clear existing handlers
        root_logger.handlers.clear()

        # Create formatter
        if self.logging.json_format:
            import json
            import time

            class JSONFormatter(logging.Formatter):
                def format(self, record):
                    log_obj = {
                        'timestamp': time.time(),
                        'level': record.levelname,
                        'logger': record.name,
                        'message': record.getMessage(),
                        'module': record.module,
                        'function': record.funcName,
                        'line': record.lineno
                    }
                    if record.exc_info:
                        log_obj['exception'] = self.formatException(record.exc_info)
                    return json.dumps(log_obj)

            formatter = JSONFormatter()
        else:
            formatter = logging.Formatter(self.logging.format)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

        # File handler if specified
        if self.logging.file:
            file_handler = logging.handlers.RotatingFileHandler(
                self.logging.file,
                maxBytes=self.logging.max_bytes,
                backupCount=self.logging.backup_count
            )
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)


# Global configuration instance
config = Config()


def get_config() -> Config:
    """Get the global configuration instance"""
    return config


def reload_config(config_file: Optional[str] = None) -> Config:
    """Reload configuration from file or environment"""
    global config
    if config_file:
        config = Config.load_from_file(config_file)
    else:
        config = Config()
    return config


def validate_config() -> bool:
    """Validate the current configuration"""
    try:
        config.validate()
        return True
    except ValueError as e:
        logger.error(f"Configuration validation failed: {e}")
        return False


if __name__ == '__main__':
    # Test configuration
    test_config = Config()
    print("Configuration loaded successfully:")
    print(f"Database path: {test_config.database.path}")
    print(f"GPG home: {test_config.gpg.home}")
    print(f"Log level: {test_config.logging.level}")