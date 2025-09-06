# Changelog

All notable changes to the GPG Key Tracker project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Web-based dashboard for key management
- REST API for integration with other systems
- Key expiration tracking and notifications
- Advanced analytics and trend analysis
- Multi-database support (PostgreSQL, MySQL)

## [1.2.0] - 2024-12-19

### Added
- **Automated Reporting System**
  - Report generation in CSV, JSON, and HTML formats
  - Email delivery with customizable SMTP settings
  - S3 upload support for cloud storage integration
  - SCP transfer for legacy system compatibility
  - Auto-report command for one-step generation and export
  - Comprehensive usage statistics and audit trails

- **New CLI Commands**
  - `generate-report`: Create usage reports in multiple formats
  - `email-report`: Send reports via email
  - `upload-to-s3`: Upload reports to AWS S3
  - `scp-report`: Upload reports to remote servers via SCP
  - `auto-report`: Generate and export reports automatically

- **Report Features**
  - Customizable date ranges (default 30 days)
  - Key-specific filtering
  - Success rate calculations
  - Operations breakdown by type, user, and key
  - Detailed audit logs with timestamps
  - Beautiful HTML reports with styling

- **Configuration Options**
  - SMTP settings for email delivery
  - AWS credentials for S3 integration
  - SSH settings for SCP transfers
  - Environment variable configuration

### Dependencies
- Added `boto3>=1.26.0` for AWS S3 support
- Added `paramiko>=3.0.0` for SSH/SCP functionality
- Added `jinja2>=3.1.0` for HTML template rendering

## [1.1.0] - 2024-12-19

### Added
- **Key Status Management**
  - `activate-key` command to reactivate deactivated keys
  - `deactivate-key` command to deactivate keys without deletion
  - Key status display in listings (active/inactive indicators)
  - `list-keys --all` option to show inactive keys

- **Key Replacement System**
  - `replace-key` command to swap keys while preserving metadata
  - Automatic metadata transfer (owner, requester, JIRA ticket)
  - Optional old key deletion from keyring
  - Confirmation prompts for destructive operations

- **Enhanced Key Management**
  - Improved `list_keys()` method with `include_inactive` parameter
  - Better error handling and user feedback
  - Status indicators in key listings (✓ for active, ✗ for inactive)

### Changed
- Updated `list_keys()` method signature to support inactive key inclusion
- Enhanced key listing display with status indicators
- Improved user confirmation for destructive operations

### Fixed
- Better error handling in key operations
- Improved database transaction management

## [1.0.0] - 2024-12-19

### Added
- **Core GPG Key Management**
  - Add GPG keys with metadata tracking
  - Delete keys from keyring and database
  - Edit key metadata (owner, requester, JIRA ticket, notes)
  - List all tracked keys with detailed information
  - View detailed key information and recent usage

- **Usage Logging System**
  - Automatic logging of all GPG operations
  - Track encrypt, decrypt, sign, and verify operations
  - User identification and file path tracking
  - Success/failure status with error messages
  - Timestamp and recipient information

- **GPG Wrapper**
  - Intercept and log all GPG operations
  - Maintain original GPG interface
  - Automatic usage tracking for audit trails
  - Support for encrypt, decrypt, sign, and verify operations

- **Database Integration**
  - SQLite database for persistent storage
  - SQLAlchemy ORM for data management
  - GPGKey and UsageLog models
  - Automatic database initialization

- **CLI Interface**
  - Rich terminal interface with tables and panels
  - Color-coded output and status indicators
  - Interactive confirmations for destructive operations
  - Comprehensive help and usage information

- **Cross-Platform Support**
  - RedHat/CentOS/Fedora compatibility
  - Debian/Ubuntu compatibility
  - Automated installation script
  - Systemd service integration

- **Configuration Management**
  - Environment variable configuration
  - Configurable GPG home directory
  - Database path customization
  - Log level configuration

### Features
- **Key Metadata Tracking**
  - Owner information
  - Requester information
  - JIRA ticket numbers
  - Creation and update timestamps
  - Custom notes and descriptions

- **Audit Trail**
  - Complete operation logging
  - User activity tracking
  - File operation history
  - Success/failure monitoring
  - Error message capture

- **Security Features**
  - Secure key storage in GPG keyring
  - Database contains only metadata
  - Proper file permissions
  - Audit logging for compliance

### Dependencies
- `cryptography>=41.0.0` for cryptographic operations
- `gnupg>=2.3.2` for GPG integration
- `click>=8.1.0` for CLI interface
- `rich>=13.0.0` for terminal formatting
- `sqlalchemy>=2.0.0` for database management
- `python-dotenv>=1.0.0` for configuration
- `pydantic>=2.0.0` for data validation
- `tabulate>=0.9.0` for table formatting
- `colorama>=0.4.6` for cross-platform colors

---

## Version History Summary

- **1.0.0**: Initial release with core key management and logging
- **1.1.0**: Added key status management and replacement functionality
- **1.2.0**: Added comprehensive automated reporting system

## Migration Notes

### From 1.0.0 to 1.1.0
- No database schema changes required
- New CLI commands available for key activation/deactivation
- Enhanced key listing with status indicators

### From 1.1.0 to 1.2.0
- New dependencies required (boto3, paramiko, jinja2)
- New environment variables for reporting configuration
- Database schema remains compatible

## Contributing

When contributing to this project, please update this CHANGELOG.md file to document your changes. Follow the existing format and include:

- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for security vulnerability fixes

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
