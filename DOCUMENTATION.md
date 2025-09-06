# GPG Key Tracker Documentation

## Overview

The GPG Key Tracker is a comprehensive Python application designed to manage PGP/GPG keys with full audit trails and metadata tracking. It provides a secure way to track key ownership, usage, and maintain compliance requirements.

## Architecture

### Core Components

1. **Database Layer** (`models.py`)
   - SQLAlchemy ORM models
   - GPGKey table for key metadata
   - UsageLog table for audit trails

2. **GPG Manager** (`gpg_manager.py`)
   - Core business logic
   - Key management operations
   - Database integration

3. **GPG Wrapper** (`gpg_wrapper.py`)
   - Intercepts GPG operations
   - Logs all usage automatically
   - Maintains original GPG interface

4. **CLI Interface** (`gpg_tracker.py`)
   - Rich terminal interface
   - Command-line operations
   - User-friendly output

## Database Schema

### GPGKey Table
```sql
CREATE TABLE gpg_keys (
    id INTEGER PRIMARY KEY,
    fingerprint VARCHAR(40) UNIQUE NOT NULL,
    key_id VARCHAR(16) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    name VARCHAR(255),
    owner VARCHAR(255) NOT NULL,
    requester VARCHAR(255) NOT NULL,
    jira_ticket VARCHAR(50),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    notes TEXT
);
```

### UsageLog Table
```sql
CREATE TABLE usage_logs (
    id INTEGER PRIMARY KEY,
    fingerprint VARCHAR(40) NOT NULL,
    operation VARCHAR(50) NOT NULL,
    user VARCHAR(255) NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    file_path VARCHAR(500),
    recipient VARCHAR(255),
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT
);
```

## Installation

### Prerequisites
- Python 3.8 or higher
- GPG2 installed on the system
- Root or sudo access for system-wide installation

### Quick Installation
```bash
# Clone the repository
git clone <repository-url>
cd gpg-key-tracker

# Run the installation script
./install.sh
```

### Manual Installation
```bash
# Install system dependencies
# For RedHat/CentOS/Fedora:
sudo dnf install gnupg2 python3 python3-pip sqlite

# For Debian/Ubuntu:
sudo apt-get install gnupg2 python3 python3-pip sqlite3

# Install Python dependencies
pip3 install -r requirements.txt

# Initialize the database
python3 gpg_tracker.py init
```

## Configuration

### Environment Variables
Create a `.env` file in the project root:

```bash
# GPG home directory
GPG_HOME=/home/user/.gnupg

# Database path
DATABASE_PATH=./gpg_tracker.db

# Log level
LOG_LEVEL=INFO

# Optional: Custom GPG binary
GPG_BINARY=/usr/bin/gpg2
```

### GPG Configuration
Ensure your GPG configuration is properly set up:

```bash
# Create GPG home directory
mkdir -p ~/.gnupg
chmod 700 ~/.gnupg

# Set up GPG configuration
echo "use-agent" >> ~/.gnupg/gpg.conf
echo "pinentry-program /usr/bin/pinentry-curses" >> ~/.gnupg/gpg.conf
```

## Usage

### Key Management

#### Add a New Key
```bash
python3 gpg_tracker.py add-key \
    --key-file /path/to/key.asc \
    --owner "John Doe" \
    --requester "Jane Smith" \
    --jira-ticket "PROJ-123" \
    --notes "Production key for API encryption"
```

#### List Keys
```bash
python3 gpg_tracker.py list-keys
python3 gpg_tracker.py list-keys --all  # Include inactive keys
```

#### Get Key Details
```bash
python3 gpg_tracker.py key-info --fingerprint ABC123...
```

#### Edit Key Metadata
```bash
python3 gpg_tracker.py edit-key \
    --fingerprint ABC123... \
    --owner "New Owner" \
    --jira-ticket "PROJ-456"
```

#### Activate/Deactivate Keys
```bash
python3 gpg_tracker.py activate-key --fingerprint ABC123...
python3 gpg_tracker.py deactivate-key --fingerprint ABC123...
```

#### Replace a Key
```bash
python3 gpg_tracker.py replace-key \
    --old-fingerprint ABC123... \
    --new-key-file new_key.asc \
    --owner "New Owner" \
    --delete-old
```

#### Delete a Key
```bash
python3 gpg_tracker.py delete-key --fingerprint ABC123...
```

### Usage Logs

#### View Usage Logs
```bash
# View all logs
python3 gpg_tracker.py logs

# View logs for specific key
python3 gpg_tracker.py logs --fingerprint ABC123...

# Limit number of logs
python3 gpg_tracker.py logs --limit 100
```

### GPG Operations with Logging

#### Encrypt a File
```bash
python3 gpg_wrapper.py encrypt \
    --file document.txt \
    --recipient user@example.com \
    --output document.txt.gpg
```

#### Decrypt a File
```bash
python3 gpg_wrapper.py decrypt \
    --file document.txt.gpg \
    --output document.txt
```

#### Sign a File
```bash
python3 gpg_wrapper.py sign \
    --file document.txt \
    --output document.txt.sig
```

#### Verify a Signature
```bash
python3 gpg_wrapper.py verify \
    --file document.txt \
    --signature document.txt.sig
```

### Report Generation and Export

#### Generate Reports
```bash
# Generate CSV report for last 30 days
python3 gpg_tracker.py generate-report --format csv

# Generate HTML report for last 7 days
python3 gpg_tracker.py generate-report --days 7 --format html

# Generate JSON report for specific key
python3 gpg_tracker.py generate-report --fingerprint ABC123... --format json
```

#### Export Reports
```bash
# Email report
python3 gpg_tracker.py email-report \
    --report-file report.csv \
    --recipients "admin@company.com,security@company.com"

# Upload to S3
python3 gpg_tracker.py upload-to-s3 \
    --report-file report.csv \
    --bucket my-reports-bucket

# Upload via SCP
python3 gpg_tracker.py scp-report \
    --report-file report.csv \
    --host server.company.com \
    --path /reports

# Auto-generate and export
python3 gpg_tracker.py auto-report \
    --format html \
    --recipients "admin@company.com" \
    --s3-bucket my-reports
```

## Security Considerations

### Key Storage
- GPG keys are stored in the standard GPG keyring
- Database contains only metadata, not actual keys
- Key files should be stored securely and deleted after import

### Access Control
- GPG home directory should have restricted permissions (700)
- Database file should be protected from unauthorized access
- Consider using encrypted storage for the database

### Audit Trail
- All key operations are logged with timestamps
- User information is captured for each operation
- Failed operations are logged with error details

### Best Practices
1. **Key Rotation**: Regularly rotate keys and update metadata
2. **Access Review**: Periodically review key ownership and access
3. **Backup**: Regularly backup the database and GPG keyring
4. **Monitoring**: Set up alerts for unusual key usage patterns

## API Reference

### GPGManager Class

#### Methods

##### `add_key(key_file, owner, requester, jira_ticket=None, notes=None)`
Add a new GPG key to the tracker.

**Parameters:**
- `key_file` (str): Path to the key file
- `owner` (str): Key owner name
- `requester` (str): Person who requested the key
- `jira_ticket` (str, optional): JIRA ticket number
- `notes` (str, optional): Additional notes

**Returns:** `bool` - Success status

##### `delete_key(fingerprint)`
Delete a GPG key from the tracker.

**Parameters:**
- `fingerprint` (str): Key fingerprint

**Returns:** `bool` - Success status

##### `edit_key(fingerprint, **kwargs)`
Edit key metadata.

**Parameters:**
- `fingerprint` (str): Key fingerprint
- `**kwargs`: Fields to update (owner, requester, jira_ticket, notes, is_active)

**Returns:** `bool` - Success status

##### `activate_key(fingerprint)`
Activate a deactivated key.

**Parameters:**
- `fingerprint` (str): Key fingerprint

**Returns:** `bool` - Success status

##### `deactivate_key(fingerprint)`
Deactivate an active key.

**Parameters:**
- `fingerprint` (str): Key fingerprint

**Returns:** `bool` - Success status

##### `replace_key(old_fingerprint, new_key_file, owner=None, requester=None, jira_ticket=None, notes=None, delete_old=False)`
Replace an existing key with a new one.

**Parameters:**
- `old_fingerprint` (str): Fingerprint of key to replace
- `new_key_file` (str): Path to the new key file
- `owner` (str, optional): New owner name
- `requester` (str, optional): New requester name
- `jira_ticket` (str, optional): New JIRA ticket number
- `notes` (str, optional): Additional notes
- `delete_old` (bool): Whether to delete old key from keyring

**Returns:** `bool` - Success status

##### `list_keys(include_inactive=False)`
Get tracked keys.

**Parameters:**
- `include_inactive` (bool): Whether to include inactive keys

**Returns:** `List[Dict]` - List of key dictionaries

### ReportGenerator Class

#### Methods

##### `generate_usage_report(days=30, key_fingerprint=None)`
Generate a comprehensive usage report.

**Parameters:**
- `days` (int): Number of days to include in report
- `key_fingerprint` (str, optional): Filter by specific key

**Returns:** `Dict[str, Any]` - Report data dictionary

##### `export_to_csv(report_data, output_file)`
Export report to CSV format.

**Parameters:**
- `report_data` (Dict): Report data from generate_usage_report
- `output_file` (str): Output file path

**Returns:** `str` - Path to generated file

##### `export_to_json(report_data, output_file)`
Export report to JSON format.

**Parameters:**
- `report_data` (Dict): Report data from generate_usage_report
- `output_file` (str): Output file path

**Returns:** `str` - Path to generated file

##### `export_to_html(report_data, output_file)`
Export report to HTML format.

**Parameters:**
- `report_data` (Dict): Report data from generate_usage_report
- `output_file` (str): Output file path

**Returns:** `str` - Path to generated file

### ReportExporter Class

#### Methods

##### `send_email_report(report_file, recipients, subject=None, body=None)`
Send report via email.

**Parameters:**
- `report_file` (str): Path to report file
- `recipients` (List[str]): List of email addresses
- `subject` (str, optional): Email subject
- `body` (str, optional): Email body

**Returns:** `bool` - Success status

##### `upload_to_s3(report_file, bucket, key=None)`
Upload report to S3 bucket.

**Parameters:**
- `report_file` (str): Path to report file
- `bucket` (str): S3 bucket name
- `key` (str, optional): S3 object key

**Returns:** `bool` - Success status

##### `scp_to_remote(report_file, remote_host, remote_path, username=None, password=None, key_file=None)`
Upload report to remote server via SCP.

**Parameters:**
- `report_file` (str): Path to report file
- `remote_host` (str): Remote host address
- `remote_path` (str): Remote directory path
- `username` (str, optional): SSH username
- `password` (str, optional): SSH password
- `key_file` (str, optional): SSH private key file

**Returns:** `bool` - Success status

##### `log_usage(fingerprint, operation, user, file_path=None, recipient=None, success=True, error_message=None)`
Log a key usage operation.

**Parameters:**
- `fingerprint` (str): Key fingerprint
- `operation` (str): Operation type (encrypt, decrypt, sign, verify)
- `user` (str): User performing the operation
- `file_path` (str, optional): File being processed
- `recipient` (str, optional): Recipient for encryption
- `success` (bool): Operation success status
- `error_message` (str, optional): Error message if failed

### GPGWrapper Class

#### Methods

##### `encrypt(file_path, recipient, output_file=None)`
Encrypt a file and log the operation.

**Parameters:**
- `file_path` (str): File to encrypt
- `recipient` (str): Recipient email or identifier
- `output_file` (str, optional): Output file path

**Returns:** `bool` - Success status

##### `decrypt(file_path, output_file=None)`
Decrypt a file and log the operation.

**Parameters:**
- `file_path` (str): File to decrypt
- `output_file` (str, optional): Output file path

**Returns:** `bool` - Success status

## Troubleshooting

### Common Issues

#### GPG Not Found
```bash
# Check GPG installation
which gpg2

# Install GPG if missing
# RedHat/CentOS/Fedora:
sudo dnf install gnupg2

# Debian/Ubuntu:
sudo apt-get install gnupg2
```

#### Permission Denied
```bash
# Fix GPG directory permissions
chmod 700 ~/.gnupg
chmod 600 ~/.gnupg/gpg.conf
```

#### Database Errors
```bash
# Reinitialize database
python3 gpg_tracker.py init

# Check database file permissions
ls -la gpg_tracker.db
```

#### Key Import Failures
```bash
# Check key file format
gpg2 --list-packets key.asc

# Verify key file integrity
gpg2 --verify key.asc
```

### Log Analysis

#### Check Application Logs
```bash
# View recent logs
python3 gpg_tracker.py logs --limit 50

# Filter by operation type
python3 gpg_tracker.py logs | grep "encrypt"

# Check for failed operations
python3 gpg_tracker.py logs | grep "✗"
```

#### Database Queries
```bash
# Connect to database
sqlite3 gpg_tracker.db

# View all keys
SELECT fingerprint, owner, created_at FROM gpg_keys;

# View recent usage
SELECT timestamp, operation, user, success FROM usage_logs ORDER BY timestamp DESC LIMIT 10;
```

## Development

### Running Tests
```bash
python3 test_gpg_tracker.py
```

### Code Style
The project follows PEP 8 style guidelines. Use a linter:
```bash
pip install flake8
flake8 *.py
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## Author

**Ryan J Coleman** - *Design and Development* - [coleman.ryan@gmail.com](mailto:coleman.ryan@gmail.com)

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the logs for error messages
3. Create an issue in the repository
4. Contact the development team
