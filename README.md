# GPG Key Tracker

A comprehensive GPG key management system with both CLI and server components for tracking, monitoring, and managing GPG keys across your infrastructure.

## 🚀 Features

### Client Features
- Track and monitor GPG keys
- Automated key backup
- Key expiration alerts
- Usage reporting
- Interactive key management

### Server Features
- RESTful API for key management
- Centralized key tracking
- Multi-user support
- API key authentication
- Docker deployment support

## 🏗 Project Structure

```
./
├── config/               # Configuration files
│   ├── .env.server.example
│   └── config.env.example
├── docker/               # Docker configuration
│   ├── Dockerfile.server
│   └── docker-compose.server.yml
├── docs/                 # Documentation
│   ├── CHANGELOG.md
│   ├── INSTALL.md
│   └── server/
├── examples/             # Usage examples
├── lib/                  # Core library code
├── scripts/              # Installation scripts
├── server/               # Server components
│   ├── gpg_server.py
│   └── server_cli.py
└── tests/                # Test suite
```

## 🛠 Installation

### Client Installation
```bash
# Install client components
pip install -r requirements.txt

# Configure settings
cp config/config.env.example config/config.env
```

### Server Installation
```bash
# Using Docker
docker-compose -f docker/docker-compose.server.yml up -d

# Manual installation
pip install -r docker/requirements_server.txt
cp config/.env.server.example config/.env.server
./server/start_server.py
```

## 📚 Documentation

- [Installation Guide](docs/INSTALL.md)
- [Server Setup](docs/server/SETUP_SERVER.md)
- [API Documentation](docs/server/API_SEARCH_GUIDE.md)
- [Feature Summary](docs/FEATURE_SUMMARY.md)
- [Security Policy](docs/SECURITY.md)

## 🔒 Security

- End-to-end GPG key encryption
- API key authentication
- Secure key backup system
- Role-based access control

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)

A comprehensive GPG key management system with both standalone tracking capabilities and a secure HTTP API server for enterprise key management.

📖 **[Server Documentation](docs/server/SERVER_README.md)** | 🚀 **[Quick Start](#quick-start)** | 📋 **[Setup Guide](docs/server/SETUP_SERVER.md)** | 🔍 **[Search API Guide](docs/server/API_SEARCH_GUIDE.md)**

## 🎆 Features

### 🔧 Standalone GPG Tracker
- **GPG Key Management**: Import, list, search, and manage GPG keys with metadata tracking
- **Usage Monitoring**: Track encrypt, decrypt, sign, and verify operations with full audit trails
- **Expiration Tracking**: Monitor key expiration dates with automated alerts
- **Backup & Restore**: Automated backup system with configurable retention policies
- **Interactive Mode**: User-friendly interactive CLI interface with rich terminal output
- **Report Generation**: Detailed usage reports in CSV, JSON, and HTML formats
- **Prometheus Integration**: Export metrics for operational monitoring systems

### 🌐 GPG Key Server (Enterprise)
- **🔐 HTTP API Server**: FastAPI-based secure API with SSL/TLS support on ports 80/443
- **🔑 API Key Authentication**: Mandatory authentication for all operations with rate limiting
- **👑 Master Key Validation**: Organizational signing & encryption keys for key validation
- **🔍 Enhanced Search**: Advanced search by fingerprint, email, key ID, name, or raw key upload
- **⚡ GPG Operations**: Complete support for read, list, sign, encrypt, info, and search operations
- **👨‍💼 Admin Interface**: Full API key and master key management with comprehensive CLI tools
- **🐳 Docker Support**: Production-ready containerization with Docker Compose
- **📊 Monitoring**: Health checks, usage statistics, and Prometheus metrics integration
- **🏢 Organizational Keys**: Default organizational signing and encryption keys for validation

### 🔒 Security & Enterprise Features
- **Input Validation**: Comprehensive sanitization and validation for all inputs
- **Rate Limiting**: Configurable per-API-key rate limiting to prevent abuse
- **Audit Logging**: Complete operation history and usage tracking for compliance
- **Permission System**: Granular permissions for operations and key access
- **SSL/TLS Support**: Full HTTPS support with certificate validation
- **Master Signatures**: All keys must be signed by organizational master keys
- **Secure Storage**: SHA-256 hashed API keys and encrypted sensitive data

### 📦 Deployment & DevOps
- **Docker Support**: Production-ready containerization
- **Kubernetes Manifests**: Cloud-native deployment
- **CI/CD Pipeline**: Automated testing and deployment
- **Monitoring**: Prometheus metrics and Grafana dashboards
- **Service Management**: Systemd integration for production

## 🚀 Quick Start

```bash
# 1. Clone and install
git clone https://github.com/straticus1/gpg-key-tracker.git
cd gpg-key-tracker
./install.sh

# 2. Initialize database
python3 gpg_tracker.py init

# 3. Add your first key
python3 gpg_tracker.py add-key --key-file /path/to/key.asc --owner "John Doe" --requester "IT Security"

# 4. List all keys
python3 gpg_tracker.py list-keys

# 5. Generate usage report
python3 gpg_tracker.py generate-report --format html
```

For detailed installation instructions, see **[INSTALL.md](docs/INSTALL.md)**.

## 📚 Table of Contents

1. [🎆 Features](#-features)
2. [🚀 Quick Start](#-quick-start)
3. [📋 Installation](#-installation)
4. [💻 Usage](#-usage)
5. [⚙️ Configuration](#-configuration)
6. [📈 Reporting](#-reporting)
7. [🔒 Security](#-security)
8. [📝 Documentation](#-documentation)
9. [🤝 Contributing](#-contributing)
10. [📜 License](#-license)

## 📋 Quick Start

### 🔧 Standalone Tracker

```bash
# Clone and install
git clone https://github.com/your-org/gpg-key-tracker.git
cd gpg-key-tracker
pip install -r requirements.txt

# Initialize database
python gpg_tracker.py --init-db

# Run interactive mode
python gpg_tracker.py --interactive

# Or manage keys directly
python gpg_tracker.py --add-key /path/to/key.asc --owner "user@example.com" --requester "admin@example.com"
python gpg_tracker.py --list-keys
```

### 🌐 GPG Key Server

```bash
# Install server dependencies
pip install -r requirements.txt -r docker/requirements_server.txt

# Configure server
cp config/.env.server.example .env
# Edit .env and set GPG_SERVER_ADMIN_API_KEY to a secure value

# Initialize and start server
python start_gpg_server.py --init-only
python server_cli_wrapper.py master-key create-organizational \
  --organization "Your Organization" \
  --name "Production Keys" \
  --email "admin@yourorg.com"
python start_gpg_server.py

# Create API keys and test
python server_cli_wrapper.py api-key create --name "My App" --owner "app@example.com" --operations read list search
curl -H "X-API-Key: YOUR_API_KEY" https://localhost:8443/keys
```

### 🐳 Docker Deployment (Server)

```bash
# Quick Docker setup
cp config/.env.server.example .env
# Edit .env with your settings
docker-compose -f docker/docker-compose.server.yml up -d

# Initialize organizational keys
docker-compose exec gpg-server python server_cli.py master-key create-organizational \
  --organization "Your Organization" \
  --name "Production Keys" \
  --email "admin@yourorg.com"
```

## 📋 Installation

### Prerequisites

- Python 3.8 or higher
- GPG installed on your system
- Root or sudo access for GPG operations

### Install Dependencies

```bash
# Core dependencies
pip install -r requirements.txt

# Server dependencies (if using GPG Key Server)
pip install -r docker/requirements_server.txt
```

### System Setup

#### RedHat/CentOS/Fedora:
```bash
sudo yum install gnupg2
# or
sudo dnf install gnupg2
```

#### Debian/Ubuntu:
```bash
sudo apt-get install gnupg2
```

## 💻 Usage

### Initialize the Database
```bash
python gpg_tracker.py init
```

### Interactive Mode
```bash
# Start user-friendly interactive mode
python gpg_tracker.py interactive
```

### Key Management

#### Add a New Key
```bash
python gpg_tracker.py add-key --key-file /path/to/key.asc --owner "John Doe" --requester "Jane Smith" --jira-ticket "PROJ-123"
# Alias: python gpg_tracker.py add -k /path/to/key.asc -o "John Doe" -r "Jane Smith"
```

#### List Keys
```bash
python gpg_tracker.py list-keys
python gpg_tracker.py list-keys --all  # Include inactive keys
# Aliases: python gpg_tracker.py ls (active only) or python gpg_tracker.py ll (all keys)
```

#### Edit Key Metadata
```bash
python gpg_tracker.py edit-key --fingerprint ABC123 --owner "New Owner"
```

#### Activate/Deactivate Keys
```bash
python gpg_tracker.py activate-key --fingerprint ABC123
python gpg_tracker.py deactivate-key --fingerprint ABC123
```

#### Replace a Key
```bash
python gpg_tracker.py replace-key --old-fingerprint ABC123 --new-key-file new_key.asc
```

#### Delete a Key
```bash
python gpg_tracker.py delete-key --fingerprint ABC123
# Alias: python gpg_tracker.py rm --fingerprint ABC123
```

### Key Expiration Management

#### Check Expiring Keys
```bash
python gpg_tracker.py expiring-keys --days 30
# Alias: python gpg_tracker.py expiring -d 30
```

#### Check Expired Keys
```bash
python gpg_tracker.py expired-keys
# Alias: python gpg_tracker.py expired
```

#### Update Expiration Status
```bash
python gpg_tracker.py update-expiry
```

### Usage Monitoring

#### View Usage Logs
```bash
python gpg_tracker.py logs
python gpg_tracker.py logs --fingerprint ABC123 --limit 100
# Alias: python gpg_tracker.py log -f ABC123 -l 100
```

### System Health & Monitoring

#### Health Check
```bash
python gpg_tracker.py health-check
# Alias: python gpg_tracker.py status
```

#### View Metrics
```bash
python gpg_tracker.py metrics
python gpg_tracker.py export-metrics --format json
# Alias: python gpg_tracker.py stats
```

### Backup & Restore

#### Create Backup
```bash
python gpg_tracker.py create-backup
python gpg_tracker.py create-backup --name "pre-migration-backup"
```

#### List Backups
```bash
python gpg_tracker.py list-backups
```

#### Restore from Backup
```bash
python gpg_tracker.py restore-backup --backup-name backup_20240915_120000
python gpg_tracker.py restore-backup --backup-name my-backup --components database,gpg_keyring
```

#### Delete Backup
```bash
python gpg_tracker.py delete-backup --backup-name old-backup
```

### Generate Reports
```bash
# Generate CSV report for last 30 days
python gpg_tracker.py generate-report --format csv

# Generate HTML report for last 7 days
python gpg_tracker.py generate-report --days 7 --format html

# Generate report for specific key
python gpg_tracker.py generate-report --fingerprint ABC123 --format json
```

### Export Reports
```bash
# Email report
python gpg_tracker.py email-report --report-file report.csv --recipients "admin@company.com,security@company.com"

# Upload to S3
python gpg_tracker.py upload-to-s3 --report-file report.csv --bucket my-reports-bucket

# Upload via SCP
python gpg_tracker.py scp-report --report-file report.csv --host server.company.com --path /reports

# Auto-generate and export
python gpg_tracker.py auto-report --format html --recipients "admin@company.com" --s3-bucket my-reports
```

### Using the GPG Wrapper
```bash
python gpg_wrapper.py encrypt --file document.txt --recipient user@example.com
python gpg_wrapper.py decrypt --file document.txt.gpg
```

## ⚙️ Configuration

Create a `.env` file in the project root:
```
GPG_HOME=/home/user/.gnupg
DATABASE_PATH=./gpg_tracker.db
LOG_LEVEL=INFO
```

## 🔒 Security Considerations

- The application logs all GPG key usage for audit purposes
- Keys are stored securely in the GPG keyring
- Database contains only metadata, not the actual keys
- All operations are logged with timestamps and user information

## 📈 Reporting

GPG Key Tracker includes comprehensive reporting capabilities:

### Generate Reports
```bash
# CSV report for last 30 days
python3 gpg_tracker.py generate-report --format csv

# HTML report for specific timeframe
python3 gpg_tracker.py generate-report --days 7 --format html

# JSON report for specific key
python3 gpg_tracker.py generate-report --fingerprint ABC123 --format json
```

### Export Options
- **Email**: Automated email delivery with SMTP
- **AWS S3**: Upload reports to cloud storage
- **SCP**: Secure copy to remote servers
- **Local**: Save to filesystem

### Report Features
- Usage statistics and success rates
- Operation breakdown by type and user
- Key-specific filtering
- Customizable date ranges
- Beautiful HTML formatting

## 📝 Documentation

- **[Installation Guide](docs/INSTALL.md)**: Comprehensive installation instructions
- **[Changelog](docs/CHANGELOG.md)**: Version history and feature updates
- **[GitHub Pages](https://straticus1.github.io/gpg-key-tracker/)**: Full documentation website
- **In-app Help**: Use `--help` with any command for detailed usage

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/yourusername/gpg-key-tracker.git`
3. **Create** a feature branch: `git checkout -b feature/amazing-feature`
4. **Make** your changes and add tests
5. **Commit** your changes: `git commit -m 'Add amazing feature'`
6. **Push** to your fork: `git push origin feature/amazing-feature`
7. **Submit** a Pull Request

### Development Setup
```bash
# Clone the repository
git clone https://github.com/straticus1/gpg-key-tracker.git
cd gpg-key-tracker

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run tests
python3 -m pytest test_gpg_tracker.py
```

### Contribution Guidelines
- Follow PEP 8 style guidelines
- Add tests for new features
- Update documentation as needed
- Include clear commit messages

## 🐛 Issues and Support

Found a bug or need help?

- **GitHub Issues**: [Submit an issue](https://github.com/straticus1/gpg-key-tracker/issues)
- **Documentation**: Check the [full documentation](https://straticus1.github.io/gpg-key-tracker/)
- **Email**: [coleman.ryan@gmail.com](mailto:coleman.ryan@gmail.com)

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Ryan J Coleman**
- Email: [coleman.ryan@gmail.com](mailto:coleman.ryan@gmail.com)
- GitHub: [@straticus1](https://github.com/straticus1)
- Role: *Design and Development*

---

<div align="center">

**🚀 Made with ❤️ for secure GPG key management**

[Documentation](https://straticus1.github.io/gpg-key-tracker/) • [Issues](https://github.com/straticus1/gpg-key-tracker/issues) • [Releases](https://github.com/straticus1/gpg-key-tracker/releases)

</div>
