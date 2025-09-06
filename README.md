# GPG Key Tracker

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Linux](https://img.shields.io/badge/Platform-Linux-green.svg)](https://www.linux.org/)
[![GPG](https://img.shields.io/badge/GPG-2.0+-red.svg)](https://gnupg.org/)

A comprehensive Python application for managing PGP/GPG keys with metadata tracking, usage logging, and automated reporting.

📖 **[Full Documentation](https://straticus1.github.io/gpg-key-tracker/)** | 🚀 **[Quick Start](#quick-start)** | 📋 **[Installation Guide](INSTALL.md)**

## 🎆 Features

### 🔑 Core Key Management
- **Add/Remove Keys**: Import and delete GPG keys with full metadata tracking
- **Key Status Control**: Activate/deactivate keys without deletion
- **Key Replacement**: Replace keys while preserving metadata and history
- **Metadata Tracking**: Track owner, requester, JIRA tickets, and notes

### 📈 Usage Monitoring
- **Operation Logging**: Track encrypt, decrypt, sign, and verify operations
- **User Identification**: Log which users performed operations
- **Audit Trail**: Complete operation history with timestamps
- **Success/Failure Tracking**: Monitor operation outcomes

### 📊 Automated Reporting
- **Multiple Formats**: CSV, JSON, and HTML reports
- **Export Options**: Email, AWS S3, SCP, or local file generation
- **Customizable Timeframes**: Reports for any date range
- **Usage Statistics**: Success rates and operation breakdowns

### 🛠️ System Integration
- **Cross-Platform**: RedHat, CentOS, Fedora, Debian, Ubuntu support
- **CLI Interface**: Rich terminal interface with tables and colors
- **Database Storage**: SQLite with SQLAlchemy ORM
- **Systemd Service**: Optional background service mode

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

For detailed installation instructions, see **[INSTALL.md](INSTALL.md)**.

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

## 📋 Installation

### Prerequisites

- Python 3.8 or higher
- GPG installed on your system
- Root or sudo access for GPG operations

### Install Dependencies

```bash
pip install -r requirements.txt
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

### Add a New Key
```bash
python gpg_tracker.py add-key --key-file /path/to/key.asc --owner "John Doe" --requester "Jane Smith" --jira-ticket "PROJ-123"
```

### List Keys
```bash
python gpg_tracker.py list-keys
python gpg_tracker.py list-keys --all  # Include inactive keys
```

### Edit Key Metadata
```bash
python gpg_tracker.py edit-key --fingerprint ABC123 --owner "New Owner"
```

### Activate/Deactivate Keys
```bash
python gpg_tracker.py activate-key --fingerprint ABC123
python gpg_tracker.py deactivate-key --fingerprint ABC123
```

### Replace a Key
```bash
python gpg_tracker.py replace-key --old-fingerprint ABC123 --new-key-file new_key.asc
```

### Delete a Key
```bash
python gpg_tracker.py delete-key --fingerprint ABC123
```

### View Usage Logs
```bash
python gpg_tracker.py logs
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

- **[Installation Guide](INSTALL.md)**: Comprehensive installation instructions
- **[Changelog](CHANGELOG.md)**: Version history and feature updates
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
