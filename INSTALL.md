# GPG Key Tracker - Installation Guide

This guide provides comprehensive installation instructions for the GPG Key Tracker on various Linux systems.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Quick Installation](#quick-installation)
3. [Manual Installation](#manual-installation)
4. [Post-Installation Setup](#post-installation-setup)
5. [Verification](#verification)
6. [Troubleshooting](#troubleshooting)
7. [Uninstallation](#uninstallation)

## System Requirements

### Operating Systems
- **RedHat Enterprise Linux** 7, 8, 9
- **CentOS** 7, 8, 9
- **Fedora** 35+
- **Debian** 10, 11, 12
- **Ubuntu** 18.04, 20.04, 22.04, 24.04

### System Dependencies
- **Python** 3.8 or higher
- **GPG** 2.0 or higher
- **SQLite** 3.0 or higher
- **pip** for Python package management
- **sudo** access for system package installation

### Hardware Requirements
- **RAM**: Minimum 512MB, Recommended 1GB+
- **Disk Space**: 100MB for application + space for key storage
- **CPU**: Any modern x86_64 or ARM64 processor

## Quick Installation

### Automated Installation Script

For most users, the automated installation script is the easiest way to get started:

```bash
# Clone the repository
git clone https://github.com/straticus1/gpg-key-tracker.git
cd gpg-key-tracker

# Make the install script executable
chmod +x install.sh

# Run the installation
./install.sh
```

The script will:
- Detect your operating system
- Install system dependencies
- Install Python dependencies
- Set up GPG directory with proper permissions
- Initialize the database
- Create configuration files
- Optionally set up systemd service

## Manual Installation

### Step 1: Install System Dependencies

#### RedHat/CentOS/Fedora

```bash
# For Fedora (dnf)
sudo dnf install gnupg2 python3 python3-pip sqlite

# For RHEL/CentOS 7 (yum)
sudo yum install gnupg2 python3 python3-pip sqlite

# For RHEL/CentOS 8+ (dnf)
sudo dnf install gnupg2 python3 python3-pip sqlite
```

#### Debian/Ubuntu

```bash
# Update package list
sudo apt-get update

# Install dependencies
sudo apt-get install gnupg2 python3 python3-pip sqlite3
```

### Step 2: Clone Repository

```bash
git clone https://github.com/straticus1/gpg-key-tracker.git
cd gpg-key-tracker
```

### Step 3: Install Python Dependencies

```bash
# Upgrade pip
python3 -m pip install --upgrade pip

# Install requirements
pip3 install -r requirements.txt
```

### Step 4: Set Up GPG Environment

```bash
# Create GPG home directory if needed
mkdir -p ~/.gnupg
chmod 700 ~/.gnupg

# Set proper permissions
chmod 600 ~/.gnupg/* 2>/dev/null || true
```

### Step 5: Configure Application

```bash
# Copy configuration template
cp config.env.example .env

# Edit configuration (optional)
nano .env
```

### Step 6: Initialize Database

```bash
python3 gpg_tracker.py init
```

## Post-Installation Setup

### Configuration File

Edit the `.env` file to customize your installation:

```bash
# GPG Configuration
GPG_HOME=/home/user/.gnupg
DATABASE_PATH=./gpg_tracker.db
LOG_LEVEL=INFO

# Email Configuration (for reports)
SMTP_HOST=smtp.company.com
SMTP_PORT=587
SMTP_USER=your-email@company.com
SMTP_PASSWORD=your-password
SMTP_TLS=true

# AWS S3 Configuration (for report uploads)
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=us-east-1

# SSH Configuration (for SCP uploads)
SSH_HOST=server.company.com
SSH_USER=username
SSH_KEY_PATH=/path/to/ssh/key
```

### Systemd Service (Optional)

To run GPG Key Tracker as a service:

```bash
# Copy service file
sudo cp gpg-tracker.service /etc/systemd/system/

# Edit service file if needed
sudo nano /etc/systemd/system/gpg-tracker.service

# Reload systemd
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable gpg-tracker.service

# Start service
sudo systemctl start gpg-tracker.service

# Check status
sudo systemctl status gpg-tracker.service
```

### File Permissions

Ensure proper file permissions for security:

```bash
# Application files
chmod 755 gpg_tracker.py gpg_wrapper.py
chmod 644 *.py requirements.txt

# Configuration files
chmod 600 .env

# GPG directory
chmod 700 ~/.gnupg
chmod 600 ~/.gnupg/*
```

## Verification

### Basic Functionality Test

```bash
# Initialize database (if not done already)
python3 gpg_tracker.py init

# List current keys
python3 gpg_tracker.py list-keys

# Check help
python3 gpg_tracker.py --help

# Test GPG wrapper
python3 gpg_wrapper.py --help
```

### Add Test Key

```bash
# Generate a test key (optional)
gpg --batch --gen-key << EOF
%no-protection
Key-Type: RSA
Key-Length: 2048
Name-Real: Test User
Name-Email: test@example.com
Expire-Date: 0
EOF

# Export the test key
gpg --armor --export test@example.com > test_key.asc

# Add to tracker
python3 gpg_tracker.py add-key --key-file test_key.asc --owner "Test User" --requester "Admin" --jira-ticket "TEST-001"

# List keys to verify
python3 gpg_tracker.py list-keys
```

### Database Verification

```bash
# Check database file exists
ls -la gpg_tracker.db

# Check database tables (requires sqlite3)
sqlite3 gpg_tracker.db ".tables"
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied Errors

```bash
# Fix GPG directory permissions
chmod 700 ~/.gnupg
chmod 600 ~/.gnupg/*

# Fix application permissions
chmod +x gpg_tracker.py gpg_wrapper.py
```

#### 2. Python Module Not Found

```bash
# Reinstall requirements
pip3 install --force-reinstall -r requirements.txt

# Check Python path
python3 -c "import sys; print(sys.path)"
```

#### 3. GPG Command Not Found

```bash
# Install GPG
# RedHat/Fedora
sudo dnf install gnupg2

# Debian/Ubuntu
sudo apt-get install gnupg2

# Verify installation
gpg --version
```

#### 4. Database Initialization Fails

```bash
# Remove old database
rm -f gpg_tracker.db

# Reinitialize
python3 gpg_tracker.py init

# Check SQLite installation
sqlite3 --version
```

#### 5. Import Errors

```bash
# Check all dependencies
pip3 list | grep -E "(click|rich|sqlalchemy|gnupg|cryptography)"

# Reinstall specific package
pip3 install --upgrade package-name
```

### Debug Mode

Run with debug logging to troubleshoot issues:

```bash
# Set debug level in .env file
echo "LOG_LEVEL=DEBUG" >> .env

# Or run with debug flag
python3 gpg_tracker.py --debug list-keys
```

### Log Files

Check system logs for errors:

```bash
# Application logs
tail -f /var/log/gpg-tracker.log

# System logs
journalctl -u gpg-tracker.service -f

# GPG logs
tail -f ~/.gnupg/gpg.log
```

## Uninstallation

### Remove Application

```bash
# Stop service if running
sudo systemctl stop gpg-tracker.service
sudo systemctl disable gpg-tracker.service

# Remove service file
sudo rm -f /etc/systemd/system/gpg-tracker.service
sudo systemctl daemon-reload

# Remove application directory
cd ..
rm -rf gpg-key-tracker

# Remove Python packages (optional)
pip3 uninstall -y -r requirements.txt
```

### Remove Database and Configuration

```bash
# Remove database (WARNING: This removes all tracked key metadata)
rm -f gpg_tracker.db

# Remove configuration
rm -f .env

# GPG keys remain in keyring unless manually removed
```

### Remove System Dependencies

```bash
# RedHat/Fedora (only if not needed by other applications)
sudo dnf remove gnupg2

# Debian/Ubuntu
sudo apt-get remove gnupg2
```

## Advanced Installation Options

### Virtual Environment Installation

For isolated Python environment:

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Use with full path or activate environment first
./venv/bin/python gpg_tracker.py list-keys
```

### Docker Installation

Create a Dockerfile for containerized deployment:

```dockerfile
FROM python:3.11-alpine

RUN apk add --no-cache gnupg sqlite

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["python", "gpg_tracker.py", "--help"]
```

### Custom Installation Path

```bash
# Install to custom directory
sudo mkdir -p /opt/gpg-tracker
sudo cp -r * /opt/gpg-tracker/
sudo chown -R $USER:$USER /opt/gpg-tracker

# Create symlinks
sudo ln -s /opt/gpg-tracker/gpg_tracker.py /usr/local/bin/gpg-tracker
sudo ln -s /opt/gpg-tracker/gpg_wrapper.py /usr/local/bin/gpg-wrapper
```

## Support

For installation issues:

1. Check this guide first
2. Review the [README.md](README.md) for usage information
3. Check the [CHANGELOG.md](CHANGELOG.md) for version-specific notes
4. Submit issues on GitHub: [https://github.com/straticus1/gpg-key-tracker/issues](https://github.com/straticus1/gpg-key-tracker/issues)

---

**Author**: Ryan J Coleman - [coleman.ryan@gmail.com](mailto:coleman.ryan@gmail.com)

**License**: MIT - See [LICENSE](LICENSE) file for details
