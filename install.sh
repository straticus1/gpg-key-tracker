#!/bin/bash

# GPG Key Tracker Installation Script
# Supports RedHat/CentOS/Fedora and Debian/Ubuntu systems

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        print_error "Cannot detect OS"
        exit 1
    fi
}

# Install system dependencies
install_system_deps() {
    print_status "Installing system dependencies..."
    
    if [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Fedora"* ]]; then
        # RedHat/CentOS/Fedora
        if command -v dnf &> /dev/null; then
            sudo dnf install -y gnupg2 python3 python3-pip sqlite
        elif command -v yum &> /dev/null; then
            sudo yum install -y gnupg2 python3 python3-pip sqlite
        else
            print_error "No supported package manager found"
            exit 1
        fi
    elif [[ "$OS" == *"Debian"* ]] || [[ "$OS" == *"Ubuntu"* ]]; then
        # Debian/Ubuntu
        sudo apt-get update
        sudo apt-get install -y gnupg2 python3 python3-pip sqlite3
    else
        print_error "Unsupported OS: $OS"
        exit 1
    fi
    
    print_success "System dependencies installed"
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    # Upgrade pip
    python3 -m pip install --upgrade pip
    
    # Install requirements
    pip3 install -r requirements.txt
    
    print_success "Python dependencies installed"
}

# Setup GPG directory
setup_gpg() {
    print_status "Setting up GPG directory..."
    
    # Create GPG home directory if it doesn't exist
    if [ ! -d ~/.gnupg ]; then
        mkdir -p ~/.gnupg
        chmod 700 ~/.gnupg
        print_success "Created GPG home directory"
    fi
    
    # Set proper permissions
    chmod 700 ~/.gnupg
    if [ -f ~/.gnupg/gpg.conf ]; then
        chmod 600 ~/.gnupg/gpg.conf
    fi
    
    print_success "GPG directory configured"
}

# Initialize database
init_database() {
    print_status "Initializing database..."
    
    python3 gpg_tracker.py init
    
    print_success "Database initialized"
}

# Create configuration
create_config() {
    print_status "Creating configuration..."
    
    if [ ! -f .env ]; then
        cp config.env.example .env
        print_success "Configuration file created from template"
    else
        print_warning "Configuration file already exists, skipping"
    fi
}

# Setup systemd service (optional)
setup_service() {
    read -p "Do you want to install as a systemd service? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Setting up systemd service..."
        
        # Copy service file
        sudo cp gpg-tracker.service /etc/systemd/system/
        
        # Reload systemd
        sudo systemctl daemon-reload
        
        # Enable service
        sudo systemctl enable gpg-tracker.service
        
        print_success "Systemd service installed and enabled"
        print_status "You can start it with: sudo systemctl start gpg-tracker.service"
    fi
}

# Main installation
main() {
    print_status "Starting GPG Key Tracker installation..."
    print_status "Detected OS: $OS $VER"
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root. Consider running as a regular user for better security."
    fi
    
    # Install dependencies
    install_system_deps
    install_python_deps
    
    # Setup environment
    setup_gpg
    create_config
    init_database
    
    # Optional service setup
    setup_service
    
    print_success "Installation completed successfully!"
    echo
    print_status "Next steps:"
    echo "1. Copy your .env file and configure it: cp config.env.example .env"
    echo "2. Add your first key: python3 gpg_tracker.py add-key --key-file /path/to/key.asc --owner 'Owner Name' --requester 'Requester Name'"
    echo "3. List keys: python3 gpg_tracker.py list-keys"
    echo "4. Use the wrapper: python3 gpg_wrapper.py encrypt --file document.txt --recipient user@example.com"
    echo
    print_status "For more information, see the README.md file"
}

# Run main function
detect_os
main
