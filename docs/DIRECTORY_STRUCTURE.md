# Directory Structure

This document describes the organization of the GPG Key Tracker & Server project.

## 📁 Root Directory Structure

```
gpg-key-tracker/
├── 🏠 Root Files
│   ├── README.md                     # Main project documentation
│   ├── LICENSE                       # MIT license
│   ├── requirements.txt              # Core Python dependencies
│   ├── .gitignore                    # Git ignore rules
│   └── setup.py                      # Python package setup
│
├── 🔧 Standalone Tracker Components
│   ├── gpg_tracker.py                # Main tracker application
│   ├── gpg_manager.py                # GPG operations manager
│   ├── models.py                     # Database models (shared)
│   ├── config.py                     # Configuration management (shared)
│   ├── interactive.py                # Interactive CLI mode
│   ├── report_generator.py           # Report generation
│   ├── monitoring.py                 # Metrics and monitoring
│   ├── backup_manager.py             # Backup operations
│   ├── cli_aliases.py                # CLI aliases and shortcuts
│   ├── gpg_wrapper.py                # GPG wrapper utilities
│   ├── example_usage.py              # Usage examples
│   └── test_gpg_tracker.py           # Tracker test suite
│
├── 🌐 Server Entry Points
│   ├── start_gpg_server.py           # Server startup wrapper
│   └── server_cli_wrapper.py         # Server CLI wrapper
│
├── 📁 server/                        # GPG Key Server Components
│   ├── gpg_server.py                 # Main FastAPI server application
│   ├── api_key_manager.py            # API key management system
│   ├── master_key_manager.py         # Master key management system
│   ├── gpg_key_manager.py            # Server-specific GPG operations
│   ├── auth_middleware.py            # Authentication middleware
│   ├── server_models.py              # Pydantic request/response models
│   ├── server_cli.py                 # Server management CLI
│   ├── start_server.py               # Server startup script
│   └── test_server.py                # Server test suite
│
├── 📁 config/                        # Configuration Files
│   ├── .env.server.example           # Server configuration template
│   └── config.env.example            # Tracker configuration template
│
├── 📁 docker/                        # Docker Deployment
│   ├── Dockerfile.server             # Server Docker image
│   ├── docker-compose.server.yml     # Complete deployment stack
│   └── requirements_server.txt       # Server Python dependencies
│
├── 📁 scripts/                       # Utility Scripts
│   ├── install.sh                    # Installation script
│   └── gpg-tracker.service           # systemd service file
│
├── 📁 docs/                          # Documentation
│   ├── CHANGELOG.md                  # Version history
│   ├── DEPLOYMENT.md                 # General deployment guide
│   ├── DIRECTORY_STRUCTURE.md        # This file
│   ├── DOCUMENTATION.md              # Tracker documentation
│   ├── FEATURE_SUMMARY.md            # Implementation completion summary
│   ├── INSTALL.md                    # Detailed installation guide
│   ├── PROJECT_PLAN.md               # Project roadmap and planning
│   ├── SECURITY.md                   # Security policy
│   └── server/                       # Server-specific documentation
│       ├── API_SEARCH_GUIDE.md       # Enhanced search API guide
│       ├── GPG_SERVER_PLAN.md        # Architecture and implementation plan
│       ├── SERVER_README.md          # Complete server documentation
│       └── SETUP_SERVER.md           # Quick server setup guide
│
└── 📁 tests/                         # Test Suite
    └── ... (test files)
```

## 🔄 How Components Interact

### Standalone Tracker
- Entry point: `gpg_tracker.py`
- Uses: `gpg_manager.py`, `models.py`, `config.py`, `interactive.py`
- Optional: `report_generator.py`, `monitoring.py`, `backup_manager.py`

### GPG Key Server
- Entry point: `start_gpg_server.py` → `server/start_server.py` → `server/gpg_server.py`
- Server management: `server_cli_wrapper.py` → `server/server_cli.py`
- Core components:
  - `server/gpg_server.py` (FastAPI app)
  - `server/api_key_manager.py` (authentication)
  - `server/master_key_manager.py` (key validation)
  - `server/gpg_key_manager.py` (GPG operations)
  - `server/auth_middleware.py` (middleware)
  - `server/server_models.py` (API models)

### Shared Components
- `models.py`: Database models used by both tracker and server
- `config.py`: Configuration management for both components

## 🚀 Usage Examples

### Starting Components

**Standalone Tracker:**
```bash
# Interactive mode
python gpg_tracker.py --interactive

# Direct command
python gpg_tracker.py --list-keys
```

**GPG Key Server:**
```bash
# Start server
python start_gpg_server.py

# Server management
python server_cli_wrapper.py api-key list
python server_cli_wrapper.py master-key create-organizational --organization "My Org"
```

**Docker Deployment:**
```bash
# Server with Docker Compose
docker-compose -f docker/docker-compose.server.yml up -d
```

### Configuration

**Tracker Configuration:**
- Copy `config/config.env.example` to `.env` or use environment variables
- Modify `config.py` settings as needed

**Server Configuration:**
- Copy `config/.env.server.example` to `.env`
- Set `GPG_SERVER_ADMIN_API_KEY` and other server settings
- Configure SSL certificates for production

## 🔧 Development

### Adding New Features

**For Tracker:**
1. Add functionality to appropriate module (`gpg_manager.py`, `report_generator.py`, etc.)
2. Update `gpg_tracker.py` CLI interface
3. Add tests to `test_gpg_tracker.py`

**For Server:**
1. Add API endpoints to `server/gpg_server.py`
2. Add request/response models to `server/server_models.py`
3. Add business logic to appropriate manager (`api_key_manager.py`, etc.)
4. Add tests to `server/test_server.py`
5. Update CLI in `server/server_cli.py` if needed

### Testing

```bash
# Test tracker
python -m pytest test_gpg_tracker.py

# Test server
python -m pytest server/test_server.py

# Test all
python -m pytest
```

## 🏗️ Architecture Benefits

### Separation of Concerns
- **Standalone tracker**: Simple, focused functionality for individual use
- **Server components**: Enterprise features with authentication and API access
- **Shared models**: Common database structure and configuration

### Maintainability
- Clear module boundaries
- Organized by functionality
- Easy to locate and modify specific features

### Scalability
- Server components can be deployed independently
- Docker support for containerized deployment
- Configuration management supports different environments

### Security
- Server components isolated with proper authentication
- Sensitive configuration in dedicated config directory
- Clear separation between public and admin operations

This organization supports both simple standalone usage and complex enterprise deployments while maintaining clear separation between different system components.