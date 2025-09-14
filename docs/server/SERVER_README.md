# GPG Key Server

A secure HTTP API server for GPG key management with mandatory API key authentication and master key validation.

## Features

- **HTTP API Server** with FastAPI framework
- **Mandatory API Key Authentication** for all operations
- **Master Key Validation System** with organizational signing/encryption keys
- **GPG Operations**: read, list, sign, encrypt, info, search
- **Rate Limiting** and usage logging
- **SSL/TLS Support** for secure communications
- **Admin Interface** for API key and master key management
- **CLI Utilities** for server management
- **Docker Support** for containerized deployment

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt -r requirements_server.txt
```

### 2. Initialize Database and Keys

```bash
python start_server.py --init-only
```

### 3. Create Organizational Keys

```bash
python server_cli.py master-key create-organizational \
  --organization "Your Organization" \
  --name "Organization Keys" \
  --email "admin@yourorg.com"
```

### 4. Create Admin API Key

Set admin API key in environment:
```bash
export GPG_SERVER_ADMIN_API_KEY="your-secure-admin-key-here"
```

### 5. Start Server

```bash
python start_server.py
```

Server will start on `https://localhost:8443` (or `http://localhost:8443` if SSL is disabled).

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GPG_SERVER_HOST` | Server host | `0.0.0.0` |
| `GPG_SERVER_PORT` | Server port | `8443` |
| `GPG_SERVER_ADMIN_API_KEY` | Admin API key | None |
| `GPG_SERVER_SSL_CERT` | SSL certificate file | None |
| `GPG_SERVER_SSL_KEY` | SSL key file | None |
| `GPG_SERVER_REQUIRE_SSL` | Require SSL/TLS | `true` |
| `DATABASE_PATH` | Database file path | `./gpg_tracker.db` |
| `GPG_HOME` | GPG home directory | `~/.gnupg` |
| `REQUIRE_MASTER_SIGNATURE` | Require master signatures | `true` |
| `RATE_LIMIT_ENABLED` | Enable rate limiting | `true` |
| `API_KEY_DEFAULT_RATE_LIMIT` | Default rate limit (req/min) | `100` |

### Full Configuration Example

```bash
# Server Configuration
export GPG_SERVER_ENABLED=true
export GPG_SERVER_HOST=0.0.0.0
export GPG_SERVER_PORT=8443
export GPG_SERVER_ADMIN_API_KEY="secure-admin-key-123"
export GPG_SERVER_SSL_CERT="/path/to/cert.pem"
export GPG_SERVER_SSL_KEY="/path/to/key.pem"

# Database Configuration
export DATABASE_PATH="/opt/gpg-server/data/server.db"
export GPG_HOME="/opt/gpg-server/gpg"

# Security Configuration
export REQUIRE_MASTER_SIGNATURE=true
export RATE_LIMIT_ENABLED=true
export API_KEY_DEFAULT_RATE_LIMIT=100

# Organization Configuration
export ORGANIZATION_NAME="Your Organization"
export ADMIN_EMAIL="admin@yourorg.com"
```

## API Usage

### Authentication

All API endpoints (except `/`, `/health`, `/docs`) require authentication via `X-API-Key` header:

```bash
curl -H "X-API-Key: your-api-key-here" https://server:8443/keys
```

### Server Information

```bash
# Get server information (no auth required)
curl https://server:8443/

# Health check (no auth required)
curl https://server:8443/health
```

### GPG Operations

```bash
# List keys
curl -H "X-API-Key: your-key" https://server:8443/keys

# Get specific key
curl -H "X-API-Key: your-key" https://server:8443/keys/FINGERPRINT

# Search keys
curl -X POST -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"query": "example@email.com", "limit": 10}' \
  https://server:8443/keys/search

# Sign data
curl -X POST -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"data": "message to sign", "detached": true}' \
  https://server:8443/keys/FINGERPRINT/sign

# Encrypt data
curl -X POST -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"data": "secret message", "recipients": ["FINGERPRINT"]}' \
  https://server:8443/keys/FINGERPRINT/encrypt
```

### Admin Operations (require admin API key)

```bash
# List API keys
curl -H "X-API-Key: admin-key" https://server:8443/api-keys

# Create API key
curl -X POST -H "X-API-Key: admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Web App Key",
    "owner": "webapp@example.com",
    "permissions": {
      "operations": ["read", "list", "info"],
      "keys": "*"
    },
    "rate_limit": 1000
  }' https://server:8443/api-keys

# List master keys
curl -H "X-API-Key: admin-key" https://server:8443/master-keys

# Get usage statistics
curl -H "X-API-Key: admin-key" https://server:8443/usage?days=30
```

## CLI Management

### API Key Management

```bash
# Create API key
python server_cli.py api-key create \
  --name "Web App Key" \
  --owner "webapp@example.com" \
  --operations read list info search \
  --rate-limit 1000

# List API keys
python server_cli.py api-key list

# Show API key details
python server_cli.py api-key show 123

# Update API key
python server_cli.py api-key update 123 \
  --rate-limit 2000 \
  --notes "Updated for new features"

# Delete API key
python server_cli.py api-key delete 123

# Rotate API key
python server_cli.py api-key rotate 123
```

### Master Key Management

```bash
# Create organizational key pair
python server_cli.py master-key create-organizational \
  --organization "Your Organization" \
  --name "Production Keys" \
  --email "admin@yourorg.com"

# Create individual master key
python server_cli.py master-key create \
  --name "Backup Signing Key" \
  --type signing \
  --role master \
  --set-default

# List master keys
python server_cli.py master-key list

# Backup master keys
python server_cli.py master-key backup ./master-key-backup
```

### Usage Statistics

```bash
# Get overall usage stats
python server_cli.py stats --days 30

# Get stats for specific API key
python server_cli.py stats --days 7 --api-key-id 123
```

## Docker Deployment

### Docker Compose (Recommended)

1. Set environment variables in `.env` file:
```bash
GPG_SERVER_ADMIN_API_KEY=your-secure-admin-key
ORGANIZATION_NAME=Your Organization
ADMIN_EMAIL=admin@yourorg.com
```

2. Start services:
```bash
docker-compose -f docker-compose.server.yml up -d
```

3. Initialize organizational keys:
```bash
docker-compose exec gpg-server python server_cli.py master-key create-organizational \
  --organization "Your Organization" \
  --name "Production Keys" \
  --email "admin@yourorg.com"
```

### Manual Docker

```bash
# Build image
docker build -f Dockerfile.server -t gpg-key-server .

# Run container
docker run -d \
  --name gpg-server \
  -p 8443:8443 \
  -e GPG_SERVER_ADMIN_API_KEY=your-admin-key \
  -e ORGANIZATION_NAME="Your Org" \
  -v gpg_data:/app/data \
  -v gpg_home:/app/gpg \
  gpg-key-server
```

## SSL/TLS Configuration

### Self-Signed Certificates (Development)

```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Set environment variables
export GPG_SERVER_SSL_CERT="./cert.pem"
export GPG_SERVER_SSL_KEY="./key.pem"
export GPG_SERVER_REQUIRE_SSL=true
```

### Production Certificates

Use certificates from a trusted CA (Let's Encrypt, etc.):

```bash
export GPG_SERVER_SSL_CERT="/path/to/your/cert.pem"
export GPG_SERVER_SSL_KEY="/path/to/your/private.key"
export GPG_SERVER_REQUIRE_SSL=true
```

## Security Considerations

### API Keys
- Use cryptographically secure API keys (64 character hex)
- Store API keys securely (never in logs or code)
- Rotate API keys regularly
- Use least-privilege permissions
- Monitor API key usage

### Master Keys
- Backup master keys securely
- Use strong passphrases for master keys
- Store master keys offline when not in use
- Regularly verify master key signatures
- Have a master key rotation procedure

### Network Security
- Always use HTTPS/TLS in production
- Use proper certificate validation
- Implement network firewalls
- Monitor for unusual traffic patterns
- Use rate limiting and DDoS protection

### Access Control
- Limit admin API key distribution
- Use specific permissions per API key
- Monitor admin operations
- Implement IP restrictions if needed
- Regular access reviews

## Monitoring and Logging

### Prometheus Metrics
Server exposes metrics on port 8000:
```bash
curl http://server:8000/metrics
```

### Log Files
- Application logs: `/app/logs/server.log` (in container)
- Access logs: Via uvicorn
- Audit logs: Database `api_key_usage` table

### Health Checks
```bash
curl https://server:8443/health
```

## Troubleshooting

### Common Issues

1. **Database initialization fails**
   - Check database directory permissions
   - Ensure SQLite is installed
   - Check disk space

2. **GPG operations fail**
   - Verify GPG_HOME directory exists and is writable
   - Check GPG daemon is running
   - Verify key imports successful

3. **SSL certificate errors**
   - Verify certificate file paths
   - Check certificate validity
   - Ensure private key matches certificate

4. **Rate limiting issues**
   - Check API key rate limits
   - Monitor usage patterns
   - Adjust rate limits as needed

### Debug Mode

Enable debug logging:
```bash
export LOG_LEVEL=DEBUG
python start_server.py
```

### Testing API Endpoints

Use the interactive API documentation:
- Visit `https://server:8443/docs` for Swagger UI
- Visit `https://server:8443/redoc` for ReDoc

## API Reference

Complete API documentation is available at:
- **Swagger UI**: `https://server:8443/docs`
- **ReDoc**: `https://server:8443/redoc`
- **OpenAPI JSON**: `https://server:8443/openapi.json`

## Development

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run tests
python -m pytest test_server.py -v
```

### Code Structure

```
├── gpg_server.py           # Main FastAPI application
├── api_key_manager.py      # API key management
├── master_key_manager.py   # Master key management
├── gpg_key_manager.py      # GPG operations
├── auth_middleware.py      # Authentication middleware
├── server_models.py        # Pydantic models
├── server_cli.py           # CLI utility
├── start_server.py         # Server startup script
├── models.py               # Database models
├── config.py               # Configuration management
└── test_server.py          # Tests
```

## Support

For issues and feature requests, please check the documentation or contact the system administrator.