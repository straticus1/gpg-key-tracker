# GPG Key Server Setup Guide

## Quick Setup

### 1. Install Dependencies

```bash
# Install Python dependencies
pip install -r requirements.txt -r requirements_server.txt
```

### 2. Configure Environment

```bash
# Copy example environment file
cp .env.server.example .env

# Edit configuration (set your admin API key!)
nano .env
```

**⚠️ Important**: Change the `GPG_SERVER_ADMIN_API_KEY` to a secure value!

### 3. Initialize Database and Keys

```bash
# Initialize everything
python start_server.py --init-only

# Or step by step:
python server_cli.py init
python server_cli.py master-key create-organizational \
  --organization "Your Organization" \
  --name "Production Keys" \
  --email "admin@yourorg.com"
```

### 4. Start Server

```bash
# Start server
python start_server.py

# Or for production (with SSL):
export GPG_SERVER_SSL_CERT="/path/to/cert.pem"
export GPG_SERVER_SSL_KEY="/path/to/key.pem"
export GPG_SERVER_REQUIRE_SSL=true
python start_server.py
```

Server will be available at:
- **API**: https://localhost:8443 (or http if SSL disabled)
- **Docs**: https://localhost:8443/docs
- **Health**: https://localhost:8443/health
- **Metrics**: http://localhost:8000/metrics

### 5. Create Your First API Key

```bash
# Using CLI with admin key
python server_cli.py api-key create \
  --name "My App Key" \
  --owner "myapp@example.com" \
  --operations read list info search \
  --rate-limit 1000
```

### 6. Test API Access

```bash
# Test with your API key
curl -H "X-API-Key: YOUR_API_KEY" https://localhost:8443/keys
```

## Docker Setup (Recommended for Production)

### 1. Configure Environment

```bash
# Create .env file with your settings
cat > .env << EOF
GPG_SERVER_ADMIN_API_KEY=your-secure-admin-key-here
ORGANIZATION_NAME=Your Organization
ADMIN_EMAIL=admin@yourorg.com
EOF
```

### 2. Start with Docker Compose

```bash
# Start all services
docker-compose -f docker-compose.server.yml up -d

# Check logs
docker-compose -f docker-compose.server.yml logs -f gpg-server
```

### 3. Initialize Organizational Keys

```bash
# Initialize organizational keys
docker-compose exec gpg-server python server_cli.py master-key create-organizational \
  --organization "Your Organization" \
  --name "Production Keys" \
  --email "admin@yourorg.com"

# Create first API key
docker-compose exec gpg-server python server_cli.py api-key create \
  --name "Production API Key" \
  --owner "production@yourorg.com" \
  --operations read list info search sign encrypt \
  --rate-limit 5000
```

## Security Checklist

- [ ] Changed default admin API key
- [ ] Configured SSL/TLS certificates
- [ ] Set up firewall rules
- [ ] Created organizational keys
- [ ] Configured proper permissions for API keys
- [ ] Set up monitoring and logging
- [ ] Configured backups
- [ ] Reviewed security settings

## Next Steps

1. **Create API Keys** for your applications
2. **Set up SSL/TLS** for production use
3. **Configure monitoring** with Prometheus
4. **Set up automated backups** for master keys
5. **Implement access controls** and IP restrictions
6. **Monitor usage** and set up alerts

## Troubleshooting

See [SERVER_README.md](SERVER_README.md) for detailed documentation and troubleshooting guide.

## Key Features Implemented

✅ **HTTP API Server** - FastAPI with SSL/TLS support
✅ **API Key Authentication** - Mandatory for all operations
✅ **Master Key Validation** - Organizational signing & encryption keys
✅ **GPG Operations** - read, list, sign, encrypt, info, search
✅ **Rate Limiting** - Configurable per API key
✅ **Admin Interface** - Full API key and master key management
✅ **CLI Utilities** - Complete command-line management tools
✅ **Docker Support** - Production-ready containerization
✅ **Comprehensive Documentation** - API docs, setup guides
✅ **Security Features** - Input validation, secure key storage
✅ **Monitoring** - Prometheus metrics and health checks