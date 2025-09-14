# Deployment Guide

This guide covers various deployment scenarios for GPG Key Tracker, from local development to production environments.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Local Development](#local-development)
3. [Production Deployment](#production-deployment)
4. [Docker Deployment](#docker-deployment)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [Monitoring and Logging](#monitoring-and-logging)
7. [Security Considerations](#security-considerations)
8. [Backup and Recovery](#backup-and-recovery)
9. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- **OS**: Linux (Ubuntu 20.04+, CentOS 8+, RHEL 8+)
- **Python**: 3.8 or higher
- **GPG**: 2.0 or higher
- **Memory**: Minimum 512MB, Recommended 2GB
- **Disk**: Minimum 1GB free space
- **Network**: HTTP/HTTPS access for reports and monitoring

### Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3 python3-pip gnupg2 sqlite3

# CentOS/RHEL/Fedora
sudo yum install python3 python3-pip gnupg2 sqlite
# or
sudo dnf install python3 python3-pip gnupg2 sqlite
```

## Local Development

### Quick Start

```bash
# Clone repository
git clone https://github.com/straticus1/gpg-key-tracker.git
cd gpg-key-tracker

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python gpg_tracker.py init

# Start interactive mode
python gpg_tracker.py interactive
```

### Development Configuration

Create a `.env` file:

```bash
# Database
DATABASE_PATH=./dev_gpg_tracker.db

# GPG
GPG_HOME=~/.gnupg

# Logging
LOG_LEVEL=DEBUG
LOG_FILE=./logs/gpg_tracker.log

# Monitoring (optional)
MONITORING_ENABLED=true
PROMETHEUS_PORT=8000
HEALTH_CHECK_PORT=8001

# Email (for testing)
SMTP_SERVER=localhost
SMTP_PORT=1025
EMAIL_FROM_ADDRESS=test@localhost
```

### Development Services

```bash
# Start development SMTP server (for email testing)
python -m smtpd -n -c DebuggingServer localhost:1025

# Start monitoring
python -c "from monitoring import start_monitoring; start_monitoring()"
```

## Production Deployment

### System Setup

1. **Create dedicated user**:
```bash
sudo useradd -r -s /bin/bash -d /opt/gpg-key-tracker gpgtracker
sudo mkdir -p /opt/gpg-key-tracker
sudo chown gpgtracker:gpgtracker /opt/gpg-key-tracker
```

2. **Install application**:
```bash
sudo -u gpgtracker -i
cd /opt/gpg-key-tracker

# Clone or copy application files
git clone https://github.com/straticus1/gpg-key-tracker.git .

# Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. **Create directories**:
```bash
mkdir -p data logs backups config
chmod 700 ~/.gnupg
```

### Production Configuration

Create `/opt/gpg-key-tracker/config/.env`:

```bash
# Database
DATABASE_PATH=/opt/gpg-key-tracker/data/gpg_tracker.db

# GPG
GPG_HOME=/opt/gpg-key-tracker/.gnupg

# Logging
LOG_LEVEL=INFO
LOG_FILE=/opt/gpg-key-tracker/logs/gpg_tracker.log
LOG_JSON=true

# Backup
BACKUP_ENABLED=true
BACKUP_PATH=/opt/gpg-key-tracker/backups
BACKUP_RETENTION_DAYS=30

# Monitoring
MONITORING_ENABLED=true
PROMETHEUS_PORT=8000
HEALTH_CHECK_PORT=8001

# Email
SMTP_SERVER=your-smtp-server.com
SMTP_PORT=587
SMTP_USERNAME=your-username
SMTP_PASSWORD=your-password
SMTP_USE_TLS=true
EMAIL_FROM_ADDRESS=gpg-tracker@your-domain.com

# AWS (optional)
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_DEFAULT_REGION=us-east-1
S3_BUCKET=your-backup-bucket
```

### Systemd Service

Create `/etc/systemd/system/gpg-key-tracker.service`:

```ini
[Unit]
Description=GPG Key Tracker
After=network.target

[Service]
Type=notify
User=gpgtracker
Group=gpgtracker
WorkingDirectory=/opt/gpg-key-tracker
Environment=PATH=/opt/gpg-key-tracker/venv/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=/opt/gpg-key-tracker/venv/bin/python gpg_tracker.py daemon
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/opt/gpg-key-tracker

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable gpg-key-tracker
sudo systemctl start gpg-key-tracker
sudo systemctl status gpg-key-tracker
```

### Reverse Proxy (Nginx)

Create `/etc/nginx/sites-available/gpg-key-tracker`:

```nginx
server {
    listen 80;
    server_name gpg-tracker.your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name gpg-tracker.your-domain.com;

    ssl_certificate /path/to/certificate.pem;
    ssl_certificate_key /path/to/private-key.pem;

    # Health check endpoint
    location /health {
        proxy_pass http://127.0.0.1:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Metrics endpoint (restrict access)
    location /metrics {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;

        # Restrict access
        allow 10.0.0.0/8;
        allow 192.168.0.0/16;
        deny all;
    }

    # Static files (if any)
    location /static {
        alias /opt/gpg-key-tracker/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

## Docker Deployment

### Basic Docker Run

```bash
# Build image
docker build -t gpg-key-tracker .

# Run container
docker run -d \
  --name gpg-key-tracker \
  -v /opt/gpg-data:/app/data \
  -v /opt/gpg-home:/home/gpgtracker/.gnupg \
  -v /opt/gpg-backups:/app/backups \
  -p 8000:8000 \
  -p 8001:8001 \
  -e DATABASE_PATH=/app/data/gpg_tracker.db \
  -e LOG_LEVEL=INFO \
  gpg-key-tracker
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  gpg-key-tracker:
    build: .
    container_name: gpg-key-tracker
    restart: unless-stopped
    volumes:
      - ./data:/app/data
      - ./gpg-home:/home/gpgtracker/.gnupg
      - ./backups:/app/backups
      - ./logs:/app/logs
    ports:
      - "8000:8000"  # Prometheus metrics
      - "8001:8001"  # Health check
    environment:
      - DATABASE_PATH=/app/data/gpg_tracker.db
      - LOG_LEVEL=INFO
      - LOG_FILE=/app/logs/gpg_tracker.log
      - BACKUP_ENABLED=true
      - BACKUP_PATH=/app/backups
      - MONITORING_ENABLED=true
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8001/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  nginx:
    image: nginx:alpine
    container_name: gpg-tracker-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/ssl:ro
    depends_on:
      - gpg-key-tracker
```

Start services:

```bash
docker-compose up -d
```

## Kubernetes Deployment

### Namespace

Create `k8s/namespace.yaml`:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: gpg-key-tracker
```

### ConfigMap

Create `k8s/configmap.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: gpg-key-tracker-config
  namespace: gpg-key-tracker
data:
  DATABASE_PATH: "/app/data/gpg_tracker.db"
  LOG_LEVEL: "INFO"
  LOG_FILE: "/app/logs/gpg_tracker.log"
  BACKUP_ENABLED: "true"
  BACKUP_PATH: "/app/backups"
  MONITORING_ENABLED: "true"
  PROMETHEUS_PORT: "8000"
  HEALTH_CHECK_PORT: "8001"
```

### Secret

Create `k8s/secret.yaml`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: gpg-key-tracker-secret
  namespace: gpg-key-tracker
type: Opaque
data:
  SMTP_USERNAME: <base64-encoded-username>
  SMTP_PASSWORD: <base64-encoded-password>
  AWS_ACCESS_KEY_ID: <base64-encoded-key>
  AWS_SECRET_ACCESS_KEY: <base64-encoded-secret>
```

### Deployment

Create `k8s/deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gpg-key-tracker
  namespace: gpg-key-tracker
spec:
  replicas: 1
  selector:
    matchLabels:
      app: gpg-key-tracker
  template:
    metadata:
      labels:
        app: gpg-key-tracker
    spec:
      containers:
      - name: gpg-key-tracker
        image: ghcr.io/straticus1/gpg-key-tracker:latest
        ports:
        - containerPort: 8000
        - containerPort: 8001
        envFrom:
        - configMapRef:
            name: gpg-key-tracker-config
        - secretRef:
            name: gpg-key-tracker-secret
        volumeMounts:
        - name: data
          mountPath: /app/data
        - name: gpg-home
          mountPath: /home/gpgtracker/.gnupg
        - name: backups
          mountPath: /app/backups
        livenessProbe:
          httpGet:
            path: /health
            port: 8001
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8001
          initialDelaySeconds: 5
          periodSeconds: 10
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: gpg-key-tracker-data
      - name: gpg-home
        persistentVolumeClaim:
          claimName: gpg-key-tracker-gpg
      - name: backups
        persistentVolumeClaim:
          claimName: gpg-key-tracker-backups
```

### Service

Create `k8s/service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: gpg-key-tracker-service
  namespace: gpg-key-tracker
spec:
  selector:
    app: gpg-key-tracker
  ports:
  - name: metrics
    port: 8000
    targetPort: 8000
  - name: health
    port: 8001
    targetPort: 8001
  type: ClusterIP
```

### Deploy

```bash
kubectl apply -f k8s/
```

## Monitoring and Logging

### Prometheus Configuration

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'gpg-key-tracker'
    static_configs:
      - targets: ['gpg-tracker.your-domain.com:8000']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### Grafana Dashboard

Import the provided Grafana dashboard or create custom panels for:

- Key counts and status
- Operation success rates
- Response times
- System health
- Database size

### Log Aggregation

Configure log shipping to your preferred log aggregation system:

- ELK Stack (Elasticsearch, Logstash, Kibana)
- Fluentd/Fluent Bit
- Splunk
- Datadog

Example Filebeat configuration:

```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /opt/gpg-key-tracker/logs/*.log
  fields:
    service: gpg-key-tracker
  fields_under_root: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "gpg-key-tracker-%{+yyyy.MM.dd}"
```

## Security Considerations

### Network Security

1. **Firewall Rules**:
```bash
# Allow SSH
sudo ufw allow ssh

# Allow HTTP/HTTPS
sudo ufw allow http
sudo ufw allow https

# Restrict monitoring ports
sudo ufw allow from 10.0.0.0/8 to any port 8000
sudo ufw allow from 10.0.0.0/8 to any port 8001

# Enable firewall
sudo ufw enable
```

2. **SSL/TLS Configuration**:
   - Use strong cipher suites
   - Enable HSTS headers
   - Regular certificate renewal

### File Permissions

```bash
# Application directory
sudo chmod 755 /opt/gpg-key-tracker
sudo chmod 700 /opt/gpg-key-tracker/.gnupg
sudo chmod 750 /opt/gpg-key-tracker/data
sudo chmod 750 /opt/gpg-key-tracker/logs
sudo chmod 750 /opt/gpg-key-tracker/backups

# Configuration files
sudo chmod 600 /opt/gpg-key-tracker/config/.env
```

### Regular Security Updates

```bash
# System updates
sudo apt update && sudo apt upgrade -y

# Python dependencies
pip install --upgrade -r requirements.txt

# Security scanning
bandit -r .
safety check
```

## Backup and Recovery

### Automated Backups

1. **Application Backups**:
```bash
# Create backup
python gpg_tracker.py create-backup

# List backups
python gpg_tracker.py list-backups

# Clean old backups
python gpg_tracker.py cleanup-backups --days 30
```

2. **System-Level Backups**:
```bash
#!/bin/bash
# backup-script.sh

BACKUP_DIR="/opt/backups/gpg-key-tracker"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR/$DATE"

# Backup application data
tar -czf "$BACKUP_DIR/$DATE/gpg_data.tar.gz" -C /opt/gpg-key-tracker data
tar -czf "$BACKUP_DIR/$DATE/gpg_home.tar.gz" -C /opt/gpg-key-tracker .gnupg

# Backup configuration
cp /opt/gpg-key-tracker/config/.env "$BACKUP_DIR/$DATE/"

# Upload to remote storage
aws s3 cp "$BACKUP_DIR/$DATE/" "s3://your-backup-bucket/gpg-key-tracker/$DATE/" --recursive
```

### Recovery Procedures

1. **Database Recovery**:
```bash
# Stop service
sudo systemctl stop gpg-key-tracker

# Restore database
python gpg_tracker.py restore-backup --backup-name backup_20240915_120000

# Start service
sudo systemctl start gpg-key-tracker
```

2. **Full System Recovery**:
```bash
# Restore application files
tar -xzf gpg_data.tar.gz -C /opt/gpg-key-tracker/
tar -xzf gpg_home.tar.gz -C /opt/gpg-key-tracker/

# Restore permissions
sudo chown -R gpgtracker:gpgtracker /opt/gpg-key-tracker
sudo chmod 700 /opt/gpg-key-tracker/.gnupg

# Restart service
sudo systemctl restart gpg-key-tracker
```

## Troubleshooting

### Common Issues

1. **Database Connection Errors**:
```bash
# Check database file permissions
ls -la /opt/gpg-key-tracker/data/

# Test database connection
python -c "from models import get_session; get_session().execute('SELECT 1')"
```

2. **GPG Errors**:
```bash
# Check GPG home permissions
ls -la /opt/gpg-key-tracker/.gnupg/

# Test GPG functionality
gpg --homedir /opt/gpg-key-tracker/.gnupg --list-keys
```

3. **Service Issues**:
```bash
# Check service status
sudo systemctl status gpg-key-tracker

# View logs
sudo journalctl -u gpg-key-tracker -f

# Check application logs
tail -f /opt/gpg-key-tracker/logs/gpg_tracker.log
```

4. **Performance Issues**:
```bash
# Check system resources
htop
df -h
free -m

# Database analysis
sqlite3 /opt/gpg-key-tracker/data/gpg_tracker.db ".schema"
```

### Log Analysis

Common log patterns to monitor:

```bash
# Errors
grep "ERROR" /opt/gpg-key-tracker/logs/gpg_tracker.log

# Database operations
grep "Database" /opt/gpg-key-tracker/logs/gpg_tracker.log

# GPG operations
grep "GPG" /opt/gpg-key-tracker/logs/gpg_tracker.log

# Security events
grep -E "(Failed|Invalid|Unauthorized)" /opt/gpg-key-tracker/logs/gpg_tracker.log
```

### Health Checks

Automated health monitoring:

```bash
#!/bin/bash
# health-check.sh

# Check service status
if ! systemctl is-active --quiet gpg-key-tracker; then
    echo "CRITICAL: GPG Key Tracker service is not running"
    exit 2
fi

# Check health endpoint
if ! curl -f http://localhost:8001/health > /dev/null 2>&1; then
    echo "CRITICAL: Health check endpoint failed"
    exit 2
fi

# Check database
if ! python -c "from models import check_database_health; assert check_database_health()" 2>/dev/null; then
    echo "WARNING: Database health check failed"
    exit 1
fi

echo "OK: All health checks passed"
exit 0
```

### Support

For deployment issues:

1. Check the [troubleshooting section](TROUBLESHOOTING.md)
2. Review application logs
3. Consult the [documentation](https://straticus1.github.io/gpg-key-tracker/)
4. Open an issue on [GitHub](https://github.com/straticus1/gpg-key-tracker/issues)

---

**Last Updated**: September 2025
**Version**: 1.2.0