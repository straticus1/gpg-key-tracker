# Multi-stage Dockerfile for GPG Key Tracker

# Build stage
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Copy source code
COPY . .

# Build the application
RUN python -m pip install --user build
RUN python -m build

# Production stage
FROM python:3.11-slim as production

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    gnupg2 \
    gpg-agent \
    sqlite3 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create application user
RUN groupadd -r gpgtracker && useradd -r -g gpgtracker gpgtracker

# Set working directory
WORKDIR /app

# Copy Python dependencies from builder stage
COPY --from=builder /root/.local /home/gpgtracker/.local

# Copy application code
COPY --chown=gpgtracker:gpgtracker . .

# Create necessary directories
RUN mkdir -p /app/data /app/logs /app/backups /home/gpgtracker/.gnupg \
    && chown -R gpgtracker:gpgtracker /app /home/gpgtracker \
    && chmod 700 /home/gpgtracker/.gnupg

# Set environment variables
ENV PATH=/home/gpgtracker/.local/bin:$PATH
ENV PYTHONPATH=/app
ENV GPG_HOME=/home/gpgtracker/.gnupg
ENV DATABASE_PATH=/app/data/gpg_tracker.db
ENV LOG_LEVEL=INFO
ENV BACKUP_PATH=/app/backups

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from monitoring import get_health_checker; hc = get_health_checker(); exit(0 if hc.get_overall_health()['status'] == 'healthy' else 1)" || exit 1

# Switch to non-root user
USER gpgtracker

# Expose ports for monitoring
EXPOSE 8000 8001

# Default command
CMD ["python", "gpg_tracker.py", "--help"]

# Development stage (for development and testing)
FROM production as development

USER root

# Install development dependencies
RUN pip install --no-cache-dir \
    pytest \
    pytest-cov \
    pytest-mock \
    black \
    flake8 \
    mypy \
    bandit \
    safety \
    prometheus-client

# Install additional development tools
RUN apt-get update && apt-get install -y \
    git \
    vim \
    htop \
    && rm -rf /var/lib/apt/lists/*

USER gpgtracker

CMD ["/bin/bash"]

# Labels for metadata
LABEL org.opencontainers.image.title="GPG Key Tracker"
LABEL org.opencontainers.image.description="A comprehensive Python application for managing PGP/GPG keys with metadata tracking and usage logging"
LABEL org.opencontainers.image.version="1.2.0"
LABEL org.opencontainers.image.vendor="Ryan J Coleman"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/straticus1/gpg-key-tracker"
LABEL org.opencontainers.image.documentation="https://straticus1.github.io/gpg-key-tracker/"