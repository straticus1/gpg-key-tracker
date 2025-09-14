# Security Policy

## Overview

GPG Key Tracker takes security seriously. This document outlines our security practices and how to report security vulnerabilities.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| 1.1.x   | :x:                |
| < 1.1   | :x:                |

## Security Features

### Input Validation and Sanitization

- All user inputs are validated and sanitized to prevent injection attacks
- File size limits prevent DoS attacks through large files
- Fingerprint validation ensures only valid GPG fingerprints are processed
- Email validation prevents malformed email addresses

### Authentication and Authorization

- Database operations use parameterized queries to prevent SQL injection
- File operations validate paths and permissions
- GPG operations are executed with proper error handling

### Data Protection

- GPG keys are stored securely in the GPG keyring, not in the database
- Database contains only metadata, not sensitive key material
- All operations are logged for audit purposes
- Backup and restore operations preserve security permissions

### Secure Configuration

- Environment variable support for sensitive configuration
- Configuration validation prevents misconfiguration
- Secure defaults for all settings
- Optional encryption for configuration files

## Security Best Practices

### Deployment

1. **Database Security**
   - Use file system permissions to protect the database file
   - Consider encrypting the database file at rest
   - Regular backups with secure storage

2. **GPG Keyring Security**
   - Proper file permissions (700) for GPG home directory
   - Regular key rotation and expiry monitoring
   - Secure key backup and recovery procedures

3. **Network Security**
   - Use HTTPS for web interfaces
   - Secure channels for remote operations (SSH, TLS)
   - Firewall protection for monitoring ports

4. **Access Control**
   - Run with minimal required privileges
   - Use dedicated user accounts for production
   - Implement role-based access control

### Monitoring and Alerting

- Enable comprehensive logging
- Monitor for security events and anomalies
- Set up alerts for key expiration and security events
- Regular security audits and reviews

## Known Security Considerations

### GPG Security

- GPG key security depends on the underlying GPG installation
- Key compromise requires manual intervention and key revocation
- Private key protection is handled by GPG, not this application

### Database Security

- SQLite database files should be protected with file system permissions
- Consider database encryption for sensitive environments
- Regular backup and recovery testing

### Network Exposure

- Monitoring endpoints should be protected in production environments
- Email operations may expose metadata to mail servers
- S3 and SCP operations require secure credential management

## Reporting Security Vulnerabilities

If you discover a security vulnerability, please report it responsibly:

### Preferred Method

Email: [coleman.ryan@gmail.com](mailto:coleman.ryan@gmail.com)

Subject: [SECURITY] GPG Key Tracker Vulnerability

### Information to Include

1. Description of the vulnerability
2. Steps to reproduce the issue
3. Potential impact assessment
4. Suggested fix (if available)
5. Your contact information for follow-up

### Response Timeline

- **Initial Response**: Within 48 hours
- **Assessment**: Within 1 week
- **Fix Development**: Within 2 weeks (for critical issues)
- **Public Disclosure**: After fix is released and users have time to update

### What to Expect

1. Acknowledgment of your report
2. Assessment of the vulnerability
3. Development of a fix
4. Security advisory publication
5. Credit attribution (if desired)

## Security Advisory Process

Security advisories will be published through:

- GitHub Security Advisories
- Release notes
- Documentation updates
- Email notifications to known users (if applicable)

## Compliance and Standards

GPG Key Tracker follows these security standards:

- OWASP Top 10 security practices
- Secure coding practices
- Input validation and output encoding
- Proper error handling
- Security logging and monitoring

## Security Testing

Regular security testing includes:

- Static code analysis with Bandit
- Dependency vulnerability scanning with Safety
- Security-focused code reviews
- Penetration testing for major releases

## Contact

For security-related questions or concerns:

- Email: [coleman.ryan@gmail.com](mailto:coleman.ryan@gmail.com)
- GitHub Issues: For non-sensitive security discussions
- GitHub Security: For vulnerability reports

## Acknowledgments

We thank the security community for responsible disclosure of vulnerabilities and contributions to improving the security of GPG Key Tracker.

---

**Last Updated**: September 2025
**Version**: 1.2.0