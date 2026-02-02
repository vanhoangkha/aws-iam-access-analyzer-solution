# Security Policy

## Reporting Security Issues

If you discover a security vulnerability, please report it via [AWS Security](https://aws.amazon.com/security/vulnerability-reporting/).

**Do not** create public GitHub issues for security vulnerabilities.

## Security Best Practices

This repository follows AWS security best practices:

### IAM Policies
- ✅ Least privilege permissions
- ✅ No wildcard actions on sensitive resources
- ✅ Condition keys where applicable
- ✅ Resource-level permissions

### Infrastructure
- ✅ SNS topics encrypted with KMS
- ✅ Lambda functions with minimal permissions
- ✅ CloudWatch Logs with retention policies
- ✅ EventBridge rules with source account conditions

### Code
- ✅ No hardcoded credentials
- ✅ No sensitive data in logs
- ✅ Input validation
- ✅ Error handling without information disclosure

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | ✅        |
| 1.x     | ❌        |
