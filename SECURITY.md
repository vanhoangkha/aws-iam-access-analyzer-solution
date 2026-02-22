# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please follow responsible disclosure:

### Do NOT

- Create a public GitHub issue
- Disclose the vulnerability publicly before it's fixed

### Do

1. **Email**: khavan.work@gmail.com
2. **Subject**: `[SECURITY] aws-iam-access-analyzer-solution`
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution Target**: Within 30 days (depending on severity)

## Security Best Practices

When using this solution, follow these best practices:

### Authentication & Authorization

- ✅ Use IAM roles instead of access keys when possible
- ✅ Apply least privilege principles
- ✅ Rotate credentials regularly
- ✅ Use AWS Organizations SCPs for guardrails

### Monitoring & Logging

- ✅ Enable CloudTrail for audit logging
- ✅ Review Access Analyzer findings regularly
- ✅ Set up SNS notifications for critical findings
- ✅ Use CloudWatch alarms for anomaly detection

### Infrastructure

- ✅ Deploy in private subnets when possible
- ✅ Use VPC endpoints for AWS services
- ✅ Enable encryption at rest and in transit
- ✅ Regularly update dependencies

## Acknowledgments

We appreciate security researchers who help keep this project secure. Contributors will be acknowledged (with permission) in release notes.
