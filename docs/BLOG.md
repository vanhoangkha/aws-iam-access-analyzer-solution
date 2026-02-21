# Automate IAM Security Audits with AWS Access Analyzer SDK

Managing IAM permissions at scale is challenging. With hundreds of roles, users, and resource policies, it's easy to miss overly permissive access or unused permissions that increase your attack surface.

This post introduces a complete Python SDK for AWS IAM Access Analyzer that implements all 37 APIs, enabling automated security audits, CI/CD policy validation, and continuous monitoring.

## The Problem

Organizations face several IAM security challenges:

1. **External Access Detection** - S3 buckets, KMS keys, or IAM roles accidentally exposed to the public or external accounts
2. **Unused Permissions** - Roles with permissions granted but never used, violating least privilege
3. **Policy Validation** - No automated way to catch policy errors before deployment
4. **Manual Audits** - Security reviews are time-consuming and error-prone

## The Solution

AWS IAM Access Analyzer addresses these challenges, but the AWS Console and CLI have limitations for automation. This SDK provides:

- Complete API coverage (all 37 Access Analyzer APIs)
- CI/CD integration for policy validation
- Security dashboard for monitoring
- Cost-optimized implementation

## Quick Start

### Installation

```bash
pip install aws-access-analyzer
```

Or clone and install:

```bash
git clone https://github.com/vanhoangkha/aws-iam-access-analyzer-solution.git
cd aws-iam-access-analyzer-solution
pip install -e .
```

### Basic Usage

```python
from access_analyzer import AccessAnalyzerClient

client = AccessAnalyzerClient()

# Run full security scan
results = client.full_scan()
print(f"External access findings: {results['summary']['external_count']}")
print(f"Unused access findings: {results['summary']['unused_count']}")
```

### CLI Commands

```bash
# Scan for findings
python -m access_analyzer scan

# Validate policies before deployment
python -m access_analyzer validate ./policies/

# Generate security dashboard
python -m access_analyzer dashboard --export report.json
```

## Key Features

### 1. Policy Validation in CI/CD

Block insecure policies before they reach production:

```python
from access_analyzer import PolicyValidator

validator = PolicyValidator()

# Validate policy syntax and best practices
findings = validator.validate_policy({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": "s3:*",
        "Resource": "*"
    }]
})

# Check for public access
result = validator.check_no_public_access(bucket_policy, "AWS::S3::Bucket")
if result["result"] == "FAIL":
    raise Exception("Policy allows public access!")

# Detect privilege escalation risks
result = validator.check_no_privilege_escalation(policy)
if result["dangerous_actions"]:
    print(f"Dangerous actions found: {result['dangerous_actions']}")
```

### 2. GitHub Actions Integration

```yaml
# .github/workflows/policy-check.yml
name: IAM Policy Validation

on:
  pull_request:
    paths:
      - 'policies/**'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      
      - name: Install SDK
        run: pip install aws-access-analyzer
      
      - name: Validate Policies
        run: python -m access_analyzer validate ./policies/
        env:
          AWS_REGION: ap-southeast-1
```

### 3. Security Dashboard

Generate comprehensive security reports:

```python
from access_analyzer import SecurityDashboard

dashboard = SecurityDashboard()
report = dashboard.generate_report()

print(f"Total critical findings: {report['totals']['critical']}")
print(f"External access issues: {report['totals']['external']}")
print(f"Unused permissions: {report['totals']['unused']}")

# Export for further analysis
dashboard.export_json("security_report.json")
```

### 4. Access Preview

Test policy changes before applying:

```python
client = AccessAnalyzerClient()

# Preview what access a new bucket policy would grant
preview_id = client.create_access_preview(
    analyzer_arn="arn:aws:access-analyzer:...",
    configurations={
        "arn:aws:s3:::my-bucket": {
            "s3Bucket": {
                "bucketPolicy": new_policy
            }
        }
    }
)

# Check preview findings
findings = client.list_access_preview_findings(analyzer_arn, preview_id)
```

## Cost Optimization

The SDK is designed for cost efficiency:

| Feature | Cost | Usage |
|---------|------|-------|
| External Access Analyzer | FREE | Always enable |
| Policy Validation | FREE | Unlimited CI/CD checks |
| Access Preview | FREE | Test before deploy |
| Unused Access Analyzer | $0.20/entity/month | Enable for compliance |
| Custom Policy Checks | $0.002/call | Use for critical paths |

**Example: 100 IAM entities**
- External analyzer: $0
- Unused analyzer: $20/month
- 1000 policy validations: $0
- 100 custom checks: $0.20

**Total: ~$20/month** for comprehensive IAM security

## Infrastructure as Code

Deploy the complete solution with CloudFormation:

```bash
aws cloudformation deploy \
  --template-file infrastructure/access-analyzer-setup.yaml \
  --stack-name iam-access-analyzer \
  --parameter-overrides NotificationEmail=security@company.com \
  --capabilities CAPABILITY_IAM
```

This creates:
- External Access Analyzer (free)
- Unused Access Analyzer (optional)
- SNS topic with KMS encryption
- EventBridge rules for real-time alerts
- Budget alert at $10 threshold

## Best Practices

1. **Enable External Access Analyzer** - It's free and catches public exposure
2. **Integrate policy validation in CI/CD** - Shift security left
3. **Use Access Preview** - Test changes before applying
4. **Review unused permissions quarterly** - Reduce attack surface
5. **Set up alerts** - Get notified of new findings immediately

## Conclusion

Automating IAM security audits reduces risk and saves time. This SDK provides everything needed to:

- Detect external access and unused permissions
- Validate policies in CI/CD pipelines
- Generate security reports
- Monitor continuously with alerts

Get started: [github.com/vanhoangkha/aws-iam-access-analyzer-solution](https://github.com/vanhoangkha/aws-iam-access-analyzer-solution)

## Resources

- [AWS IAM Access Analyzer Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [Access Analyzer API Reference](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_Operations.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
