# AWS IAM Access Analyzer - Comprehensive Solution

Production-ready implementation leveraging ALL IAM Access Analyzer features for AWS security automation.

## Overview

This solution provides a comprehensive implementation of AWS IAM Access Analyzer, enabling:
- Proactive Security: Detect external/public access before deployment
- Least Privilege: Identify and remediate unused permissions
- CI/CD Integration: Block insecure policies in pipelines
- Real-time Alerts: EventBridge-powered notifications

## Features

| Feature | API | Cost |
|---------|-----|------|
| External Access Detection | `list_findings_v2` | FREE |
| Unused Access Analysis | `list_findings_v2` | $0.20/identity/month |
| Policy Validation | `validate_policy` | FREE |
| Public Access Check | `check_no_public_access` | $0.002/call |
| Access Not Granted Check | `check_access_not_granted` | $0.002/call |
| No New Access Check | `check_no_new_access` | $0.002/call |
| Access Preview | `create_access_preview` | FREE |
| Policy Generation | `start_policy_generation` | FREE |
| Finding Recommendations | `generate_finding_recommendation` | FREE |

## Quick Start

### Prerequisites
- AWS CLI v2 configured
- Python 3.9+
- AWS account with IAM permissions

### Deploy Infrastructure
```bash
aws cloudformation deploy \
  --template-file infrastructure/access-analyzer-setup.yaml \
  --stack-name access-analyzer-solution \
  --parameter-overrides NotificationEmail=your@email.com \
  --capabilities CAPABILITY_NAMED_IAM
```

### Run Security Scan
```bash
python3 comprehensive_solution.py
```

### CI/CD Validation
```bash
python3 cicd_integration.py ./policies
```

## Project Structure

```
aws-iam-access-analyzer-samples/
├── infrastructure/
│   └── access-analyzer-setup.yaml    # CloudFormation (Analyzers, EventBridge, Lambda, SNS)
├── .github/workflows/
│   └── policy-validation.yml         # GitHub Actions CI/CD
├── comprehensive_solution.py         # Full Python SDK wrapper
├── cicd_integration.py              # CI/CD pipeline integration
├── security_dashboard.py            # Security findings dashboard
├── 01-validate-policy/              # Policy validation examples
├── 02-create-access-preview/        # Access preview examples
├── 03-no-iac/                       # Non-IaC policy scanning
├── 04-cloudformation/               # CloudFormation validation
├── 05-scps/                         # Service Control Policies
└── 06-service-specific/             # Bulk scanning scripts
```

## Pricing

| Component | Price | Estimate (100 roles) |
|-----------|-------|---------------------|
| External Access Analyzer | FREE | $0 |
| Unused Access Analyzer | $0.20/identity/month | $20/month |
| Custom Policy Checks | $0.002/API call | ~$1/month |
| Total | | ~$21/month |

## Configuration

### Exclude Accounts from Analysis
```python
from comprehensive_solution import AccessAnalyzerSolution

solution = AccessAnalyzerSolution()
solution.update_analyzer_exclusions(
    analyzer_name='unused-access-analyzer',
    exclude_account_ids=['111122223333'],
    exclude_tags=[{'team': 'security'}]
)
```

### Custom Policy Checks in CI/CD
```python
result = solution.check_no_public_access(policy, 'AWS::S3::Bucket')
if result['result'] == 'FAIL':
    sys.exit(1)

result = solution.check_access_not_granted(policy, ['iam:*', 'iam:PassRole'])
if result['result'] == 'FAIL':
    sys.exit(1)
```

## Architecture

```
+------------------+     +------------------+     +-------------+
|  IAM Access      |---->|   EventBridge    |---->|    SNS      |
|  Analyzer        |     |   Rules          |     |  (encrypted)|
+------------------+     +------------------+     +-------------+
                                |
                                v
                         +------------------+
                         |  Lambda Logger   |
                         |  (audit trail)   |
                         +------------------+
                                |
                                v
                         +------------------+
                         |  CloudWatch Logs |
                         |  (90 day retain) |
                         +------------------+
```

## Documentation

- [AWS IAM Access Analyzer User Guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [API Reference](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/)
- [Pricing](https://aws.amazon.com/iam/access-analyzer/pricing/)

### AWS Blog Posts
- [Customize scope of unused access analysis](https://aws.amazon.com/blogs/security/customize-the-scope-of-iam-access-analyzer-unused-access-analysis/) (Jan 2025)
- [Refine unused access using recommendations](https://aws.amazon.com/blogs/security/refine-unused-access-using-iam-access-analyzer-recommendations) (Sep 2024)

## Testing

All features tested on AWS account:
```
19/19 tests passed
External Access Analyzer - Active
Unused Access Analyzer - Active  
EventBridge Rules - 3 active
Lambda Function - python3.12
SNS Topic - KMS encrypted
CloudWatch Logs - 90 day retention
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT-0 License. See [LICENSE](LICENSE).

## Disclaimer

This repository contains example code for educational purposes. Review and test thoroughly before production use.
