# AWS IAM Access Analyzer - Comprehensive Solution

Production-ready implementation leveraging ALL IAM Access Analyzer features for AWS security automation.

## Architecture

![Architecture](architecture.png)

## Overview

This solution provides a comprehensive implementation of AWS IAM Access Analyzer, enabling:
- **External Access Analysis**: Identify resources shared with external entities
- **Internal Access Analysis**: Monitor access to business-critical resources within your organization
- **Unused Access Analysis**: Identify and remediate unused permissions for least privilege
- **Policy Validation**: Validate policies against AWS best practices
- **Custom Policy Checks**: Validate policies against your security standards
- **Policy Generation**: Generate policies based on CloudTrail access activity
- **CI/CD Integration**: Block insecure policies in pipelines
- **Real-time Alerts**: EventBridge-powered notifications

## Supported Resource Types

### External Access Analysis (15 resource types)
| Resource Type | Service |
|--------------|---------|
| S3 Buckets | Amazon S3 |
| S3 Directory Buckets | Amazon S3 |
| IAM Roles | AWS IAM |
| KMS Keys | AWS KMS |
| Lambda Functions & Layers | AWS Lambda |
| SQS Queues | Amazon SQS |
| Secrets Manager Secrets | AWS Secrets Manager |
| SNS Topics | Amazon SNS |
| EBS Volume Snapshots | Amazon EBS |
| RDS DB Snapshots | Amazon RDS |
| RDS DB Cluster Snapshots | Amazon RDS |
| ECR Repositories | Amazon ECR |
| EFS File Systems | Amazon EFS |
| DynamoDB Streams | Amazon DynamoDB |
| DynamoDB Tables | Amazon DynamoDB |

### Internal Access Analysis (6 resource types)
- S3 Buckets & Directory Buckets
- RDS DB Snapshots & Cluster Snapshots
- DynamoDB Streams & Tables

### Unused Access Analysis
- IAM Users and Roles (excludes service-linked roles)

## Features & APIs

| Feature | API | Cost |
|---------|-----|------|
| External Access Detection | `list_findings_v2` | **FREE** |
| Internal Access Detection | `list_findings_v2` | $9.00/resource/month |
| Unused Access Analysis | `list_findings_v2` | $0.20/identity/month |
| Policy Validation | `validate_policy` | **FREE** |
| Public Access Check | `check_no_public_access` | $0.002/call |
| Access Not Granted Check | `check_access_not_granted` | $0.002/call |
| No New Access Check | `check_no_new_access` | $0.002/call |
| Access Preview | `create_access_preview` | **FREE** |
| Policy Generation | `start_policy_generation` | **FREE** |
| Finding Recommendations | `generate_finding_recommendation` | **FREE** |

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
└── 05-scps/                         # Service Control Policies
```

## Pricing Estimate

| Component | Price | Estimate (100 identities) |
|-----------|-------|--------------------------|
| External Access Analyzer | FREE | $0 |
| Unused Access Analyzer | $0.20/identity/month | $20/month |
| Internal Access Analyzer | $9.00/resource/month | Varies |
| Custom Policy Checks | $0.002/API call | ~$1/month |

## Configuration

### Exclude Accounts from Analysis (New - Jan 2025)
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
# Check for public access
result = solution.check_no_public_access(policy, 'AWS::S3::Bucket')
if result['result'] == 'FAIL':
    sys.exit(1)

# Check for dangerous actions
result = solution.check_access_not_granted(policy, ['iam:*', 'iam:PassRole'])
if result['result'] == 'FAIL':
    sys.exit(1)

# Check for new access compared to reference policy
result = solution.check_no_new_access(new_policy, existing_policy, 'IDENTITY_POLICY')
if result['result'] == 'FAIL':
    sys.exit(1)
```

## Documentation

- [IAM Access Analyzer User Guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [Supported Resource Types](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-resources.html)
- [Custom Policy Checks](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-custom-policy-checks.html)
- [API Reference](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/)
- [Pricing](https://aws.amazon.com/iam/access-analyzer/pricing/)

### AWS Blog Posts
- [Customize scope of unused access analysis](https://aws.amazon.com/blogs/security/customize-the-scope-of-iam-access-analyzer-unused-access-analysis/) (Jan 2025)
- [Refine unused access using recommendations](https://aws.amazon.com/blogs/security/refine-unused-access-using-iam-access-analyzer-recommendations) (Sep 2024)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT-0 License. See [LICENSE](LICENSE).

## Author

**Kha Van** - [GitHub](https://github.com/vanhoangkha)
