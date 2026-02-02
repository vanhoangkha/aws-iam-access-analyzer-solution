# AWS IAM Access Analyzer Solution

[![AWS](https://img.shields.io/badge/AWS-IAM%20Access%20Analyzer-FF9900?logo=amazon-aws)](https://aws.amazon.com/iam/access-analyzer/)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT--0-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Reviewed-brightgreen)](SECURITY.md)

Production-ready implementation leveraging **ALL** IAM Access Analyzer features for AWS security automation.

## 🏗️ Architecture

![Architecture](architecture.png)

## ✨ Features

| Feature | API | Cost |
|---------|-----|------|
| 🔍 External Access Detection | `list_findings_v2` | **FREE** |
| 🏢 Internal Access Detection | `list_findings_v2` | $9.00/resource/month |
| 🚫 Unused Access Analysis | `list_findings_v2` | $0.20/identity/month |
| ✅ Policy Validation | `validate_policy` | **FREE** |
| 🔒 Public Access Check | `check_no_public_access` | $0.002/call |
| 🛡️ Access Not Granted Check | `check_access_not_granted` | $0.002/call |
| 📊 No New Access Check | `check_no_new_access` | $0.002/call |
| 🔮 Access Preview | `create_access_preview` | **FREE** |
| 📝 Policy Generation | `start_policy_generation` | **FREE** |

## 📦 Supported Resources

### External Access Analysis (15 resource types)

| Category | Resources |
|----------|-----------|
| **Storage** | S3 Buckets, S3 Directory Buckets, EBS Snapshots, EFS |
| **Compute** | Lambda Functions & Layers |
| **Database** | RDS Snapshots, RDS Cluster Snapshots, DynamoDB Tables & Streams |
| **Security** | IAM Roles, KMS Keys, Secrets Manager |
| **Messaging** | SQS Queues, SNS Topics |
| **Containers** | ECR Repositories |

### Internal Access Analysis (6 resource types)
S3 Buckets, S3 Directory Buckets, RDS Snapshots, RDS Cluster Snapshots, DynamoDB Tables & Streams

## 🚀 Quick Start

### Prerequisites
- AWS CLI v2 configured
- Python 3.9+
- AWS account with IAM permissions

### 1️⃣ Deploy Infrastructure
```bash
aws cloudformation deploy \
  --template-file infrastructure/access-analyzer-setup.yaml \
  --stack-name access-analyzer-solution \
  --parameter-overrides NotificationEmail=your@email.com \
  --capabilities CAPABILITY_NAMED_IAM
```

### 2️⃣ Run Security Scan
```bash
pip install boto3
python3 comprehensive_solution.py
```

### 3️⃣ CI/CD Integration
```bash
python3 cicd_integration.py ./policies
```

## 📁 Project Structure

```
├── 📄 comprehensive_solution.py    # Full Python SDK wrapper
├── 📄 cicd_integration.py          # CI/CD pipeline integration
├── 📄 security_dashboard.py        # Security findings dashboard
├── 📁 infrastructure/
│   └── access-analyzer-setup.yaml  # CloudFormation template
├── 📁 .github/workflows/
│   └── policy-validation.yml       # GitHub Actions workflow
├── 📁 01-validate-policy/          # Policy validation examples
├── 📁 02-create-access-preview/    # Access preview examples
├── 📁 03-no-iac/                   # Non-IaC policy scanning
├── 📁 04-cloudformation/           # CloudFormation validation
└── 📁 05-scps/                     # Service Control Policies
```

## 💰 Pricing Estimate

| Component | Price | Example (100 identities) |
|-----------|-------|--------------------------|
| External Access Analyzer | FREE | $0 |
| Unused Access Analyzer | $0.20/identity/month | $20/month |
| Custom Policy Checks | $0.002/call | ~$2/month |
| **Total** | | **~$22/month** |

## 🔧 Configuration Examples

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

### CI/CD Policy Checks
```python
# Block public access
result = solution.check_no_public_access(policy, 'AWS::S3::Bucket')
if result['result'] == 'FAIL':
    sys.exit(1)

# Block dangerous actions
result = solution.check_access_not_granted(policy, ['iam:*', 'iam:PassRole'])
if result['result'] == 'FAIL':
    sys.exit(1)
```

## 📚 Documentation

| Resource | Link |
|----------|------|
| IAM Access Analyzer User Guide | [AWS Docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html) |
| Supported Resource Types | [AWS Docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-resources.html) |
| Custom Policy Checks | [AWS Docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-custom-policy-checks.html) |
| API Reference | [AWS Docs](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/) |
| Pricing | [AWS Pricing](https://aws.amazon.com/iam/access-analyzer/pricing/) |

## 📰 Related AWS Blog Posts

- [Customize scope of unused access analysis](https://aws.amazon.com/blogs/security/customize-the-scope-of-iam-access-analyzer-unused-access-analysis/) (Jan 2025)
- [Refine unused access using recommendations](https://aws.amazon.com/blogs/security/refine-unused-access-using-iam-access-analyzer-recommendations) (Sep 2024)

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

This project is licensed under the MIT-0 License. See [LICENSE](LICENSE) for details.

## 👤 Author

**Kha Van** - [GitHub](https://github.com/vanhoangkha)

---

⭐ Star this repo if you find it helpful!
