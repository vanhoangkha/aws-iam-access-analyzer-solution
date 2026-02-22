# AWS IAM Access Analyzer Solution

[![AWS](https://img.shields.io/badge/AWS-IAM%20Access%20Analyzer-FF9900?logo=amazon-aws)](https://aws.amazon.com/iam/access-analyzer/)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT--0-green.svg)](LICENSE)
[![CI](https://github.com/vanhoangkha/aws-iam-access-analyzer-solution/actions/workflows/ci.yml/badge.svg)](https://github.com/vanhoangkha/aws-iam-access-analyzer-solution/actions)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Production-ready Python SDK implementing all 37 IAM Access Analyzer APIs for AWS security automation.

## Overview

AWS IAM Access Analyzer helps identify resources shared with external entities and unused permissions. This solution provides a comprehensive Python SDK with:

- **Complete API Coverage** - All 37 IAM Access Analyzer APIs
- **Multi-Region Support** - Scan all 28 commercial AWS regions
- **Organization Support** - Organization-wide security scanning
- **Production Ready** - Retry logic, rate limiting, health checks
- **CI/CD Integration** - Built-in policy validation for pipelines
- **Security Dashboard** - Visual reporting and JSON export

## Architecture

![Architecture](docs/architecture.png)

| Diagram | Description |
|---------|-------------|
| [CI/CD Pipeline](docs/cicd-pipeline.png) | Policy validation in CI/CD |
| [Monitoring Flow](docs/monitoring-flow.png) | Security alerting flow |
| [SDK Components](docs/sdk-components.png) | Package structure |
| [Full Documentation](docs/ARCHITECTURE.md) | Complete architecture docs |

---

## Quick Start

### Installation

```bash
pip install -e .
```

### Verify Installation

```bash
# Check version
access-analyzer --version

# Verify AWS connectivity
access-analyzer health
```

### Run Your First Scan

```bash
# Single region scan
access-analyzer scan

# Output as JSON
access-analyzer scan --json
```

---

## Usage Guide

### CLI Commands

| Command | Description |
|---------|-------------|
| `access-analyzer health` | Check AWS credentials and permissions |
| `access-analyzer scan` | Run security scan |
| `access-analyzer validate <path>` | Validate IAM policies |
| `access-analyzer dashboard` | Show security dashboard |

### Scan Options

```bash
# Single region (default: us-east-1 or AWS_DEFAULT_REGION)
access-analyzer scan

# Specific region
access-analyzer scan --region eu-west-1

# All 28 commercial AWS regions
access-analyzer scan --all-regions

# Organization-level (from management account)
access-analyzer scan --org

# All regions + organization
access-analyzer scan --all-regions --org

# JSON output for automation
access-analyzer scan --json
access-analyzer scan --all-regions --json
```

### Policy Validation

```bash
# Validate single policy
access-analyzer validate policy.json

# Validate directory of policies
access-analyzer validate ./policies/

# Use in CI/CD (exits with code 1 on failure)
access-analyzer validate ./policies/ || exit 1
```

### Security Dashboard

```bash
# Display dashboard
access-analyzer dashboard

# Export to JSON
access-analyzer dashboard --export report.json

# Specific region
access-analyzer dashboard --region ap-southeast-1
```

### Python SDK

```python
from access_analyzer import AccessAnalyzerClient, health_check

# Verify connectivity
status = health_check()
print(status)  # {'status': 'healthy', 'checks': {...}}

# Initialize client
client = AccessAnalyzerClient()

# Single region scan
results = client.full_scan()
print(f"External: {results['summary']['external_count']}")
print(f"Unused: {results['summary']['unused_count']}")

# Multi-region scan
client = AccessAnalyzerClient(regions=['us-east-1', 'eu-west-1', 'ap-southeast-1'])
results = client.full_scan_all_regions()

# All commercial regions
results = AccessAnalyzerClient.scan_all_commercial_regions()

# Organization-level (from management account)
results = client.full_scan(use_org=True)

# Validate a policy
findings = client.validate_policy({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
})

# Check for public access ($0.002/call)
result = client.check_no_public_access(policy, 'AWS::S3::Bucket')

# Check dangerous actions not granted ($0.002/call)
result = client.check_access_not_granted(policy, ['iam:*', 's3:*'])
```

---

## Pricing and TCO

### AWS IAM Access Analyzer Pricing

| Feature | Cost | Notes |
|---------|------|-------|
| External Access Analyzer | FREE | Detects resources shared externally |
| Unused Access Analyzer | $0.20/IAM role or user/month | Identifies unused permissions |
| Custom Policy Checks | $0.002/API call | check_no_public_access, check_access_not_granted, check_no_new_access |
| Policy Validation | FREE | validate_policy API |
| Access Preview | FREE | Preview policy changes before applying |
| Policy Generation | FREE | Generate least-privilege policies from CloudTrail |

### TCO Examples

#### Small Organization (50 IAM identities, 1 region)

| Component | Monthly Cost |
|-----------|-------------|
| External Access Analyzer | $0.00 |
| Unused Access Analyzer (50 identities) | $10.00 |
| Custom Policy Checks (~1,000 calls) | $2.00 |
| **Total** | **$12.00/month** |

#### Medium Organization (500 IAM identities, 3 regions)

| Component | Monthly Cost |
|-----------|-------------|
| External Access Analyzer | $0.00 |
| Unused Access Analyzer (500 identities) | $100.00 |
| Custom Policy Checks (~10,000 calls) | $20.00 |
| **Total** | **$120.00/month** |

#### Enterprise (5,000 IAM identities, all regions, with CI/CD)

| Component | Monthly Cost |
|-----------|-------------|
| External Access Analyzer | $0.00 |
| Unused Access Analyzer (5,000 identities) | $1,000.00 |
| Custom Policy Checks (~100,000 calls) | $200.00 |
| **Total** | **$1,200.00/month** |

### Cost Optimization Tips

1. **Use FREE features first**: External Access Analyzer, Policy Validation, Access Preview
2. **Target unused access scanning**: Only enable for production accounts
3. **Batch policy checks**: Combine multiple checks in CI/CD pipelines
4. **Use archive rules**: Auto-archive expected findings to reduce noise

### ROI Considerations

| Risk Mitigated | Potential Cost Avoided |
|----------------|----------------------|
| Data breach from public S3 bucket | $100K - $10M+ |
| Compliance violation (SOC2, HIPAA) | $50K - $500K |
| Privilege escalation attack | $100K - $5M |
| Unused access exploitation | $50K - $1M |

A single prevented security incident typically covers years of Access Analyzer costs.

---

## API Reference

### Analyzer Management (5 APIs)

| Method | Description | Cost |
|--------|-------------|------|
| `create_analyzer` | Create analyzer (ACCOUNT, ORGANIZATION, UNUSED_ACCESS) | FREE |
| `delete_analyzer` | Delete an analyzer | FREE |
| `get_analyzer` | Get analyzer details | FREE |
| `list_analyzers` | List all analyzers | FREE |
| `update_analyzer` | Update configuration | FREE |

### Findings (6 APIs)

| Method | Description | Cost |
|--------|-------------|------|
| `list_findings` | List findings (v1) | FREE |
| `list_findings_v2` | List with enhanced details | FREE |
| `get_finding` | Get finding details (v1) | FREE |
| `get_finding_v2` | Get finding details (v2) | FREE |
| `update_findings` | Archive or resolve | FREE |
| `get_findings_statistics` | Aggregated statistics | FREE |

### Policy Validation (4 APIs)

| Method | Description | Cost |
|--------|-------------|------|
| `validate_policy` | Validate against best practices | FREE |
| `check_no_public_access` | Check for public access | $0.002/call |
| `check_access_not_granted` | Check actions not granted | $0.002/call |
| `check_no_new_access` | Compare policies | $0.002/call |

### Access Preview (4 APIs)

| Method | Description | Cost |
|--------|-------------|------|
| `create_access_preview` | Preview policy changes | FREE |
| `get_access_preview` | Get preview status | FREE |
| `list_access_previews` | List all previews | FREE |
| `list_access_preview_findings` | Get preview findings | FREE |

### Policy Generation (4 APIs)

| Method | Description | Cost |
|--------|-------------|------|
| `start_policy_generation` | Generate from CloudTrail | FREE |
| `get_generated_policy` | Get generated policy | FREE |
| `cancel_policy_generation` | Cancel job | FREE |
| `list_policy_generations` | List jobs | FREE |

### Archive Rules (6 APIs)

| Method | Description | Cost |
|--------|-------------|------|
| `create_archive_rule` | Create auto-archive rule | FREE |
| `delete_archive_rule` | Delete rule | FREE |
| `get_archive_rule` | Get rule details | FREE |
| `list_archive_rules` | List all rules | FREE |
| `update_archive_rule` | Update rule | FREE |
| `apply_archive_rule` | Apply to existing findings | FREE |

### Resources (3 APIs)

| Method | Description | Cost |
|--------|-------------|------|
| `get_analyzed_resource` | Get resource details | FREE |
| `list_analyzed_resources` | List analyzed resources | FREE |
| `start_resource_scan` | Trigger immediate scan | FREE |

### Recommendations (2 APIs)

| Method | Description | Cost |
|--------|-------------|------|
| `generate_finding_recommendation` | Generate recommendations | FREE |
| `get_finding_recommendation` | Get recommendations | FREE |

### Tags (3 APIs)

| Method | Description | Cost |
|--------|-------------|------|
| `tag_resource` | Add tags | FREE |
| `untag_resource` | Remove tags | FREE |
| `list_tags_for_resource` | List tags | FREE |

---

## Infrastructure Deployment

### CloudFormation

```bash
aws cloudformation deploy \
  --template-file infrastructure/access-analyzer-setup.yaml \
  --stack-name access-analyzer \
  --parameter-overrides NotificationEmail=security@example.com \
  --capabilities CAPABILITY_NAMED_IAM
```

### What Gets Deployed

- External Access Analyzer (ACCOUNT type)
- Unused Access Analyzer (ACCOUNT_UNUSED_ACCESS type)
- SNS Topic for alerts (KMS encrypted)
- EventBridge rules for findings
- CloudWatch Log Group (90-day retention)
- IAM roles with least privilege

---

## Production Features

### Retry and Rate Limiting

```python
# Built-in exponential backoff for transient failures
# Handles: Throttling, ServiceUnavailable, InternalServerError
# Config: 3 retries, 1-30s delay, adaptive mode
```

### Health Checks

```python
from access_analyzer import health_check

result = health_check()
# {
#   'status': 'healthy',
#   'version': '1.0.0',
#   'checks': {
#     'credentials': {'status': 'ok', 'account': '123456789012'},
#     'access_analyzer': {'status': 'ok'}
#   }
# }
```

### Multi-Region Support

```python
# All 28 commercial AWS regions supported
client = AccessAnalyzerClient(regions=AccessAnalyzerClient.ALL_REGIONS)
results = client.full_scan_all_regions()
```

### Organization Support

```python
# From AWS Organizations management account
client = AccessAnalyzerClient()
if client.is_org_management_account():
    results = client.full_scan(use_org=True)  # Scans all member accounts
```

---

## Project Structure

```
.
├── src/access_analyzer/
│   ├── __init__.py          # Package exports, health_check()
│   ├── __main__.py          # CLI entry point
│   ├── client.py            # AccessAnalyzerClient (37 APIs)
│   ├── cicd.py              # PolicyValidator for CI/CD
│   └── dashboard.py         # SecurityDashboard
├── infrastructure/
│   └── access-analyzer-setup.yaml
├── examples/
│   ├── policy-validation/   # Policy validation examples
│   ├── access-preview/      # Access preview examples
│   └── sample-policies/     # Sample IAM policies
├── tests/                   # Unit tests
└── docs/                    # Documentation
```

---

## Development

```bash
# Clone repository
git clone https://github.com/vanhoangkha/aws-iam-access-analyzer-solution.git
cd aws-iam-access-analyzer-solution

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black src tests
isort src tests
```

---

## Documentation

- [IAM Access Analyzer User Guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [API Reference](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_Operations.html)
- [Pricing](https://aws.amazon.com/iam/access-analyzer/pricing/)
- [Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-best-practices.html)

---

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md).

## License

MIT-0 License - see [LICENSE](LICENSE).

## Author

**Kha Van** - khavan.work@gmail.com - [@vanhoangkha](https://github.com/vanhoangkha)
