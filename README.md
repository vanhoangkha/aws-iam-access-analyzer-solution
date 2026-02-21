# AWS IAM Access Analyzer Solution

[![AWS](https://img.shields.io/badge/AWS-IAM%20Access%20Analyzer-FF9900?logo=amazon-aws)](https://aws.amazon.com/iam/access-analyzer/)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT--0-green.svg)](LICENSE)

Complete Python SDK implementing all 37 IAM Access Analyzer APIs for AWS security automation.

## Installation

```bash
pip install -e .
```

## Quick Start

```python
from access_analyzer import AccessAnalyzerClient

client = AccessAnalyzerClient()

# Run full security scan
results = client.full_scan()
print(f"External findings: {results['summary']['external_count']}")
print(f"Unused findings: {results['summary']['unused_count']}")

# Validate a policy
findings = client.validate_policy({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
})

# Check for public access
result = client.check_no_public_access(policy, 'AWS::S3::Bucket')
```

## CLI Usage

```bash
# Run security scan
python -m access_analyzer scan

# Validate policies in directory
python -m access_analyzer validate ./policies

# Show security dashboard
python -m access_analyzer dashboard

# Export report to JSON
python -m access_analyzer dashboard --export report.json
```

## Project Structure

```
.
├── src/
│   └── access_analyzer/
│       ├── __init__.py          # Package exports
│       ├── __main__.py          # CLI entry point
│       ├── client.py            # AccessAnalyzerClient (37 APIs)
│       ├── cicd.py              # PolicyValidator for CI/CD
│       └── dashboard.py         # SecurityDashboard
├── infrastructure/
│   └── access-analyzer-setup.yaml  # CloudFormation template
├── examples/
│   ├── policy-validation/       # Policy validation examples
│   ├── access-preview/          # Access preview examples
│   ├── scp-validation/          # SCP validation examples
│   ├── service-scanning/        # Service-specific scanning
│   ├── cloudformation/          # CloudFormation examples
│   ├── cdk/                     # CDK examples
│   └── sample-policies/         # Sample IAM policies
├── tests/                       # Unit tests
├── pyproject.toml               # Package configuration
└── README.md
```

## All 37 APIs Implemented

### Analyzer Management (5)
- `create_analyzer` - Create external, internal, or unused access analyzer
- `delete_analyzer` - Delete an analyzer
- `get_analyzer` - Get analyzer details
- `list_analyzers` - List all analyzers
- `update_analyzer` - Update analyzer configuration

### Findings (6)
- `list_findings` - List findings (v1)
- `list_findings_v2` - List findings with enhanced details
- `get_finding` - Get finding details (v1)
- `get_finding_v2` - Get finding details (v2)
- `update_findings` - Archive or resolve findings
- `get_findings_statistics` - Get aggregated statistics

### Archive Rules (6)
- `create_archive_rule` - Create auto-archive rule
- `delete_archive_rule` - Delete archive rule
- `get_archive_rule` - Get archive rule details
- `list_archive_rules` - List all archive rules
- `update_archive_rule` - Update archive rule
- `apply_archive_rule` - Apply rule to existing findings

### Policy Validation (4)
- `validate_policy` - Validate against best practices (FREE)
- `check_no_public_access` - Check for public access ($0.002/call)
- `check_access_not_granted` - Check actions not granted ($0.002/call)
- `check_no_new_access` - Compare policies ($0.002/call)

### Access Preview (4)
- `create_access_preview` - Preview policy changes (FREE)
- `get_access_preview` - Get preview status
- `list_access_previews` - List all previews
- `list_access_preview_findings` - Get preview findings

### Policy Generation (4)
- `start_policy_generation` - Generate from CloudTrail (FREE)
- `get_generated_policy` - Get generated policy
- `cancel_policy_generation` - Cancel generation job
- `list_policy_generations` - List generation jobs

### Resources (3)
- `get_analyzed_resource` - Get resource details
- `list_analyzed_resources` - List analyzed resources
- `start_resource_scan` - Trigger immediate scan

### Recommendations (2)
- `generate_finding_recommendation` - Generate recommendations
- `get_finding_recommendation` - Get recommendations

### Tags (3)
- `tag_resource` - Add tags to analyzer
- `untag_resource` - Remove tags
- `list_tags_for_resource` - List tags

## Pricing

| Feature | Cost |
|---------|------|
| External Access Analyzer | FREE |
| Unused Access Analyzer | $0.20/identity/month |
| Internal Access Analyzer | $9.00/resource/month |
| Custom Policy Checks | $0.002/call |
| Policy Validation | FREE |
| Access Preview | FREE |
| Policy Generation | FREE |

## Deploy Infrastructure

```bash
aws cloudformation deploy \
  --template-file infrastructure/access-analyzer-setup.yaml \
  --stack-name access-analyzer \
  --parameter-overrides NotificationEmail=your@email.com \
  --capabilities CAPABILITY_NAMED_IAM
```

## Documentation

- [IAM Access Analyzer User Guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [API Reference](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_Operations.html)
- [Pricing](https://aws.amazon.com/iam/access-analyzer/pricing/)

## License

MIT-0 License. See [LICENSE](LICENSE) for details.
