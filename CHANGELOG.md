# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-02-22

### Added

- Initial release of AWS IAM Access Analyzer Solution
- Complete Python SDK implementing all 37 IAM Access Analyzer APIs
- Multi-region support (all 28 commercial AWS regions)
- Organization-level analyzer support
- Production-ready features: retry logic, rate limiting, health checks
- CI/CD integration with PolicyValidator class
- Security findings dashboard with SecurityDashboard class
- CloudFormation template for infrastructure deployment
- GitHub Actions workflow for automated testing
- Comprehensive documentation and examples

### Features

#### Analyzer Types
- External Access Analysis (ACCOUNT, ORGANIZATION)
- Unused Access Analysis (ACCOUNT_UNUSED_ACCESS, ORGANIZATION_UNUSED_ACCESS)

#### API Coverage (37 APIs)
- Analyzer Management (5 APIs)
- Findings (6 APIs)
- Archive Rules (6 APIs)
- Policy Validation (4 APIs)
- Access Preview (4 APIs)
- Policy Generation (4 APIs)
- Resources (3 APIs)
- Recommendations (2 APIs)
- Tags (3 APIs)

#### CLI Commands
- `access-analyzer scan` - Run security scan
- `access-analyzer validate` - Validate IAM policies
- `access-analyzer dashboard` - Show security dashboard
- `access-analyzer health` - Check AWS connectivity

#### Infrastructure
- SNS Topic with KMS encryption
- EventBridge rules for findings
- CloudWatch Logs (90-day retention)
- IAM roles with least privilege

[Unreleased]: https://github.com/vanhoangkha/aws-iam-access-analyzer-solution/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/vanhoangkha/aws-iam-access-analyzer-solution/releases/tag/v1.0.0
