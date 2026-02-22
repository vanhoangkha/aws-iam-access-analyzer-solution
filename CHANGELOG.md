# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-02-02

### Added

- 🎉 Initial release of AWS IAM Access Analyzer Solution
- ✨ Complete Python SDK implementing all 37 IAM Access Analyzer APIs
- 🔧 CI/CD integration with `PolicyValidator` class
- 📊 Security findings dashboard with `SecurityDashboard` class
- 🏗️ Production-ready CloudFormation template
- 🔄 GitHub Actions workflow for automated policy validation
- 📝 Comprehensive documentation and examples

### Features

#### Analyzer Types
- External Access Analysis (15 resource types)
- Internal Access Analysis (6 resource types)  
- Unused Access Analysis

#### Policy Validation
- Custom Policy Checks (public access, access not granted, no new access)
- Policy Validation against AWS best practices
- Access Preview for policy changes

#### Infrastructure
- Lambda function (Python 3.12)
- SNS Topic with KMS encryption
- EventBridge rules for findings
- CloudWatch Logs (90-day retention)
- IAM roles with least privilege

### Examples
- Policy validation examples
- Access preview examples
- SCP validation examples
- Service-specific scanning
- CloudFormation examples
- CDK examples

[Unreleased]: https://github.com/vanhoangkha/aws-iam-access-analyzer-solution/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/vanhoangkha/aws-iam-access-analyzer-solution/releases/tag/v1.0.0
