# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - 2026-02-02

### Added
- Comprehensive Python SDK wrapper (`comprehensive_solution.py`)
- CI/CD integration script (`cicd_integration.py`)
- Security dashboard (`security_dashboard.py`)
- CloudFormation infrastructure with EventBridge automation
- GitHub Actions workflow for policy validation
- Finding recommendations API support (Sep 2024 feature)
- Analyzer exclusions by account/tags (Jan 2025 feature)

### Changed
- Updated Lambda runtime to Python 3.12
- Added KMS encryption to SNS topic
- Added 90-day log retention
- Improved IAM role with least-privilege permissions

### Fixed
- Policy validation errors in sample files
- SCP policy structure issues
- Action name typos (s3:ListBuckets → s3:ListBucket)

## [1.0.0] - Original

### Added
- Initial sample code for IAM Access Analyzer APIs
- Policy validation examples
- Access preview examples
- SCP validation scripts
- Service-specific bulk scanning scripts
