# Contributing to AWS IAM Access Analyzer Solution

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Style Guidelines](#style-guidelines)

## Code of Conduct

This project adheres to the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct). By participating, you are expected to uphold this code.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Set up the development environment
4. Create a feature branch
5. Make your changes
6. Submit a pull request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/aws-iam-access-analyzer-solution.git
cd aws-iam-access-analyzer-solution

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dev dependencies
pip install -e ".[dev]"

# Verify setup
pytest
```

## Making Changes

### Branch Naming

- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring

### Commit Messages

Follow conventional commits:

```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Example:
```
feat(client): add support for new API endpoint

- Added get_finding_recommendation method
- Updated documentation
```

## Pull Request Process

1. Update documentation if needed
2. Add tests for new functionality
3. Ensure all tests pass: `pytest`
4. Format code: `black src tests && isort src tests`
5. Update CHANGELOG.md
6. Submit PR with clear description

### PR Checklist

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Code formatted with black/isort
- [ ] All tests passing

## Style Guidelines

### Python

- Follow PEP 8
- Use type hints
- Maximum line length: 100 characters
- Use black for formatting
- Use isort for import sorting

### Documentation

- Use clear, concise language
- Include code examples
- Keep README.md up to date

## Questions?

Feel free to open an issue or contact the maintainer at khavan.work@gmail.com.

---

Thank you for contributing! 🎉
