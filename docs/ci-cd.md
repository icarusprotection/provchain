# CI/CD Documentation

This document describes the continuous integration and continuous deployment (CI/CD) workflows for ProvChain.

## Overview

ProvChain uses GitHub Actions for CI/CD. There are three main workflows:

1. **CI Workflow** (`.github/workflows/ci.yml`) - Runs on every push and pull request
2. **Release Workflow** (`.github/workflows/release.yml`) - Publishes to PyPI when a release is created
3. **Security Workflow** (`.github/workflows/security.yml`) - Runs security scans on push/PR and weekly

## CI Workflow

The CI workflow runs on every push to `main` and every pull request targeting `main`.

### Jobs

1. **Test** - Runs tests across Python 3.10, 3.11, and 3.12
   - Installs dependencies including dev dependencies
   - Runs pytest with coverage
   - Uploads coverage to Codecov

2. **Lint** - Checks code style with ruff
   - Runs `ruff check src/`

3. **Type Check** - Validates type hints with mypy
   - Runs `mypy src/provchain`

4. **Security** - Runs Bandit security scanner
   - Runs `bandit -r src/provchain`

### Testing Locally

You can test the CI workflow locally:

```bash
# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest --cov=provchain --cov-report=xml

# Run linting
ruff check src/

# Run type checking
mypy src/provchain

# Run security scan
bandit -r src/provchain
```

## Release Workflow

The release workflow automatically publishes to PyPI when a GitHub release is published.

### Process

1. Triggers on `release` event with type `published`
2. Builds the package using `python -m build`
3. Publishes to PyPI using `twine upload`

### Required Secrets

- **`PYPI_API_TOKEN`** - PyPI API token for publishing packages
  - Create at https://pypi.org/manage/account/token/
  - Must have upload permissions for the `provchain` package

### Testing Locally

```bash
# Install build tools
pip install build twine

# Build the package
python -m build

# Test upload (use test PyPI)
twine upload --repository-url https://test.pypi.org/legacy/ dist/*

# Production upload (only when ready)
twine upload dist/*
```

## Security Workflow

The security workflow runs security scans on every push/PR and weekly on Sundays.

### Jobs

1. **Security Scan** - Runs Bandit and Safety
   - Bandit: Static security analysis
   - Safety: Checks dependencies for known vulnerabilities

### Testing Locally

```bash
# Install security tools
pip install bandit safety

# Run Bandit
bandit -r src/provchain

# Run Safety
safety check
```

## Required GitHub Secrets

To set up CI/CD for your repository, configure the following secrets in GitHub:

1. Go to your repository → Settings → Secrets and variables → Actions
2. Add the following secrets:

### `PYPI_API_TOKEN` (Required for releases)

- **Purpose**: Authenticates with PyPI to publish packages
- **How to create**:
  1. Go to https://pypi.org/manage/account/token/
  2. Click "Add API token"
  3. Give it a name (e.g., "ProvChain CI")
  4. Set scope to "Entire account" or limit to the `provchain` project
  5. Copy the token (starts with `pypi-`)
  6. Add it as a secret named `PYPI_API_TOKEN` in GitHub

### Codecov Token (Optional)

- The CI workflow uses Codecov for coverage reporting
- If you want to use Codecov, you may need to add a token
- Check Codecov documentation for your specific setup

## Workflow Status Badges

Add these badges to your README to show workflow status:

```markdown
![CI](https://github.com/your-org/provchain/workflows/CI/badge.svg)
![Security](https://github.com/your-org/provchain/workflows/Security/badge.svg)
```

## Troubleshooting

### CI Workflow Fails

1. **Tests failing**: Run tests locally with `pytest` to reproduce
2. **Linting errors**: Run `ruff check src/` and fix issues
3. **Type errors**: Run `mypy src/provchain` and fix type issues
4. **Security issues**: Review Bandit output and address high-severity issues

### Release Workflow Fails

1. **Build errors**: Test locally with `python -m build`
2. **Upload errors**: Verify `PYPI_API_TOKEN` is set correctly
3. **Authentication errors**: Check token permissions on PyPI

### Security Workflow Issues

1. **Bandit findings**: Review and address security issues
2. **Safety warnings**: Update vulnerable dependencies
3. **False positives**: Add `# nosec` comments or configure Bandit to ignore specific checks

## Best Practices

1. **Always test locally** before pushing
2. **Fix linting and type errors** before opening PRs
3. **Review security findings** regularly
4. **Keep dependencies updated** to avoid security vulnerabilities
5. **Use semantic versioning** for releases

## Additional Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [PyPI Publishing Guide](https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Safety Documentation](https://pyup.io/safety/)

