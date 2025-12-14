# ProvChain: Next Steps for Production Release

This document outlines the comprehensive steps needed to prepare ProvChain for production release on PyPI.

## Current Status

✅ **Completed:**
- Core functionality implemented (vet, verify, watch, sbom, config commands)
- Advanced vulnerability detection (vuln command with OSV.dev integration)
- Supply chain attack detection (attack command)
- Test PyPI uploads successful (versions 1.0.0 through 1.1.2)
- All tests passing
- Documentation complete
- CI/CD workflows configured
- Version 1.1.2 ready with bug fixes

## Phase 1: Production PyPI Preparation

### 1.1 Get Production PyPI API Token

1. **Create PyPI Account** (if not already done):
   - Go to https://pypi.org/account/register/
   - Complete registration and verify email

2. **Enable Two-Factor Authentication (2FA)**:
   - Go to https://pypi.org/manage/account/
   - Enable 2FA for enhanced security
   - **Important:** PyPI requires 2FA for new projects and maintainers

3. **Generate API Token**:
   - Go to https://pypi.org/manage/account/
   - Navigate to "API tokens" section
   - Click "Add API token"
   - Choose scope:
     - **For project uploads:** Select "Entire account" or specific project
     - **For automation:** Use "Entire account" with appropriate expiration
   - Copy the token immediately (it won't be shown again)
   - Format: `pypi-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

4. **Store Token Securely**:
   - **Option A: Environment Variable (Recommended for CI/CD)**
     ```powershell
     # Windows PowerShell
     $env:TWINE_PASSWORD = "pypi-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
     ```
   - **Option B: Credentials File**
     ```powershell
     # Create ~/.pypirc file
     [pypi]
     username = __token__
     password = pypi-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
     ```
   - **Option C: GitHub Secrets (for CI/CD)**
     - Go to repository Settings → Secrets and variables → Actions
     - Add new secret: `PYPI_API_TOKEN`
     - Value: Your PyPI API token

### 1.2 Verify Test PyPI Upload

Before production release, verify the latest Test PyPI version works correctly:

```powershell
# Install from Test PyPI
pip install --upgrade --no-cache-dir --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ provchain

# Verify version
provchain --version

# Test all commands
provchain vet requests
provchain vuln check requests
provchain attack detect requests
provchain config show
```

### 1.3 Final Code Review Checklist

- [ ] Review all recent changes in version 1.1.2
- [ ] Verify all tests pass locally
- [ ] Check for any TODO comments or temporary code
- [ ] Ensure no debug/development code remains
- [ ] Verify all error messages are user-friendly
- [ ] Check that all imports are used
- [ ] Review security implications of all external API calls

## Phase 2: Production Release Process

### 2.1 Update Version Number

For the production release, decide on version number:

- **Option A: Release 1.1.2 as-is** (if Test PyPI version is stable)
- **Option B: Bump to 1.2.0** (if adding new features)
- **Option C: Bump to 2.0.0** (if making breaking changes)

**Recommended:** Start with **1.1.2** for production, then increment for future releases.

### 2.2 Update Version Files

If changing version, update:
1. `pyproject.toml`: `version = "1.1.2"` (or new version)
2. `src/provchain/__init__.py`: `__version__ = "1.1.2"` (or new version)

### 2.3 Build Production Package

```powershell
# Clean previous builds
Remove-Item -Recurse -Force dist, build, src\provchain.egg-info -ErrorAction SilentlyContinue

# Build package
python -m build

# Verify build contents
Get-ChildItem dist
```

### 2.4 Upload to Production PyPI

**Method 1: Using twine (Recommended)**

```powershell
# Set credentials
$env:TWINE_USERNAME = "__token__"
$env:TWINE_PASSWORD = "pypi-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Upload to production PyPI
twine upload dist/*

# Verify upload
# Visit https://pypi.org/project/provchain/
```

**Method 2: Using GitHub Actions (Automated)**

The CI/CD workflow should already be configured. To trigger:
1. Create a new release tag: `git tag v1.1.2`
2. Push tag: `git push origin v1.1.2`
3. GitHub Actions will automatically build and upload

### 2.5 Verify Production Installation

```powershell
# Uninstall any test versions
pip uninstall provchain -y

# Install from production PyPI
pip install provchain

# Verify
provchain --version
provchain --help
```

## Phase 3: Post-Release Tasks

### 3.1 Update GitHub Repository

1. **Create Release**:
   - Go to https://github.com/ipf/provchain/releases
   - Click "Draft a new release"
   - Tag: `v1.1.2`
   - Title: `ProvChain v1.1.2 - Production Release`
   - Description: Include changelog and features
   - Attach release notes

2. **Update README**:
   - Verify all badges work
   - Update installation instructions if needed
   - Add release notes section

### 3.2 Documentation Updates

- [ ] Verify all documentation links work
- [ ] Update version numbers in docs if needed
- [ ] Add release notes to documentation
- [ ] Update any example commands with latest features

### 3.3 Monitoring and Support

1. **Monitor PyPI Statistics**:
   - Check download statistics: https://pypi.org/project/provchain/#history
   - Monitor for any issues or errors

2. **Set Up Issue Tracking**:
   - Ensure GitHub Issues are enabled
   - Create templates for bug reports and feature requests
   - Set up issue labels and milestones

3. **Community Engagement**:
   - Announce release on relevant channels
   - Respond to user feedback
   - Monitor for security issues

## Phase 4: Future Enhancements

### 4.1 Short-Term (Next Release)

- [ ] Add more comprehensive test coverage
- [ ] Improve error messages and user feedback
- [ ] Add more vulnerability databases (NVD integration)
- [ ] Enhance attack detection algorithms
- [ ] Add support for more package ecosystems (npm, RubyGems, etc.)

### 4.2 Medium-Term

- [ ] Plugin system for custom analyzers
- [ ] Web dashboard for monitoring
- [ ] API server mode
- [ ] Integration with CI/CD platforms (GitHub Actions, GitLab CI, Jenkins)
- [ ] Performance optimizations

### 4.3 Long-Term

- [ ] Machine learning for attack detection
- [ ] Real-time threat intelligence feeds
- [ ] Enterprise features (SSO, audit logs, etc.)
- [ ] Multi-language support
- [ ] Cloud-hosted service option

## Phase 5: Maintenance and Updates

### 5.1 Regular Maintenance Tasks

- **Weekly**: Monitor PyPI downloads and GitHub issues
- **Monthly**: Review and update dependencies
- **Quarterly**: Security audit and dependency updates
- **As needed**: Bug fixes and security patches

### 5.2 Version Release Strategy

Follow semantic versioning (MAJOR.MINOR.PATCH):
- **PATCH** (1.1.2 → 1.1.3): Bug fixes only
- **MINOR** (1.1.2 → 1.2.0): New features, backward compatible
- **MAJOR** (1.1.2 → 2.0.0): Breaking changes

### 5.3 Security Updates

- Monitor for security vulnerabilities in dependencies
- Respond quickly to security issues
- Follow responsible disclosure practices
- Keep CVE database integrations updated

## Phase 6: CI/CD Automation

### 6.1 Automated Release Workflow

Ensure GitHub Actions workflow (`release.yml`) is configured:

```yaml
# .github/workflows/release.yml should:
# 1. Trigger on tag push (v*)
# 2. Build package
# 3. Run tests
# 4. Upload to PyPI
# 5. Create GitHub release
```

### 6.2 Automated Testing

- [ ] All tests pass before release
- [ ] Code coverage maintained
- [ ] Linting and formatting checks
- [ ] Security scanning

## Troubleshooting

### Common Issues

1. **Upload Fails with 400 Bad Request**:
   - Version already exists on PyPI
   - Solution: Increment version number

2. **Authentication Fails**:
   - Check API token is correct
   - Ensure 2FA is enabled if required
   - Verify token hasn't expired

3. **Package Installation Issues**:
   - Check Python version compatibility
   - Verify all dependencies are available
   - Check for conflicting packages

### Getting Help

- GitHub Issues: https://github.com/ipf/provchain/issues
- Documentation: https://provchain.readthedocs.io (if configured)
- PyPI Project Page: https://pypi.org/project/provchain/

## Quick Reference Commands

### Production Release Checklist

```powershell
# 1. Update version
# Edit pyproject.toml and src/provchain/__init__.py

# 2. Clean and build
Remove-Item -Recurse -Force dist, build, src\provchain.egg-info -ErrorAction SilentlyContinue
python -m build

# 3. Test locally (optional)
pip install dist/provchain-*.whl --force-reinstall

# 4. Upload to PyPI
$env:TWINE_USERNAME = "__token__"
$env:TWINE_PASSWORD = "your-token-here"
twine upload dist/*

# 5. Verify
pip install provchain --upgrade
provchain --version

# 6. Create GitHub release
git tag v1.1.2
git push origin v1.1.2
```

## Success Criteria

✅ Production release is successful when:
- Package is available on PyPI
- Installation works: `pip install provchain`
- All commands function correctly
- Documentation is accessible
- GitHub release is created
- No critical bugs reported in first 48 hours

---

**Last Updated:** 2025-01-XX  
**Current Version:** 1.1.2  
**Next Production Version:** 1.1.2 (or 1.2.0 if adding features)

