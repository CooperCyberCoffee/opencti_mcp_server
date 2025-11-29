# Security Policy

## Supported Versions

We release security updates for the following versions:

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 0.4.x   | :white_check_mark: | Current |
| 0.3.x   | :x:                | EOL    |
| 0.2.x   | :x:                | EOL    |
| 0.1.x   | :x:                | EOL    |

**Note:** Only the latest minor version receives security updates. Users should upgrade to v0.4.x for security fixes.

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

### Reporting Process

**Email:** matt@coopercybercoffee.com

**Include in your report:**
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact (confidentiality, integrity, availability)
4. Affected versions
5. Suggested fix (if any)
6. Your contact information for follow-up

**Response Timeline:**
- **Initial response:** Within 48 hours
- **Status update:** Within 7 days
- **Fix timeline:** Depends on severity (see below)

### Severity Levels

**Critical (Fix within 24-48 hours):**
- Remote code execution
- Authentication bypass
- Data exfiltration
- Privilege escalation
- TLP filtering bypass

**High (Fix within 7 days):**
- Injection vulnerabilities (SQL, command, template)
- Access control issues
- Cryptographic weaknesses
- Path traversal

**Medium (Fix within 30 days):**
- Information disclosure
- Denial of service
- Input validation issues
- Audit log tampering

**Low (Fix in next release):**
- Minor information leaks
- Configuration issues
- Non-security bugs

---

## Security Measures

This project implements multiple layers of security controls:

### Data Protection
- ✅ **TLP Filtering:** CISA-compliant Traffic Light Protocol filtering prevents unauthorized data disclosure
- ✅ **Air-Gap Support:** Works with local LLMs for classified environments
- ✅ **Data Classification:** Automatic classification labeling for audit compliance
- ✅ **No Data Persistence:** Sensitive threat intelligence not stored locally

### Input Validation
- ✅ **Sanitization:** All TLP markings sanitized to prevent injection attacks
- ✅ **Path Validation:** Config file paths validated to prevent traversal attacks
- ✅ **Parameter Masking:** Sensitive parameters masked in audit logs
- ✅ **Type Checking:** Strict type validation on all inputs

### Secure Configuration
- ✅ **YAML Safety:** Uses `yaml.safe_load()` not `yaml.load()` (prevents code execution)
- ✅ **Environment Variables:** All secrets via environment variables, never hardcoded
- ✅ **Permission Checks:** Warns if config files are world-writable
- ✅ **Default Secure:** TLP:CLEAR only by default

### Audit & Logging
- ✅ **Comprehensive Logging:** All MCP tool calls logged for audit trail
- ✅ **Sensitive Data Masking:** API tokens and secrets masked in logs
- ✅ **Structured JSON:** SIEM-compatible JSON logging
- ✅ **Compliance Ready:** CMMC, NIST 800-171, SOC 2, HIPAA compliant logging

### Rate Limiting & Performance
- ✅ **DoS Protection:** Token bucket rate limiting (60 calls/minute default)
- ✅ **Progress Reporting:** Real-time status updates for long operations
- ✅ **Cancellation Support:** User-initiated operation abortion
- ✅ **Performance Tracking:** Execution time monitoring for all operations

### Dependency Security
- ✅ **Version Pinning:** All dependencies pinned to major versions
- ✅ **CVE Monitoring:** Regular security scans with pip-audit
- ✅ **Minimal Dependencies:** Small attack surface
- ✅ **Security Audit:** Pre-release security audits (see SECURITY_AUDIT.md)

### Code Security
- ✅ **Static Analysis:** Bandit security linting
- ✅ **Type Safety:** Type hints throughout codebase
- ✅ **Code Review:** Manual security review before release
- ✅ **No Eval/Exec:** No dynamic code execution

---

## Security Best Practices

### For Users

**Deployment:**
1. Use environment variables for secrets (never hardcode)
2. Run with least privilege (non-root user)
3. Restrict network access (localhost only for MCP)
4. Enable audit logging
5. Review TLP policy regularly

**Configuration:**
1. Start with default TLP policy (TLP:CLEAR only)
2. Use `strict_mode: true` for sensitive data
3. Set `allow_unmarked: false`
4. Protect config files: `chmod 600 config/tlp_policy.yaml`
5. Use local LLM for classified/CUI data

**Operations:**
1. Monitor audit logs for suspicious activity
2. Keep dependencies updated: `pip install --upgrade -r requirements.txt`
3. Review security advisories
4. Test TLP filtering with sample data before production use
5. Document your TLP policy decisions

### For Developers

**Contributing:**
1. Run security scan before PR: `bandit -r src/`
2. Check for secrets: Review git history
3. Add security tests for new features
4. Document security implications
5. Follow secure coding practices (see CONTRIBUTING.md)

**Code Review Checklist:**
- [ ] No hardcoded credentials or API keys
- [ ] Input validation on all external input
- [ ] Sensitive data not logged
- [ ] Error messages don't leak sensitive info
- [ ] Dependencies have no known CVEs
- [ ] Tests include security test cases

---

## Known Security Considerations

### Transitive Dependencies
**Issue:** Some transitive dependencies (cryptography, pip, setuptools) have known CVEs

**Status:** Accepted risk
- Build/install tools, not runtime dependencies
- Unused vulnerable functionality
- Documented in SECURITY_AUDIT.md

**Mitigation:** Use modern pip/setuptools versions during development

### Cloud LLM Data Transmission
**Issue:** Cloud LLMs (Claude Pro) receive threat intelligence data

**Status:** By design, with mitigations
- TLP filtering prevents sensitive data transmission
- Default policy: TLP:CLEAR only
- Documented deployment options

**Mitigation:** Use local LLM for sensitive data (TLP:AMBER+, classified, CUI)

### Rate Limiting Configuration
**Issue:** Default rate limit (60 calls/minute) may be too restrictive for some deployments

**Status:** Configurable by design
- Adjustable via `RATE_LIMIT_CALLS_PER_MINUTE` environment variable
- Balance between protection and usability
- Documented in configuration guide

**Mitigation:** Tune based on deployment size (single user: 60, team: 120, enterprise: 300+)

### Bind to All Interfaces
**Issue:** Default MCP server host is 0.0.0.0 (all interfaces)

**Status:** Accepted for containerized deployment
- Expected for Docker/K8s
- Configurable via `MCP_SERVER_HOST=127.0.0.1`
- Network exposure controlled by container orchestration

**Mitigation:** Override with `MCP_SERVER_HOST=127.0.0.1` for local-only binding

---

## Compliance & Standards

This project is designed to support:

### CMMC Level 2
- **AC.L2-3.1.5:** Audit logging
- **AC.L2-3.1.3:** Information flow enforcement (TLP filtering)
- **SC.L2-3.13.11:** Cryptographic protection of CUI

### NIST 800-171
- **3.13.11:** Cryptographic Protection (TLP filtering)
- **3.3.1:** Audit Logging
- **3.5.2:** Authentication (API tokens)
- **3.14.1:** Flaw Remediation

### HIPAA
- **§164.312(b):** Audit controls
- **§164.312(a)(1):** Access controls (TLP filtering)
- **§164.312(a)(2)(iv):** Encryption (data-in-transit only)

### SOC 2 Type II
- **CC6.1:** Logical access controls
- **CC7.2:** System monitoring
- **CC7.3:** Vulnerability management

**Note:** Users are responsible for their own compliance. This tool provides security controls; you must implement organizational policies and procedures.

---

## Disclosure Policy

When a security vulnerability is fixed:

1. **Fix Development:** Develop and test fix in private repository
2. **Version Release:** Release patched version
3. **Advisory Publication:** Publish security advisory on GitHub
4. **CVE Assignment:** Request CVE ID for high/critical issues
5. **User Notification:** Notify users via GitHub, email list
6. **Public Disclosure:** Full disclosure 90 days after patch (or when exploitation detected)

**Credit:** We gladly give credit to security researchers (if desired)

---

## Security Audit History

### v0.3.0 (2025-01-19)
**Scope:** Comprehensive pre-release security audit

**Activities:**
- Dependency CVE scan (pip-audit)
- Static code analysis (bandit)
- Manual code review
- Input validation hardening
- YAML security enhancement
- Audit log sanitization

**Findings:** See [SECURITY_AUDIT.md](SECURITY_AUDIT.md)

**Status:** ✅ Approved for release with documented residual risks

### v0.4.x Series (2025-01-19)
**Scope:** Incremental security enhancements

**v0.4.0 - Performance & Audit Release:**
- Server-side TLP filtering (scope minimization)
- Rate limiting and DoS protection
- Enhanced audit logging with correlation IDs

**v0.4.1 - UX & Cancellation Release:**
- Progress reporting (no security impact)
- User-initiated cancellation (audit logged)

**v0.4.2 - IOC Enrichment Release:**
- Multi-observable search (no security impact)
- Expanded type detection (validation enhanced)

**Status:** ✅ No new vulnerabilities introduced

### Next Audit
**Scheduled:** 2026-02-19 (Quarterly)

---

## Security Contact

**Security Issues:** matt@coopercybercoffee.com
**General Questions:** matt@coopercybercoffee.com
**Project Lead:** Matthew Hopkins
**LinkedIn:** https://linkedin.com/in/matthew-hopkins
**Project:** https://coopercybercoffee.com

---

## Acknowledgments

We thank the security researchers and community members who help keep this project secure:

- (Your name here - report a vulnerability!)

---

*This security policy demonstrates Cooper Cyber Coffee's commitment to security-first development and responsible disclosure practices.*

**Last Updated:** 2025-11-20
**Version:** 0.4.2.1
