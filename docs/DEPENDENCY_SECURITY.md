# Dependency Security Report

This document outlines the findings from the `pip-audit` scan (Phase 7 - SEC-004) and the remediation steps applied to the portal's dependencies.

## Audit Findings

The initial scan of `requirements.txt` identified the following vulnerable packages:

1. **`python-dotenv` (Version 1.0.1)**
   - **Vulnerability:** CVE-2026-66380 (GHSA-8qwc-g9w5-vwh7)
   - **Description:** `set_key()` and `unset_key()` follow symbolic links when rewriting `.env` files, allowing a local attacker to overwrite arbitrary files via a crafted symlink when a cross-device rename fallback is triggered.
   - **Remediation:** Pinned to version `1.2.2`.

2. **`cryptography` (Version 49.0.0)**
   - **Vulnerability:** CVE-2026-69247 (GHSA-g6cj-pr64-35w5)
   - **Description:** `pkcs7_decrypt_der`, `pkcs7_decrypt_pem`, and `pkcs7_decrypt_smime` disclosed the exact length recovered from the RSA operation. This gives an attacker a Bleichenbacher oracle against the content-encryption key.
   - **Remediation:** Pinned to version `50.0.0`.

## Remediated State

The `requirements.txt` file was successfully updated, and a subsequent run of `pip-audit -r requirements.txt` confirms that zero known vulnerabilities remain in the dependency tree.

*Note: The environment also showed some previously reported vulnerabilities (like `requests` TLS pooling, `jinja2` XSS, and `werkzeug` DoS) which were already mitigated by upgrading those packages to newer versions in `requirements.txt` (`requests==2.34.2`, `werkzeug==3.1.8`, `PyJWT==2.13.0`).*


3. **`flask` (Version 3.0.3)**
   - **Vulnerability:** CVE-2026-27205 (GHSA-68rp-wp8r-4726)
   - **Description:** Use of Cache Containing Sensitive Information due to missing `Vary: Cookie` header when session is accessed via the `in` operator.
   - **Remediation:** Pinned to version `3.1.3`.
