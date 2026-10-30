# Security Policy

## Supported versions

secure-exchange has not reached v1.0 yet. Only the latest commit on `main` receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub:
[Security → Report a vulnerability](https://github.com/tntrock/secure-exchange/security/advisories/new).

Include affected version/commit, steps to reproduce, and impact. You should get an initial response within 7 days. Once a fix is released we publish a GitHub Security Advisory and credit you unless you prefer otherwise.

## Scope

In scope: anything that breaks the platform's guarantees — encryption at rest, OTP/TOTP authentication, share access control (recipient lists, IP limits, expiry, view limits), view-only enforcement (obtaining original bytes from a view-only share), watermark/trace-code bypass, audit-log tampering, render-worker sandbox escape, and secrets leaking into logs.

Out of scope: screenshots or camera capture of a watermarked view (watermarks deter and trace, they cannot prevent), denial of service by an authenticated admin, and issues in self-hosters' own deployment (TLS, firewall, host hardening).
