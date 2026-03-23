# Security Policy

## Scope

certconv is a local-only tool. It reads certificate files from your filesystem and converts between formats. It does not:

- Make network connections
- Generate new certificates or keys
- Modify existing files (all outputs use exclusive-create)
- Store or transmit credentials

Passwords for PFX operations are passed via file descriptors or temp files, never via command-line arguments visible in `ps` output.

## Reporting a Vulnerability

If you find a security issue (e.g. a path traversal, command injection via crafted filenames, or a dependency vulnerability), please report it privately:

1. Open a [GitHub Security Advisory](https://github.com/nickromney/certconv/security/advisories/new)
2. Or email the maintainer directly via the address on the GitHub profile

Please include:

- Description of the issue
- Steps to reproduce
- Affected version(s)

You should receive a response within 7 days.

## Dependencies

Dependencies are monitored via Dependabot (weekly checks for Go modules and GitHub Actions).
Run `make vuln` to check for known vulnerabilities locally.
