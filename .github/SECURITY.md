# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability within CogitSec, please follow these steps:

1. **Do NOT disclose the vulnerability publicly**
2. Send an email to security@example.com with details about the vulnerability
3. Include steps to reproduce, potential impact, and any suggestions for remediation if possible
4. Allow some time for the vulnerability to be addressed before any public disclosure

### What to expect

- A confirmation of your report within 48 hours
- A determination of the validility and severity within 7 days
- Regular updates on the progress of the fix (at least weekly)
- Credit for discovering and reporting the vulnerability (unless you prefer to remain anonymous)

## Security Features

This project implements several security features:

1. **Automated Scanning**: We use GitHub CodeQL for automated security scanning of our codebase
2. **Dependency Monitoring**: Dependabot monitors our dependencies for known vulnerabilities
3. **Regular Audits**: The codebase undergoes regular security reviews

## Best Practices for Contributors

When contributing to this project, please:

1. Follow secure coding practices
2. Avoid hardcoding sensitive information
3. Be careful with untrusted input, especially user input from the UI
4. Use proper input validation and sanitization
5. Report any security concerns immediately through proper channels 