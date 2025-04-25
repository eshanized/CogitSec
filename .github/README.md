# CodeQL Security Scanning

This directory contains configuration for GitHub CodeQL scanning, which is used to identify vulnerabilities and security issues in the codebase.

## Workflows

- **codeql-analysis.yml**: Runs automatic code scanning for Rust code to detect security vulnerabilities.

## What CodeQL Scans For

The CodeQL analyzer searches for various security issues, including:

- Memory safety issues
- Buffer overflow vulnerabilities 
- Use-after-free bugs
- Path traversal vulnerabilities
- SQL/Command injection vectors
- Data flow problems
- Resource leaks
- Best practice violations

## How to View Results

After the CodeQL workflow runs, you can view the results in the "Security" tab of the GitHub repository. Navigate to:

1. Security tab
2. Code scanning alerts
3. Filter for specific types of issues or severity levels

## Local Analysis

If you want to run CodeQL analysis locally, you'll need:

1. The CodeQL CLI tool (https://github.com/github/codeql-cli-binaries)
2. The CodeQL standard libraries (https://github.com/github/codeql)

## Additional Resources

- [CodeQL Documentation](https://codeql.github.com/docs)
- [GitHub Code Scanning Documentation](https://docs.github.com/en/code-security/code-scanning)
- [GitHub Advanced Security](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security) 