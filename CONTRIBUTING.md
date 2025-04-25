# Contributing to CogitSec

Thank you for your interest in contributing to CogitSec! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Issue Reporting](#issue-reporting)
- [Feature Requests](#feature-requests)

## Code of Conduct

This project and everyone participating in it is governed by the [CogitSec Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/cogitsec.git
   cd cogitsec
   ```
3. **Add the upstream repository** as a remote:
   ```bash
   git remote add upstream https://github.com/username/cogitsec.git
   ```
4. **Create a branch** for your work:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Workflow

1. **Set up your development environment**:
   - Install Rust (1.67+)
   - Install GTK development libraries
   - Install libadwaita development libraries

2. **Build the project**:
   ```bash
   cargo build
   ```

3. **Run the application**:
   ```bash
   cargo run
   ```

4. **Run tests**:
   ```bash
   cargo test
   ```

5. **Make your changes**

6. **Ensure your code passes linting**:
   ```bash
   cargo clippy -- -D warnings
   ```

7. **Format your code**:
   ```bash
   cargo fmt
   ```

## Pull Request Process

1. **Update your fork** with the latest changes from upstream:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Push your branch** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

3. **Create a Pull Request** from your fork to the main repository

4. **Address review comments** and update your PR as needed

5. **Your PR will be merged** once it has been approved by maintainers

## Coding Standards

We follow Rust's official style guidelines. Some key points:

- Use `cargo fmt` to format your code
- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Write clear, descriptive code with appropriate comments
- Use meaningful variable and function names
- Keep functions small and focused on a single task
- Avoid unwraps in production code; handle errors appropriately

## Testing

- All new features should include appropriate tests
- Ensure all tests pass before submitting a PR
- For UI components, include appropriate integration tests
- Write both unit tests and integration tests where applicable

## Documentation

- Document all public APIs using Rust's documentation format
- Include examples in documentation when appropriate
- Update the README.md or other documentation as needed
- Create or update wiki pages for significant features

## Issue Reporting

When reporting issues, please use the issue template and include:

- A clear description of the issue
- Steps to reproduce the problem
- Expected behavior
- Actual behavior
- Screenshots if applicable
- Environment information (OS, Rust version, etc.)

## Feature Requests

Feature requests are welcome! When suggesting a feature, please:

- Provide a clear description of the feature
- Explain why it would be useful to the project
- Consider how it might be implemented
- Discuss potential drawbacks or challenges

## Security Issues

If you discover a security vulnerability, please do NOT open an issue. Email security@cogitsec.com instead.

---

Thank you for contributing to CogitSec! Your efforts help make the project better for everyone.
