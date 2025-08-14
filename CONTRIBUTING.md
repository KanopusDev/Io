# Contributing to Io URL Shortener

Thank you for your interest in contributing to Io URL Shortener! We welcome contributions from everyone, regardless of experience level. This document provides guidelines and instructions to help you get started.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
  - [Setting Up Your Development Environment](#setting-up-your-development-environment)
  - [Understanding the Project Structure](#understanding-the-project-structure)
- [Development Workflow](#development-workflow)
  - [Branching Strategy](#branching-strategy)
  - [Commit Messages](#commit-messages)
  - [Pull Requests](#pull-requests)
- [Coding Standards](#coding-standards)
  - [Python Style Guide](#python-style-guide)
  - [JavaScript Style Guide](#javascript-style-guide)
  - [Documentation](#documentation)
- [Testing](#testing)
  - [Writing Tests](#writing-tests)
  - [Running Tests](#running-tests)
- [Bug Reports and Feature Requests](#bug-reports-and-feature-requests)
- [Review Process](#review-process)
- [Community](#community)

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- **Be Respectful**: Treat everyone with respect. No harassment, discrimination, or hate speech will be tolerated.
- **Be Constructive**: Offer constructive feedback and be open to receiving it.
- **Be Collaborative**: Work together to create better solutions.
- **Be Mindful**: Consider the impact of your words and actions on others.

Violations of the Code of Conduct may result in removal from the project community.

## Getting Started

### Setting Up Your Development Environment

1. **Fork the Repository**:
   - Visit the [Io URL Shortener repository](https://github.com/kanopusdev/io)
   - Click the "Fork" button in the top right corner

2. **Clone Your Fork**:
   ```bash
   git clone https://github.com/YOUR-USERNAME/io.git
   cd io
   ```

3. **Add the Upstream Remote**:
   ```bash
   git remote add upstream https://github.com/kanopusdev/io.git
   ```

4. **Set Up Your Environment**:
   ```bash
   # Create a virtual environment
   python -m venv venv
   
   # Activate the virtual environment
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   
   # Install dependencies
   pip install -r requirements.txt
   
   # Install development dependencies
   pip install -r requirements-dev.txt
   ```

5. **Set Up Environment Variables**:
   ```bash
   # Copy the example environment file
   cp .env.example .env
   
   # Edit the .env file with your preferred settings
   ```

6. **Initialize the Database**:
   ```bash
   cd backend
   python app.py
   ```

### Understanding the Project Structure

Io URL Shortener follows a service-oriented architecture:

- **`backend/app.py`**: The main application entry point
- **`backend/app/`**: Core application code
  - **`models/`**: SQLAlchemy database models
  - **`routes/`**: API endpoints and route handlers
  - **`services/`**: Business logic layer
  - **`utils/`**: Helper functions and utilities
- **`frontend/`**: Static frontend files
- **`tests/`**: Test suite

Review the [ARCHITECTURE.md](ARCHITECTURE.md) file for a detailed understanding of the system design.

## Development Workflow

### Branching Strategy

We follow a simplified version of Git Flow:

- **`main`**: Production-ready code
- **`develop`**: Integration branch for feature work
- **`feature/{feature-name}`**: For new features
- **`bugfix/{bug-name}`**: For bug fixes
- **`hotfix/{hotfix-name}`**: For urgent fixes to production

Always branch off from `develop` for new work:

```bash
git checkout develop
git pull upstream develop
git checkout -b feature/your-feature-name
```

### Commit Messages

Write clear, concise commit messages following these guidelines:

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters
- Reference issues and pull requests after the first line

Example:
```
Add custom domain support for verified users

- Add domain validation service
- Update user model with custom domain field
- Add domain configuration endpoint

Fixes #123
```

### Pull Requests

1. **Update Your Branch**:
   ```bash
   git checkout develop
   git pull upstream develop
   git checkout feature/your-feature
   git rebase develop
   ```

2. **Push Your Changes**:
   ```bash
   git push origin feature/your-feature
   ```

3. **Create a Pull Request**:
   - Go to your fork on GitHub
   - Click "New Pull Request"
   - Select your feature branch and the `develop` branch of the main repository
   - Fill in the PR template with details about your changes

4. **Address Review Feedback**:
   - Make requested changes
   - Commit and push updates
   - Respond to reviewer comments

## Coding Standards

### Python Style Guide

We follow PEP 8 and use Black for code formatting:

- Use 4 spaces for indentation (not tabs)
- Maximum line length of 88 characters (Black default)
- Use docstrings for all public modules, functions, classes, and methods
- Run Black before committing:
  ```bash
  black backend/
  ```
- Run Flake8 to catch linting errors:
  ```bash
  flake8 backend/
  ```

### JavaScript Style Guide

For JavaScript code:

- Use 2 spaces for indentation
- Use camelCase for variable and function names
- Use PascalCase for class names
- Use ES6+ features when appropriate
- Format your code using Prettier:
  ```bash
  npx prettier --write frontend/assets/js/
  ```

### Documentation

- Document all public APIs, classes, and methods
- Use clear, concise language
- Update documentation when you change functionality
- Include examples where appropriate

## Testing

### Writing Tests

- Write tests for all new features and bug fixes
- Place tests in the `tests/` directory
- Follow the existing test structure
- Use descriptive test names that explain what is being tested
- Aim for high test coverage (>80%)

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
coverage run -m pytest
coverage report

# Run specific test file
pytest tests/test_specific_file.py

# Run tests with verbose output
pytest -v
```

## Bug Reports and Feature Requests

- Use the GitHub issue tracker to report bugs
- Search existing issues before creating a new one
- Include detailed steps to reproduce bugs
- For feature requests, describe the desired functionality and why it would be valuable
- Use issue templates when available

## Review Process

Pull requests are reviewed by maintainers based on:

- Code quality and adherence to style guidelines
- Test coverage
- Documentation quality
- Relevance to project goals

The review process typically takes 1-3 days. Be responsive to feedback to expedite the process.

## Community

- Follow us on [Twitter](https://twitter.com/kanopusdev) for updates
- Attend our monthly virtual meetups (announced on Discord)

Thank you for contributing to Io URL Shortener! Your efforts help make this project better for everyone.
