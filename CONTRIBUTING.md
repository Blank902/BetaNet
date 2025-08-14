# Contributing to BetaNet C Library

Thank you for your interest in contributing to the BetaNet C Library! This document provides guidelines for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Testing](#testing)
- [Documentation](#documentation)
- [Security](#security)
- [Code Style](#code-style)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

## Code of Conduct

This project follows a standard code of conduct. Please be respectful, inclusive, and constructive in all interactions.

## Getting Started

### Prerequisites

- CMake 3.15 or higher
- C11-compatible compiler (GCC 7+, Clang 6+, MSVC 2019+)
- OpenSSL or mbedTLS
- Git

### Development Setup

1. **Fork and clone the repository**

   ```bash
   git clone https://github.com/yourusername/BetaNet.git
   cd BetaNet
   ```

2. **Build the project**

   ```bash
   cmake -B build -DCMAKE_BUILD_TYPE=Debug
   cmake --build build
   ```

3. **Run tests**

   ```bash
   cd build
   ctest --output-on-failure
   ```

4. **Verify your setup**

   ```bash
   ./build/cli/bnetc-cli/bnetc-cli --help
   ```

## Contributing Guidelines

### Types of Contributions

We welcome several types of contributions:

- **Bug fixes**: Fix issues in the codebase
- **Feature additions**: Implement new functionality
- **Documentation improvements**: Enhance docs, comments, examples
- **Performance optimizations**: Make the code faster or more efficient
- **Security improvements**: Address security vulnerabilities
- **Test coverage**: Add or improve tests

### Before You Start

1. **Check existing issues**: Look for existing issues or discussions
2. **Create an issue**: For significant changes, create an issue first to discuss
3. **Follow BetaNet specification**: Ensure compliance with the [BetaNet specification](README.md)
4. **Consider security impact**: Be mindful of cryptographic and security implications

## Development Workflow

### Branch Strategy

- `main`: Stable release branch
- `develop`: Active development branch
- `feature/name`: Feature development branches
- `fix/name`: Bug fix branches
- `security/name`: Security fix branches (for non-critical issues)

### Commit Guidelines

- Use clear, descriptive commit messages
- Reference issue numbers when applicable
- Keep commits focused and atomic
- Sign your commits if possible

Example:

```text
feat: implement adaptive HTTP/2 shaping

- Add origin-mirrored SETTINGS frame handling
- Implement PING cadence randomization
- Add regression tests for fingerprint conformity

Fixes #123
```

### Commit Message Format

```text
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Test additions/modifications
- `security`: Security-related changes
- `build`: Build system changes
- `ci`: CI/CD changes

## Testing

### Test Categories

1. **Unit Tests** (`tests/unit/`): Test individual functions and modules
2. **Integration Tests** (`tests/integration/`): Test component interactions
3. **Interop Tests** (`tests/interop/`): Test protocol compliance
4. **Performance Tests** (`tests/performance/`): Benchmark critical paths
5. **Fuzz Tests**: Test parser robustness

### Running Tests

```bash
# All tests
cd build && ctest

# Specific test category
./build/tests/unit/protocol_regression_test
./build/tests/integration/end_to_end_test

# With sanitizers
cmake -B build-asan -DCMAKE_C_FLAGS="-fsanitize=address,undefined"
cmake --build build-asan
cd build-asan && ctest
```

### Writing Tests

- Add tests for all new functionality
- Include both positive and negative test cases
- Test edge cases and error conditions
- Use descriptive test names
- Add regression tests for bug fixes

## Documentation

### Documentation Requirements

- **API Documentation**: Document all public functions with Doxygen
- **Architecture Changes**: Update `technical-overview.md`
- **Security Implications**: Update `SECURITY_NOTES.md`
- **User Guide Changes**: Update `README.md` and `DEVELOPER_GUIDE.md`

### Documentation Style

- Use clear, concise language
- Include code examples where helpful
- Document security considerations
- Keep documentation up-to-date with code changes

### Generating Documentation

```bash
# Install Doxygen
sudo apt-get install doxygen graphviz  # Ubuntu
brew install doxygen graphviz          # macOS

# Generate documentation
doxygen Doxyfile

# View documentation
open docs/html/index.html
```

## Security

### Security-First Development

- **Threat Modeling**: Consider attack vectors for your changes
- **Cryptographic Code**: Follow established patterns, avoid custom crypto
- **Input Validation**: Validate all inputs, especially from network
- **Memory Safety**: Use safe memory management practices
- **Side-Channel Resistance**: Be aware of timing attacks

### Security Review Process

1. **Self-Review**: Check your own code for security issues
2. **Automated Scanning**: Ensure CI security checks pass
3. **Peer Review**: Get security-focused code review
4. **Fuzzing**: Test parsers and input handling with fuzz testing

### Reporting Security Issues

For security vulnerabilities:

1. **Critical Issues**: Email maintainers privately
2. **Non-Critical Issues**: Use the security issue template
3. **Follow Responsible Disclosure**: Work with maintainers on timeline

## Code Style

### C Code Style

- **Standard**: C11 with POSIX extensions where needed
- **Formatting**: 4-space indentation, no tabs
- **Naming**: `snake_case` for functions and variables
- **Constants**: `UPPER_CASE` for macros and constants
- **Line Length**: 80 characters (flexible for readability)

### Code Quality

- **Compiler Warnings**: Code must compile without warnings
- **Static Analysis**: Must pass clang-tidy and cppcheck
- **Memory Safety**: Use AddressSanitizer and Valgrind clean code
- **Error Handling**: Always check return values and handle errors

### Example Code Style

```c
/**
 * @brief Validates and processes an HTX access ticket
 * 
 * @param ticket Pointer to the ticket buffer
 * @param ticket_len Length of the ticket in bytes
 * @param context Processing context
 * @return BETANET_SUCCESS on success, error code on failure
 */
betanet_result_t betanet_process_ticket(
    const uint8_t *ticket,
    size_t ticket_len,
    betanet_context_t *context)
{
    if (!ticket || !context || ticket_len < BETANET_MIN_TICKET_SIZE) {
        return BETANET_ERROR_INVALID_ARGUMENT;
    }

    // Implementation...
    return BETANET_SUCCESS;
}
```

## Pull Request Process

### Before Submitting

1. **Rebase**: Rebase your branch on latest main/develop
2. **Self-Review**: Review your own changes thoroughly
3. **Tests Pass**: Ensure all tests pass locally
4. **Documentation**: Update relevant documentation
5. **Commit Message**: Use clear, descriptive commit messages

### PR Requirements

- [ ] **Builds Successfully**: All platforms and configurations
- [ ] **Tests Pass**: Unit, integration, and regression tests
- [ ] **Documentation Updated**: For API or behavior changes
- [ ] **Security Review**: For security-sensitive changes
- [ ] **Backwards Compatibility**: Or clear migration path
- [ ] **Performance**: No significant regressions

### Review Process

1. **Automated Checks**: CI must pass
2. **Code Review**: At least one maintainer approval
3. **Security Review**: For security-sensitive changes
4. **Final Check**: Maintainer verifies and merges

### After Merge

- Delete your feature branch
- Update your local repository
- Consider contributing to documentation or tests

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Incompatible API changes or protocol changes
- **MINOR**: Backwards-compatible functionality additions
- **PATCH**: Backwards-compatible bug fixes

### Release Checklist

1. **Version Bump**: Update version numbers
2. **Changelog**: Update CHANGELOG.md
3. **Documentation**: Ensure docs are current
4. **Testing**: Full test suite including security tests
5. **Build Artifacts**: Generate reproducible release builds
6. **SLSA Provenance**: Generate supply chain attestations

## Getting Help

### Communication Channels

- **Issues**: For bugs, features, and questions
- **Discussions**: For design discussions and help
- **Security**: Private email for security issues

### Resources

- [BetaNet Specification](README.md)
- [Technical Overview](technical-overview.md)
- [Developer Guide](DEVELOPER_GUIDE.md)
- [Security Notes](SECURITY_NOTES.md)

## Recognition

Contributors will be acknowledged in:

- Git commit history
- CONTRIBUTORS.md file
- Release notes for significant contributions

Thank you for contributing to BetaNet!
