# Contributing to DevAudit 🛡️

First off — **thank you for considering a contribution to DevAudit!** 🎉

Every contribution matters, whether it's fixing a typo, adding a new security pattern, writing a test, or translating the app into your language. This document will guide you through the process.

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Your First Contribution](#your-first-contribution)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Adding Security Patterns](#adding-security-patterns)
- [Translations](#translations)
- [Writing Tests](#writing-tests)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)

---

## 📜 Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). In short: **be respectful, inclusive, and kind to everyone**.

---

## 🤝 Ways to Contribute

There are many ways to contribute to DevAudit — no experience required!

### 🌟 No-Code Contributions (Perfect for Beginners!)

| Contribution | Time Needed | What to Do |
|---|---|---|
| 🐛 Report a bug | 5 minutes | [Open an issue](../../issues/new?template=bug_report.md) |
| 💡 Suggest a feature | 5 minutes | [Open an issue](../../issues/new?template=feature_request.md) |
| 📝 Fix a typo | 10 minutes | Edit the file directly on GitHub |
| 🌍 Add a translation | 30–60 minutes | [See Translations section](#translations) |
| ⭐ Star the repo | 10 seconds | Click the ⭐ button on GitHub |
| 📢 Share the project | 5 minutes | Tweet, blog, or tell a friend |

### 💻 Code Contributions

| Contribution | Difficulty | Label |
|---|---|---|
| Fix a documented bug | ⭐ Easy | `bug` + `good first issue` |
| Add a secret detection pattern | ⭐ Easy | `good first issue` |
| Write a unit test | ⭐⭐ Medium | `tests` |
| Add a new system security check | ⭐⭐ Medium | `enhancement` |
| Improve performance | ⭐⭐⭐ Hard | `performance` |
| Add a new module | ⭐⭐⭐ Hard | `enhancement` |

---

## 🚀 Your First Contribution

Never contributed to open source before? Here's a step-by-step guide:

### Option A: Fix Something Small (Easiest)

1. Browse our [issues](../../issues?q=label%3A"good+first+issue")
2. Find one that interests you
3. Comment: **"I'd like to work on this!"** — we'll assign it to you
4. Follow the [Development Setup](#development-setup) below
5. Make your change and open a Pull Request

### Option B: Add a Secret Detection Pattern (10 minutes)

This is the easiest code contribution:

1. Go to `devaudit/modules/secrets/patterns/`
2. Find the right category file (or create a new one)
3. Add your pattern:

```python
PatternDefinition(
    name="My New Token",
    pattern=r"mytoken_[A-Za-z0-9]{32}",
    severity=Severity.HIGH,
    description="Detects My Service API tokens",
    reference="https://docs.myservice.com/api/tokens",
    examples=[
        "mytoken_ABC123xyz789ABC123xyz789ABC123xy",  # match
    ],
    false_positives=[
        "mytoken_example_placeholder",  # known false positive
    ]
)
```

4. Run the tests: `pytest tests/modules/secrets/`
5. Open a PR!

### Option C: Add a Translation (No coding needed!)

See the [Translations](#translations) section below.

---

## 🛠️ Development Setup

### Prerequisites

- Python 3.9+ OR Node.js 18+ OR Rust 1.70+
- Git

### Setup

```bash
# 1. Fork the repository
#    Click the "Fork" button on GitHub

# 2. Clone your fork
git clone https://github.com/YOUR-GITHUB-USERNAME/devaudit.git
cd devaudit

# 3. Create a virtual environment (Python)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 4. Install dependencies
pip install -e ".[dev]"

# 5. Verify setup
devaudit --version
# Expected: DevAudit v1.x.x

# 6. Run the test suite
pytest tests/
# Expected: All tests pass ✅

# 7. Create your feature branch
git checkout -b feature/my-awesome-feature
```

---

## 📤 Pull Request Process

### Before Opening a PR

- [ ] My code follows the project's coding style (`black`, `ruff`)
- [ ] I've written tests for my changes
- [ ] All tests pass locally (`pytest tests/`)
- [ ] I've updated the documentation if needed
- [ ] I've added my name to [CONTRIBUTORS.md](CONTRIBUTORS.md)

### PR Title Format

Use conventional commits:
- `feat: add GitLab token detection pattern`
- `fix: resolve false positive in AWS key detection`
- `docs: improve Arabic translation`
- `test: add tests for system audit module`
- `chore: update dependencies`

### What Happens After You Open a PR?

1. ✅ Automated tests will run (usually 2–3 minutes)
2. 👀 A maintainer will review within **48 hours**
3. 💬 We may request small changes — this is normal and helpful!
4. 🎉 Once approved, your PR is merged and you're a DevAudit contributor!

---

## 🔍 Adding Security Patterns

The most common contribution is adding new secret detection patterns. Here's how:

### Pattern Anatomy

```python
PatternDefinition(
    # Short name for the pattern
    name="GitHub Personal Access Token (Classic)",
    
    # Regex that matches the secret
    # Tips:
    #   - Be specific to reduce false positives
    #   - Account for possible whitespace: \s*=\s*
    #   - Use named groups when helpful
    pattern=r"ghp_[A-Za-z0-9]{36}",
    
    # How dangerous is exposure?
    severity=Severity.CRITICAL,  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    
    # Human-readable explanation
    description="GitHub Personal Access Token gives full API access to user account",
    
    # Link to documentation about this secret type
    reference="https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github",
    
    # Real-format examples that SHOULD match (for testing)
    examples=[
        "GITHUB_TOKEN=ghp_ABCDefghIJKLmnopQRSTuvwxYZ0123456789",
        'token: "ghp_ABCDefghIJKLmnopQRSTuvwxYZ0123456789"',
    ],
    
    # Known false positives to NOT flag
    false_positives=[
        "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",  # placeholder
        "ghp_your_token_here",                       # documentation example
    ]
)
```

### Testing Your Pattern

```bash
# Create a test file
echo 'GITHUB_TOKEN=ghp_ABCDefghIJKLmnopQRSTuvwxYZ0123456789' > /tmp/test.txt

# Run scanner against it
devaudit secrets /tmp/test.txt

# Should detect the token ✅

# Make sure false positives are not flagged
echo 'token: ghp_your_token_here' > /tmp/fp_test.txt
devaudit secrets /tmp/fp_test.txt
# Should NOT flag this ✅
```

---

## 🌍 Translations

DevAudit supports multiple languages, and we need YOUR help!

### How to Add or Improve a Translation

1. Find your language file in `translations/`
   - If it doesn't exist, copy `translations/en.json` and rename it (e.g., `tr.json` for Turkish)

2. Translate each string:
```json
{
  "cli.scanning": "Scanning...",           ← English (do not change keys!)
  "cli.scanning": "جاري المسح...",         ← Arabic translation
  
  "cli.found_secrets": "Found {count} potential secret(s)",
  "cli.found_secrets": "تم العثور على {count} من المعلومات الحساسة",
  
  "cli.no_issues": "No issues found. Your project looks secure! ✅",
  "cli.no_issues": "لم يتم العثور على مشكلات. مشروعك يبدو آمنًا! ✅"
}
```

3. Open a PR with title: `i18n: add [Language Name] translation`

### Translation Progress

| Language | Status | Contributors Needed |
|---|---|---|
| 🇺🇸 English | ✅ Complete | — |
| 🇸🇦 Arabic | ✅ Complete | — |
| 🇫🇷 French | 🔄 60% | **Need help!** |
| 🇪🇸 Spanish | 🔄 40% | **Need help!** |
| 🇩🇪 German | 🔄 20% | **Need help!** |
| 🇮🇳 Hindi | ❌ Not started | **Need help!** |
| 🇵🇹 Portuguese | ❌ Not started | **Need help!** |
| 🇨🇳 Chinese (Simplified) | ❌ Not started | **Need help!** |
| 🇯🇵 Japanese | ❌ Not started | **Need help!** |
| 🇷🇺 Russian | ❌ Not started | **Need help!** |
| 🇹🇷 Turkish | ❌ Not started | **Need help!** |
| 🇮🇩 Indonesian | ❌ Not started | **Need help!** |

**Even 5–10 translated strings is a meaningful contribution! Every bit helps.**

---

## 🧪 Writing Tests

Tests help ensure DevAudit stays reliable. Here's how to write them:

```python
# tests/modules/secrets/test_github_patterns.py

import pytest
from devaudit.modules.secrets import SecretsScanner

class TestGitHubPatterns:
    
    def setup_method(self):
        self.scanner = SecretsScanner()
    
    def test_detects_github_pat(self, tmp_path):
        """GitHub PAT should be detected."""
        test_file = tmp_path / "config.py"
        test_file.write_text('TOKEN = "ghp_ABCDefghIJKLmnopQRSTuvwxYZ0123456789"')
        
        findings = self.scanner.scan_file(test_file)
        
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"
        assert findings[0].pattern_name == "GitHub Personal Access Token"
    
    def test_ignores_placeholder(self, tmp_path):
        """Placeholder tokens should NOT be flagged."""
        test_file = tmp_path / "README.md"
        test_file.write_text('Replace `ghp_your_token_here` with your actual token')
        
        findings = self.scanner.scan_file(test_file)
        
        assert len(findings) == 0
```

---

## 🐛 Reporting Bugs

Found a bug? Please open an issue with:

1. **DevAudit version**: `devaudit --version`
2. **Operating System**: e.g., Ubuntu 22.04, macOS 14, Windows 11
3. **What you ran**: The exact command
4. **Expected behavior**: What should have happened
5. **Actual behavior**: What actually happened
6. **Logs**: Output from `devaudit --debug [your command]`

Use our [bug report template](../../issues/new?template=bug_report.md) for easiest submission.

---

## 💡 Suggesting Features

Have an idea? We'd love to hear it!

Before suggesting, please:
1. Search [existing issues](../../issues) to avoid duplicates
2. Check the [roadmap](README.md#roadmap) to see if it's planned

When suggesting, describe:
- **The problem** you're trying to solve
- **Your proposed solution**
- **Why** this would be valuable to others

Use our [feature request template](../../issues/new?template=feature_request.md).

---

## 🏆 Recognition

Every contributor is recognized in:

- **[CONTRIBUTORS.md](CONTRIBUTORS.md)** — All-contributors list
- **Release notes** — PRs are credited in each release
- **README** — Top contributors highlighted
- **Social media** — We celebrate milestones and contributors publicly

---

## ❓ Questions?

If you have any questions that aren't covered here:

- 💬 Open a [Discussion](../../discussions)
- 📧 Email: `contributors@devaudit-project.org`

We aim to respond within **24 hours**.

---

**Thank you for making DevAudit better for everyone! 🛡️**
