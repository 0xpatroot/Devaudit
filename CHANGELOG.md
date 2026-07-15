# Changelog 🛡️

All notable changes to the **DevAudit** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-07-15

### Added
- **Interactive Terminal UI**: Added rich colored console logging, progress bars, and severity categories.
- **Project Configuration**: Implemented `.devaudit.json` support to configure default exclusions, scanning modules, and languages.
- **Docker Scanner**: Added checks for `Dockerfile` configurations (non-root USER check, insecure latest tags, ENV secrets, ADD directives).
- **SARIF Format Support**: Enabled exporting findings to the standardized SARIF format (`devaudit report --format=sarif`) for GitHub Code Scanning integration.
- **Exit Codes**: Configured non-zero exit codes (exit with 1) when critical or high severity findings are discovered to support CI/CD break-on-failure steps.
- **Exclusion Filters**: Introduced `--exclude` CLI option and `exclude` list in `.devaudit.json`.
- **Severity Filters**: Added `--severity` flag to filter terminal output.
- **Interactive Welcomer**: Included a welcome banner when the tool is executed without arguments.
- **Secrets Audit**: Modular regex scanner for credentials, keys, and tokens (GitHub PATs, AWS Keys, Google API keys, etc.).
- **Dependency Audit**: Checks `package.json`, `requirements.txt`, and `Cargo.toml` dependencies against local security vulnerability JSON database.
- **System Audit**: Audits OS-level settings (firewall profiles, active server ports, SSH daemon credentials configuration, user context elevation).
- **Network & SSL Audit**: Inspects host SSL/TLS certificates (cipher strength, expiration time, handshake validation) and resolves target DNS parameters.
- **Privacy Audit**: Detects developer tools telemetry settings (VS Code, Dotnet, npm) and audits active network connections.
- **Automatic Remediation**: Added `devaudit fix` command to automatically update vulnerable dependencies in manifest files.
- **GitHub Actions Workflows**: Added complete automated continuous integration setup (`ci.yml`) for multi-version Python testing.
- **Translations**: Added full localization support for English and Arabic.
