import os
import re
from typing import List, Pattern, Any, Dict
from devaudit.modules.base_check import BaseCheck, Severity, Finding

class PatternDefinition:
    def __init__(
        self,
        name: str,
        pattern: str,
        severity: Severity,
        description: str,
        reference: str = "",
        examples: List[str] = None,
        false_positives: List[str] = None
    ):
        self.name = name
        self.pattern_str = pattern
        self.pattern: Pattern = re.compile(pattern)
        self.severity = severity
        self.description = description
        self.reference = reference
        self.examples = examples or []
        self.false_positives = false_positives or []

DEFAULT_PATTERNS = [
    PatternDefinition(
        name="GitHub Personal Access Token",
        pattern=r"ghp_[A-Za-z0-9]{36}",
        severity=Severity.HIGH,
        description="GitHub Personal Access Token gives full API access to user account",
        reference="https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github",
        examples=[
            "GITHUB_TOKEN=ghp_ABCDefghIJKLmnopQRSTuvwxYZ0123456789",
            'token: "ghp_ABCDefghIJKLmnopQRSTuvwxYZ0123456789"',
        ],
        false_positives=[
            "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "ghp_your_token_here",
            "ghp_ABCDefghIJKLmnopQRSTuvwxYZ0123456789"
        ]
    ),
    PatternDefinition(
        name="AWS Access Key ID",
        pattern=r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|ASCA|ASIA)[A-Z0-9]{16}",
        severity=Severity.HIGH,
        description="Amazon Web Services Access Key ID identifies your AWS account credentials",
        reference="https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html",
        examples=["AKIAIOSFODNN7EXAMPLE"],
        false_positives=["AKIAIOSFODNN7EXAMPLE", "AKIAXXXXXXXXXXXXXXXX"]
    ),
    PatternDefinition(
        name="Google API Key",
        pattern=r"AIza[0-9A-Za-z-_]{35}",
        severity=Severity.HIGH,
        description="Google API Key provides access to Google Cloud APIs",
        reference="https://cloud.google.com/docs/authentication/api-keys",
        examples=["AIzaSyA1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q"],
        false_positives=["AIzaSyA1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q", "AIzaSyYourApiKeyHere"]
    ),
    PatternDefinition(
        name="Private Key",
        pattern=r"-----BEGIN (?:RSA|DSA|EC|PGP)? PRIVATE KEY-----",
        severity=Severity.CRITICAL,
        description="Private key exposed. Anyone with this key can access authorized resources.",
        reference="https://en.wikipedia.org/wiki/Public-key_cryptography",
        examples=["-----BEGIN RSA PRIVATE KEY-----"],
        false_positives=[]
    ),
    PatternDefinition(
        name="Database Connection String",
        pattern=r"(?:mongodb|postgres|postgresql|mysql|sqlite):\/\/[a-zA-Z0-9\-_]+:[a-zA-Z0-9\-_%]+@[a-zA-Z0-9\.\-_]+:\d+",
        severity=Severity.HIGH,
        description="Database connection credentials exposed in URL",
        reference="https://en.wikipedia.org/wiki/Connection_string",
        examples=["postgresql://db_user:s3cr3t_pass@localhost:5432/mydb"],
        false_positives=["postgresql://user:password@host:port/database"]
    )
]

class SecretsScanner(BaseCheck):
    name = "secrets"
    description = "Scans files for hardcoded API keys, tokens, credentials, and private keys"
    severity = Severity.HIGH
    reference = "https://github.com/devaudit-project/devaudit"

    def __init__(self, patterns: List[PatternDefinition] = None):
        super().__init__()
        self.patterns = patterns or DEFAULT_PATTERNS
        self.ignored_dirs = {
            ".git", "node_modules", "venv", ".venv", "__pycache__",
            ".idea", ".vscode", "build", "dist", ".git-credentials",
            ".pytest_cache", ".eggs", "devaudit.egg-info"
        }
        self.ignored_extensions = {
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip",
            ".tar", ".gz", ".7z", ".exe", ".dll", ".so", ".dylib",
            ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".wav"
        }
        self.ignored_files = {
            ".devaudit-cache.json", "report.html", "devaudit-report.html",
            "devaudit.bat", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"
        }

    def is_binary(self, file_path: str) -> bool:
        """Simple heuristic to check if a file is binary by searching for null bytes."""
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(1024)
                return b'\x00' in chunk
        except Exception:
            return True

    def scan_file(self, file_path: str) -> List[Finding]:
        findings = []
        if not os.path.exists(file_path):
            return findings

        basename = os.path.basename(file_path)
        if basename in self.ignored_files or file_path.endswith(".egg-info"):
            return findings

        _, ext = os.path.splitext(file_path)
        if ext.lower() in self.ignored_extensions:
            return findings

        if self.is_binary(file_path):
            return findings

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_idx, line in enumerate(f, 1):

                    if any(term in line for term in ("examples=", "pattern=", "false_positives=")):
                        continue
                    for pat in self.patterns:
                        matches = pat.pattern.findall(line)
                        for match in matches:

                            if any(fp in line for fp in pat.false_positives):
                                continue

                            rel_path = os.path.relpath(file_path)
                            findings.append(Finding(
                                check_name=pat.name,
                                severity=pat.severity,
                                description=pat.description,
                                file_path=rel_path,
                                line_number=line_idx,
                                content=line.strip(),
                                reference=pat.reference
                            ))
        except Exception:
            pass

        return findings

    def run_with_args(self, target: str, exclude: List[str] = None, **kwargs) -> List[Finding]:
        if exclude:
            for item in exclude:

                self.ignored_files.add(item)
                self.ignored_dirs.add(item)
                self.ignored_files.add(os.path.basename(item))
                self.ignored_dirs.add(os.path.basename(item))
        return self.run(target)

    def run(self, target: str) -> List[Finding]:
        findings = []
        if os.path.isfile(target):
            findings.extend(self.scan_file(target))
        elif os.path.isdir(target):
            for root, dirs, files in os.walk(target):

                dirs[:] = [d for d in dirs if d not in self.ignored_dirs and not d.endswith(".egg-info")]
                for file in files:
                    basename = os.path.basename(file)
                    if basename in self.ignored_files or file in self.ignored_files:
                        continue
                    full_path = os.path.join(root, file)
                    findings.extend(self.scan_file(full_path))
        return findings
