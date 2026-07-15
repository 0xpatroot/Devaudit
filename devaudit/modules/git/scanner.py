import os
import subprocess
import re
from typing import List
from devaudit.modules.base_check import BaseCheck, Severity, Finding
from devaudit.modules.secrets.scanner import DEFAULT_PATTERNS

class GitScanner(BaseCheck):
    name = "git"
    description = "Scans git history for credentials, secrets, or certificates that were pushed in past commits"
    severity = Severity.HIGH
    reference = "https://github.com/trufflesecurity/trufflehog"

    def __init__(self):
        super().__init__()
        self.patterns = DEFAULT_PATTERNS

    def is_git_repo(self, target: str) -> bool:

        if not os.path.isdir(target):
            return False
        try:
            output = subprocess.check_output(
                "git rev-parse --is-inside-work-tree",
                cwd=target,
                shell=True,
                stderr=subprocess.DEVNULL
            ).decode("utf-8").strip()
            return output == "true"
        except Exception:
            return os.path.exists(os.path.join(target, ".git"))

    def run_with_args(self, target: str, depth: int = 100, **kwargs) -> List[Finding]:
        findings = []
        if not self.is_git_repo(target):

            return findings

        try:

            cmd = f"git log -p -n {depth} --raw"
            output = subprocess.check_output(
                cmd,
                cwd=target,
                shell=True,
                stderr=subprocess.DEVNULL
            ).decode("utf-8", errors="ignore")

            current_commit = "unknown"
            current_author = "unknown"
            current_date = "unknown"
            current_file = "unknown"

            lines = output.splitlines()
            for line in lines:

                if line.startswith("commit "):
                    current_commit = line.split(" ")[1][:8]
                elif line.startswith("Author: "):
                    current_author = line[8:].strip()
                elif line.startswith("Date:   "):
                    current_date = line[8:].strip()
                elif line.startswith("diff --git "):

                    parts = line.split(" ")
                    if len(parts) >= 3:
                        current_file = parts[2][2:]
                elif line.startswith("+") and not line.startswith("+++ "):
                    added_content = line[1:].strip()

                    if any(term in added_content for term in ("examples=", "pattern=", "false_positives=")):
                        continue

                    for pat in self.patterns:
                        matches = pat.pattern.findall(added_content)
                        for match in matches:
                            if any(fp in added_content for fp in pat.false_positives):
                                continue

                            findings.append(Finding(
                                check_name=f"git-history:{pat.name}",
                                severity=pat.severity,
                                description=f"Credential exposure found in commit {current_commit} by {current_author} on {current_date}: {pat.description}",
                                file_path=current_file,
                                content=f"[{current_commit}] + {added_content}",
                                reference=pat.reference
                            ))
        except Exception:
            pass

        return findings

    def run(self, target: str) -> List[Finding]:
        return self.run_with_args(target, depth=100)
