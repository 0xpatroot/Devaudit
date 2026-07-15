import os
import re
from typing import List
from devaudit.modules.base_check import BaseCheck, Severity, Finding

class DockerScanner(BaseCheck):
    name = "docker"
    description = "Checks Dockerfile configurations for security best practices"
    severity = Severity.MEDIUM
    reference = "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"

    def __init__(self):
        super().__init__()

    def scan_dockerfile(self, file_path: str) -> List[Finding]:
        findings = []
        if not os.path.exists(file_path):
            return findings

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            has_user_directive = False

            for line_idx, line in enumerate(lines, 1):
                line_stripped = line.strip()
                if not line_stripped or line_stripped.startswith("#"):
                    continue

                if line_stripped.upper().startswith("USER "):
                    has_user_directive = True

                if line_stripped.upper().startswith("FROM "):

                    parts = line_stripped.split()
                    if len(parts) >= 2:
                        image = parts[1]
                        if ":" not in image:
                            findings.append(Finding(
                                check_name="docker-base-no-tag",
                                severity=Severity.LOW,
                                description=f"Base image '{image}' has no version tag specified (defaults to latest, risking unexpected updates).",
                                file_path=os.path.relpath(file_path),
                                line_number=line_idx,
                                content=line_stripped,
                                reference="https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#from"
                            ))
                        elif image.endswith(":latest"):
                            findings.append(Finding(
                                check_name="docker-base-latest-tag",
                                severity=Severity.LOW,
                                description="Base image is using mutable ':latest' tag, which compromises build reproducibility and auditability.",
                                file_path=os.path.relpath(file_path),
                                line_number=line_idx,
                                content=line_stripped,
                                reference="https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#from"
                            ))

                if line_stripped.upper().startswith("ADD "):

                    findings.append(Finding(
                        check_name="docker-add-directive",
                        severity=Severity.INFO,
                        description="ADD instruction used instead of COPY. COPY is preferred as it is simpler and less prone to unexpected remote executions.",
                        file_path=os.path.relpath(file_path),
                        line_number=line_idx,
                        content=line_stripped,
                        reference="https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy"
                    ))

                if line_stripped.upper().startswith("ENV "):

                    match = re.search(r"(?:KEY|PASS|SECRET|TOKEN|PASSWORD|CREDENTIALS)\s*=\s*\S+", line_stripped, re.IGNORECASE)
                    if match:
                        findings.append(Finding(
                            check_name="docker-hardcoded-env-secret",
                            severity=Severity.HIGH,
                            description="Potential hardcoded secret or credential exposed in ENV directive.",
                            file_path=os.path.relpath(file_path),
                            line_number=line_idx,
                            content=line_stripped,
                            reference="https://docs.docker.com/engine/reference/builder/#env"
                        ))

            if not has_user_directive:
                findings.append(Finding(
                    check_name="docker-running-as-root",
                    severity=Severity.MEDIUM,
                    description="No USER instruction found. Container will run as root by default, increasing host vulnerability in case of container escape.",
                    file_path=os.path.relpath(file_path),
                    reference="https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user"
                ))

        except Exception:
            pass

        return findings

    def run(self, target: str) -> List[Finding]:
        findings = []
        if os.path.isfile(target):
            if os.path.basename(target).lower() == "dockerfile":
                findings.extend(self.scan_dockerfile(target))
        elif os.path.isdir(target):
            for root, dirs, files in os.walk(target):

                dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "venv", ".venv", "build", "dist"}]
                for file in files:
                    if file.lower() == "dockerfile" or file.lower().endswith(".dockerfile"):
                        full_path = os.path.join(root, file)
                        findings.extend(self.scan_dockerfile(full_path))
        return findings
