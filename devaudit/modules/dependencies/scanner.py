import os
import json
import re
from typing import List, Dict, Tuple, Any
from devaudit.modules.base_check import BaseCheck, Severity, Finding

class DependencyScanner(BaseCheck):
    name = "dependencies"
    description = "Checks project dependencies for known security vulnerabilities (CVEs)"
    severity = Severity.HIGH
    reference = "https://osv.dev"

    def __init__(self):
        super().__init__()

        self.vuln_db = {}
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnerabilities.json")
        if os.path.exists(db_path):
            try:
                with open(db_path, "r", encoding="utf-8") as f:
                    self.vuln_db = json.load(f)
            except Exception:
                pass

    def parse_semver(self, version_str: str) -> Tuple[int, ...]:
        """Convert a semantic version string into a tuple of integers for comparison."""

        cleaned = re.sub(r"^[^\d]+", "", version_str).strip()

        digits_match = re.match(r"^(\d+(?:\.\d+)*)", cleaned)
        if not digits_match:
            return (0,)

        parts = digits_match.group(1).split(".")
        try:
            return tuple(int(x) for x in parts)
        except ValueError:
            return (0,)

    def is_vulnerable(self, current_ver: str, affected_range: str) -> bool:
        """Evaluate if the current version is vulnerable (e.g., current < affected)."""
        if affected_range.startswith("<="):
            affected_ver = affected_range[2:]
            return self.parse_semver(current_ver) <= self.parse_semver(affected_ver)
        elif affected_range.startswith("<"):
            affected_ver = affected_range[1:]
            return self.parse_semver(current_ver) < self.parse_semver(affected_ver)
        elif affected_range.startswith("=="):
            affected_ver = affected_range[2:]
            return self.parse_semver(current_ver) == self.parse_semver(affected_ver)
        return False

    def scan_package_json(self, file_path: str) -> List[Finding]:
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            dependencies = {}
            dependencies.update(data.get("dependencies", {}))
            dependencies.update(data.get("devDependencies", {}))

            npm_db = self.vuln_db.get("npm", {})

            for pkg, ver_spec in dependencies.items():
                if pkg in npm_db:

                    cleaned_ver = ver_spec.lstrip("^~>=< ")
                    for vuln in npm_db[pkg]:
                        if self.is_vulnerable(cleaned_ver, vuln["affected"]):
                            findings.append(Finding(
                                check_name=f"npm:{pkg}",
                                severity=Severity[vuln["severity"]],
                                description=f"{vuln['description']} ({pkg}@{ver_spec})",
                                file_path=os.path.relpath(file_path),
                                content=f'"{pkg}": "{ver_spec}"',
                                reference=vuln["reference"],
                                fixable=True,
                                fix_payload={
                                    "ecosystem": "npm",
                                    "package": pkg,
                                    "current_version": ver_spec,
                                    "safe_version": vuln["safe_version"],
                                    "file_path": file_path
                                }
                            ))
        except Exception:
            pass
        return findings

    def scan_requirements_txt(self, file_path: str) -> List[Finding]:
        findings = []
        try:
            pypi_db = self.vuln_db.get("pypi", {})
            with open(file_path, "r", encoding="utf-8") as f:
                for line_idx, line in enumerate(f, 1):
                    line_stripped = line.strip()
                    if not line_stripped or line_stripped.startswith("#"):
                        continue

                    parts = re.split(r"==|>=|<=|>|<", line_stripped)
                    if len(parts) >= 2:
                        pkg = parts[0].strip().lower()
                        ver = parts[1].strip()

                        ver = ver.split("#")[0].strip()

                        if pkg in pypi_db:
                            for vuln in pypi_db[pkg]:
                                if self.is_vulnerable(ver, vuln["affected"]):
                                    findings.append(Finding(
                                        check_name=f"pypi:{pkg}",
                                        severity=Severity[vuln["severity"]],
                                        description=f"{vuln['description']} ({pkg}=={ver})",
                                        file_path=os.path.relpath(file_path),
                                        line_number=line_idx,
                                        content=line_stripped,
                                        reference=vuln["reference"],
                                        fixable=True,
                                        fix_payload={
                                            "ecosystem": "pypi",
                                            "package": pkg,
                                            "current_version": ver,
                                            "safe_version": vuln["safe_version"],
                                            "file_path": file_path,
                                            "line_number": line_idx
                                        }
                                    ))
        except Exception:
            pass
        return findings

    def scan_cargo_toml(self, file_path: str) -> List[Finding]:
        findings = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            deps_section = re.search(r"\[dependencies\](.*?)(?:\[|$)", content, re.DOTALL)
            if deps_section:
                lines = deps_section.group(1).splitlines()
                for line_idx, line in enumerate(lines, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    match = re.match(r'^([a-zA-Z0-9\-_]+)\s*=\s*["\']([^"\']+)["\']', line)
                    if match:
                        pkg = match.group(1)
                        ver = match.group(2)

                        pass
        except Exception:
            pass
        return findings

    def scan_file(self, file_path: str) -> List[Finding]:
        basename = os.path.basename(file_path)
        if basename == "package.json":
            return self.scan_package_json(file_path)
        elif basename == "requirements.txt":
            return self.scan_requirements_txt(file_path)
        elif basename == "Cargo.toml":
            return self.scan_cargo_toml(file_path)
        return []

    def run(self, target: str) -> List[Finding]:
        findings = []
        if os.path.isfile(target):
            findings.extend(self.scan_file(target))
        elif os.path.isdir(target):
            for root, _, files in os.walk(target):

                if any(x in root.split(os.sep) for x in [".git", "node_modules", "venv", ".venv", "build", "dist"]):
                    continue
                for file in files:
                    if file in ["package.json", "requirements.txt", "Cargo.toml"]:
                        full_path = os.path.join(root, file)
                        findings.extend(self.scan_file(full_path))
        return findings
