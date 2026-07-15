import pytest
import os
import json
from devaudit.modules.dependencies import DependencyScanner

class TestDependencyScanner:
    def setup_method(self):
        self.scanner = DependencyScanner()

    def test_parse_semver(self):
        assert self.scanner.parse_semver("4.17.21") == (4, 17, 21)
        assert self.scanner.parse_semver("^4.17.21") == (4, 17, 21)
        assert self.scanner.parse_semver("==4.17.21") == (4, 17, 21)
        assert self.scanner.parse_semver("4.17.21-beta.1") == (4, 17, 21)

    def test_is_vulnerable(self):

        assert self.scanner.is_vulnerable("4.17.15", "<4.17.21") is True

        assert self.scanner.is_vulnerable("4.17.21", "<4.17.21") is False

        assert self.scanner.is_vulnerable("4.17.21", "<=4.17.21") is True
        assert self.scanner.is_vulnerable("4.17.22", "<=4.17.21") is False

        assert self.scanner.is_vulnerable("4.17.21", "==4.17.21") is True
        assert self.scanner.is_vulnerable("4.17.22", "==4.17.21") is False

    def test_scan_package_json(self, tmp_path):
        pkg_json = tmp_path / "package.json"
        content = {
            "dependencies": {
                "lodash": "^4.17.15"
            }
        }
        pkg_json.write_text(json.dumps(content))

        findings = self.scanner.scan_package_json(str(pkg_json))
        assert len(findings) == 1
        assert findings[0].check_name == "npm:lodash"
        assert findings[0].severity.value == "HIGH"
        assert findings[0].fixable is True
        assert findings[0].fix_payload["safe_version"] == "4.17.21"

    def test_scan_requirements_txt(self, tmp_path):
        req_txt = tmp_path / "requirements.txt"
        req_txt.write_text("requests==2.28.1\nurllib3==1.26.15\n")

        findings = self.scanner.scan_requirements_txt(str(req_txt))

        assert len(findings) == 2
        names = [f.check_name for f in findings]
        assert "pypi:requests" in names
        assert "pypi:urllib3" in names
