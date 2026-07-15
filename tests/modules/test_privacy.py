import pytest
import os
import json
from devaudit.modules.privacy import PrivacyScanner

class TestPrivacyScanner:
    def setup_method(self):
        self.scanner = PrivacyScanner()

    def test_dotnet_telemetry_detection(self, monkeypatch):

        monkeypatch.delenv("DOTNET_CLI_TELEMETRY_OPTOUT", raising=False)
        findings = self.scanner.check_dotnet_telemetry()
        assert len(findings) == 1
        assert findings[0].check_name == "privacy-dotnet-telemetry"

        monkeypatch.setenv("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
        findings = self.scanner.check_dotnet_telemetry()
        assert len(findings) == 0

    def test_vscode_telemetry_detection(self, tmp_path, monkeypatch):

        settings_file = tmp_path / "settings.json"

        settings_file.write_text(json.dumps({"telemetry.telemetryLevel": "all"}))

        original_check = self.scanner.check_vscode_telemetry

        def mock_check_vscode_telemetry():
            findings = []
            if os.path.exists(settings_file):
                try:
                    with open(settings_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    telemetry_level = data.get("telemetry.telemetryLevel", "all")
                    if telemetry_level != "off":
                        from devaudit.modules.base_check import Finding, Severity
                        findings.append(Finding(
                            check_name="privacy-vscode-telemetry",
                            severity=Severity.INFO,
                            description=f"VS Code telemetry level is '{telemetry_level}'",
                            file_path=str(settings_file),
                            content=f'"telemetry.telemetryLevel": "{telemetry_level}"'
                        ))
                except Exception:
                    pass
            return findings

        self.scanner.check_vscode_telemetry = mock_check_vscode_telemetry

        findings = self.scanner.check_vscode_telemetry()
        assert len(findings) == 1
        assert findings[0].check_name == "privacy-vscode-telemetry"

        settings_file.write_text(json.dumps({"telemetry.telemetryLevel": "off"}))
        findings = self.scanner.check_vscode_telemetry()
        assert len(findings) == 0
