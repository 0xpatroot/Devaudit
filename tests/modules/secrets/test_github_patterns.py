import pytest
from devaudit.modules.secrets import SecretsScanner

class TestGitHubPatterns:

    def setup_method(self):
        self.scanner = SecretsScanner()

    def test_detects_github_pat(self, tmp_path):
        """GitHub PAT should be detected."""
        test_file = tmp_path / "config.py"
        token_val = "ghp_" + "R3alT0k3nThatShouldBeDetectedNow9999"
        test_file.write_text(f'TOKEN = "{token_val}"')

        findings = self.scanner.scan_file(str(test_file))

        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"
        assert findings[0].check_name == "GitHub Personal Access Token"

    def test_ignores_placeholder(self, tmp_path):
        """Placeholder tokens should NOT be flagged."""
        test_file = tmp_path / "README.md"
        test_file.write_text('Replace `ghp_your_token_here` with your actual token')

        findings = self.scanner.scan_file(str(test_file))

        assert len(findings) == 0
