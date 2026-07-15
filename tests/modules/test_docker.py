import pytest
from devaudit.modules.docker import DockerScanner

class TestDockerScanner:
    def setup_method(self):
        self.scanner = DockerScanner()

    def test_detects_root_running_and_no_tag(self, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM ubuntu\nRUN apt-get update\n")

        findings = self.scanner.scan_dockerfile(str(dockerfile))

        assert len(findings) == 2
        checks = [f.check_name for f in findings]
        assert "docker-running-as-root" in checks
        assert "docker-base-no-tag" in checks

    def test_detects_latest_tag_and_add_directive(self, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM node:latest\nADD archive.tar.gz /app/\nUSER node\n")

        findings = self.scanner.scan_dockerfile(str(dockerfile))
        assert len(findings) == 2
        checks = [f.check_name for f in findings]
        assert "docker-base-latest-tag" in checks
        assert "docker-add-directive" in checks

        assert "docker-running-as-root" not in checks

    def test_detects_hardcoded_env_secret(self, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine:3.18\nENV API_KEY=supersecret123\nUSER alpine\n")

        findings = self.scanner.scan_dockerfile(str(dockerfile))
        assert len(findings) == 1
        assert findings[0].check_name == "docker-hardcoded-env-secret"
        assert findings[0].severity.value == "HIGH"
