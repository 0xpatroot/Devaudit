import os
import sys
import json
from typing import List
from devaudit.modules.base_check import BaseCheck, Severity, Finding

class PrivacyScanner(BaseCheck):
    name = "privacy"
    description = "Checks developer tools telemetry settings and scans active processes making network connections"
    severity = Severity.LOW
    reference = "https://www.eff.org/issues/privacy"

    def __init__(self):
        super().__init__()

    def check_vscode_telemetry(self) -> List[Finding]:
        findings = []

        settings_path = ""
        if sys.platform == "win32":
            settings_path = os.path.expandvars(r"%APPDATA%\Code\User\settings.json")
        elif sys.platform == "darwin":
            settings_path = os.path.expanduser("~/Library/Application Support/Code/User/settings.json")
        elif sys.platform == "linux":
            settings_path = os.path.expanduser("~/.config/Code/User/settings.json")

        if settings_path and os.path.exists(settings_path):
            try:
                with open(settings_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                telemetry_level = data.get("telemetry.telemetryLevel", "all")
                if telemetry_level != "off":
                    findings.append(Finding(
                        check_name="privacy-vscode-telemetry",
                        severity=Severity.INFO,
                        description=f"VS Code telemetry is enabled (Level: '{telemetry_level}'). Recommended: set 'telemetry.telemetryLevel' to 'off' in settings.json.",
                        file_path=settings_path,
                        content=f'"telemetry.telemetryLevel": "{telemetry_level}"',
                        reference="https://code.visualstudio.com/docs/getstarted/telemetry"
                    ))
            except Exception:
                pass
        return findings

    def check_dotnet_telemetry(self) -> List[Finding]:
        findings = []

        opt_out = os.environ.get("DOTNET_CLI_TELEMETRY_OPTOUT")
        if opt_out not in ("1", "true", "TRUE"):
            findings.append(Finding(
                check_name="privacy-dotnet-telemetry",
                severity=Severity.INFO,
                description="Dotnet CLI telemetry opt-out variable (DOTNET_CLI_TELEMETRY_OPTOUT) is not set. Dotnet will send usage metrics to Microsoft.",
                file_path="Environment Variables",
                content="DOTNET_CLI_TELEMETRY_OPTOUT is unset",
                reference="https://learn.microsoft.com/en-us/dotnet/core/tools/telemetry"
            ))
        return findings

    def check_npm_telemetry(self) -> List[Finding]:
        findings = []

        npmrc_path = os.path.expanduser("~/.npmrc")
        if sys.platform == "win32":

            npmrc_path = os.path.join(os.environ.get("USERPROFILE", ""), ".npmrc")

        if os.path.exists(npmrc_path):
            try:
                with open(npmrc_path, "r", encoding="utf-8") as f:
                    content = f.read()
                if "telemetry=true" in content or "send-metrics=true" in content:
                    findings.append(Finding(
                        check_name="privacy-npm-telemetry",
                        severity=Severity.INFO,
                        description="npm telemetry or metric sharing is enabled in .npmrc.",
                        file_path=npmrc_path,
                        content="telemetry=true",
                        reference="https://docs.npmjs.com/about-npm-bar-graphs"
                    ))
            except Exception:
                pass
        return findings

    def check_active_network_processes(self) -> List[Finding]:
        findings = []
        try:
            import psutil

            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    conns = proc.connections(kind='inet')
                    if conns:

                        for conn in conns:
                            if conn.status == 'ESTABLISHED' and conn.raddr:

                                if conn.raddr.ip in ("127.0.0.1", "::1", "localhost"):
                                    continue
                                findings.append(Finding(
                                    check_name="privacy-network-process",
                                    severity=Severity.INFO,
                                    description=f"Process '{proc.info['name']}' (PID: {proc.info['pid']}) has an active network connection to {conn.raddr.ip}:{conn.raddr.port}.",
                                    file_path=f"Process: {proc.info['name']}",
                                    content=f"ESTABLISHED connection to {conn.raddr.ip}:{conn.raddr.port}",
                                    reference="https://www.sans.org/white-papers/64/"
                                ))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            pass
        return findings

    def run(self, target: str) -> List[Finding]:
        findings = []
        findings.extend(self.check_vscode_telemetry())
        findings.extend(self.check_dotnet_telemetry())
        findings.extend(self.check_npm_telemetry())
        findings.extend(self.check_active_network_processes())
        return findings
