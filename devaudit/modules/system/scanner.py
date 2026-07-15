import os
import sys
import socket
import subprocess
from typing import List
from devaudit.modules.base_check import BaseCheck, Severity, Finding

class SystemScanner(BaseCheck):
    name = "system"
    description = "Checks system configurations (firewall, open ports, SSH, encryption) for security issues"
    severity = Severity.MEDIUM
    reference = "https://github.com/CISOfy/lynis"

    def __init__(self):
        super().__init__()

        self.dangerous_ports = {
            21: "FTP (unencrypted file transfer)",
            23: "Telnet (unencrypted remote access)",
            3306: "MySQL (database service)",
            5432: "PostgreSQL (database service)",
            27017: "MongoDB (NoSQL database service)",
            6379: "Redis (in-memory data store)",
            1433: "Microsoft SQL Server",
            1521: "Oracle Database",
            8080: "Alternative HTTP (often dev servers)"
        }

    def check_open_ports(self) -> List[Finding]:
        findings = []
        try:
            import psutil
            connections = psutil.net_connections(kind="inet")
            for conn in connections:

                if conn.status == "LISTEN":
                    port = conn.laddr.port
                    ip = conn.laddr.ip

                    if ip in ("0.0.0.0", "::") and port in self.dangerous_ports:
                        findings.append(Finding(
                            check_name="system-open-port",
                            severity=Severity.HIGH,
                            description=f"Port {port} ({self.dangerous_ports[port]}) is open to all interfaces (risk: external database/service exposure)",
                            file_path="System Network Configuration",
                            content=f"Listening on {ip}:{port}",
                            reference="https://www.cisa.gov/resources-tools/programs/free-common-vulnerability-scanners"
                        ))
        except Exception:

            for port in self.dangerous_ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.1)

                    result = s.connect_ex(("127.0.0.1", port))
                    if result == 0:
                        findings.append(Finding(
                            check_name="system-open-port-fallback",
                            severity=Severity.MEDIUM,
                            description=f"Port {port} ({self.dangerous_ports[port]}) appears to be active and listening locally.",
                            file_path="System Network Configuration",
                            content=f"Local active port: {port}",
                            reference="https://www.cisa.gov/resources-tools/programs/free-common-vulnerability-scanners"
                        ))
                    s.close()
                except Exception:
                    pass
        return findings

    def check_firewall(self) -> List[Finding]:
        findings = []
        try:
            if sys.platform == "win32":

                output = subprocess.check_output(
                    "netsh advfirewall show allprofiles state",
                    shell=True,
                    stderr=subprocess.DEVNULL
                ).decode("utf-8", errors="ignore")

                if "State" in output and "OFF" in output:
                    findings.append(Finding(
                        check_name="system-firewall-windows",
                        severity=Severity.HIGH,
                        description="One or more Windows Firewall profiles are disabled.",
                        file_path="Windows Firewall",
                        content="State: OFF",
                        reference="https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/windows-firewall-with-advanced-security"
                    ))
            elif sys.platform == "linux":

                try:
                    output = subprocess.check_output(
                        "ufw status",
                        shell=True,
                        stderr=subprocess.DEVNULL
                    ).decode("utf-8", errors="ignore")
                    if "inactive" in output:
                        findings.append(Finding(
                            check_name="system-firewall-linux",
                            severity=Severity.HIGH,
                            description="Uncomplicated Firewall (UFW) is inactive on this Linux host.",
                            file_path="Linux UFW",
                            content="Status: inactive",
                            reference="https://help.ubuntu.com/community/UFW"
                        ))
                except Exception:
                    pass
            elif sys.platform == "darwin":

                try:
                    output = subprocess.check_output(
                        "/usr/libexec/ApplicationFirewall/socketfilterfw --getstate",
                        shell=True,
                        stderr=subprocess.DEVNULL
                    ).decode("utf-8", errors="ignore")
                    if "disabled" in output.lower():
                        findings.append(Finding(
                            check_name="system-firewall-macos",
                            severity=Severity.HIGH,
                            description="macOS Application Firewall is disabled.",
                            file_path="macOS Firewall",
                            content="Firewall is disabled",
                            reference="https://support.apple.com/en-us/HT201642"
                        ))
                except Exception:
                    pass
        except Exception:
            pass
        return findings

    def check_ssh_config(self) -> List[Finding]:
        findings = []
        if sys.platform in ("linux", "darwin"):
            ssh_config_path = "/etc/ssh/sshd_config"
            if os.path.exists(ssh_config_path):
                try:
                    with open(ssh_config_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    root_login = re.search(r"^\s*PermitRootLogin\s+(yes|prohibit-password)", content, re.MULTILINE | re.IGNORECASE)
                    if root_login and root_login.group(1).lower() == "yes":
                        findings.append(Finding(
                            check_name="system-ssh-root-login",
                            severity=Severity.HIGH,
                            description="SSH daemon config allows Root Login. This exposes the system to automated credential attacks.",
                            file_path=ssh_config_path,
                            content="PermitRootLogin yes",
                            reference="https://www.openssh.com/manual.html"
                        ))

                    passwd_auth = re.search(r"^\s*PasswordAuthentication\s+yes", content, re.MULTILINE | re.IGNORECASE)
                    if passwd_auth:
                        findings.append(Finding(
                            check_name="system-ssh-password-authentication",
                            severity=Severity.MEDIUM,
                            description="SSH Password Authentication is enabled. It is safer to enforce public key authentication.",
                            file_path=ssh_config_path,
                            content="PasswordAuthentication yes",
                            reference="https://www.openssh.com/manual.html"
                        ))
                except Exception:
                    pass
        elif sys.platform == "win32":

            try:
                output = subprocess.check_output(
                    "powershell -Command \"Get-Service sshd -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status\"",
                    shell=True,
                    stderr=subprocess.DEVNULL
                ).decode("utf-8", errors="ignore").strip()

                if output == "Running":

                    win_ssh_config = r"C:\ProgramData\ssh\sshd_config"
                    if os.path.exists(win_ssh_config):
                        with open(win_ssh_config, "r", encoding="utf-8", errors="ignore") as f:
                            config_content = f.read()
                        if "PasswordAuthentication yes" in config_content or "PasswordAuthentication" not in config_content:
                            findings.append(Finding(
                                check_name="system-ssh-password-authentication-windows",
                                severity=Severity.MEDIUM,
                                description="Windows OpenSSH Server service is active and PasswordAuthentication is enabled (or defaulted to yes).",
                                file_path=win_ssh_config,
                                content="PasswordAuthentication yes (active service)",
                                reference="https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_server_configuration"
                            ))
            except Exception:
                pass
        return findings

    def check_user_privilege(self) -> List[Finding]:
        findings = []
        try:
            if sys.platform == "win32":
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                if is_admin:
                    findings.append(Finding(
                        check_name="system-running-as-admin",
                        severity=Severity.INFO,
                        description="CLI tool is running with Administrator privileges. Ensure dev scripts are executed with appropriate low-privilege accounts unless required.",
                        file_path="User Context Check",
                        content="User: Administrator / Elevated",
                        reference="https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-overview"
                    ))
            else:
                if os.geteuid() == 0:
                    findings.append(Finding(
                        check_name="system-running-as-root",
                        severity=Severity.INFO,
                        description="CLI tool is running as root (UID 0). Developers should run commands without elevated privileges unless installing software.",
                        file_path="User Context Check",
                        content="User: Root (UID 0)",
                        reference="https://en.wikipedia.org/wiki/Least_privilege"
                    ))
        except Exception:
            pass
        return findings

    def check_disk_encryption(self) -> List[Finding]:
        findings = []
        try:
            if sys.platform == "win32":

                output = subprocess.check_output(
                    "manage-bde -status C:",
                    shell=True,
                    stderr=subprocess.DEVNULL
                ).decode("utf-8", errors="ignore")

                if "Fully Decrypted" in output or "Protection Off" in output:
                    findings.append(Finding(
                        check_name="system-disk-encryption-windows",
                        severity=Severity.HIGH,
                        description="Drive C: is not encrypted with BitLocker. Physical access can compromise codebases and credentials.",
                        file_path="C: Drive Encryption",
                        content="BitLocker Status: Protection Off or Decrypted",
                        reference="https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-overview"
                    ))
            elif sys.platform == "darwin":

                output = subprocess.check_output(
                    "fdesetup status",
                    shell=True,
                    stderr=subprocess.DEVNULL
                ).decode("utf-8", errors="ignore")
                if "FileVault is Off" in output:
                    findings.append(Finding(
                        check_name="system-disk-encryption-macos",
                        severity=Severity.HIGH,
                        description="FileVault disk encryption is disabled on this Mac.",
                        file_path="macOS FileVault status",
                        content="FileVault is Off",
                        reference="https://support.apple.com/guide/mac-help/encrypt-mac-data-with-filevault-mh40596/mac"
                    ))
        except Exception:
            pass
        return findings

    def run(self, target: str) -> List[Finding]:
        findings = []
        findings.extend(self.check_open_ports())
        findings.extend(self.check_firewall())
        findings.extend(self.check_ssh_config())
        findings.extend(self.check_user_privilege())
        findings.extend(self.check_disk_encryption())
        return findings
