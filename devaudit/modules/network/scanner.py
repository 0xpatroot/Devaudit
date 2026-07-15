import socket
import ssl
import datetime
import urllib.parse
from typing import List, Tuple
from devaudit.modules.base_check import BaseCheck, Severity, Finding

class NetworkScanner(BaseCheck):
    name = "network"
    description = "Inspects network configurations, DNS records, and SSL/TLS certificate parameters"
    severity = Severity.MEDIUM
    reference = "https://www.ssllabs.com/"

    def __init__(self):
        super().__init__()

    def parse_target(self, target: str) -> Tuple[str, int]:
        """Parse target URL or host string to extract host and port."""

        if "://" in target:
            parsed = urllib.parse.urlparse(target)
            host = parsed.hostname or ""
            port = parsed.port
            if not port:
                port = 443 if parsed.scheme == "https" else 80
            return host, port
        else:
            if ":" in target:
                host, port_str = target.split(":", 1)
                try:
                    return host.strip(), int(port_str.strip())
                except ValueError:
                    return host.strip(), 443
            else:
                return target.strip(), 443

    def audit_ssl(self, host: str, port: int) -> List[Finding]:
        findings = []
        if not host:
            return findings

        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                        findings.append(Finding(
                            check_name="ssl-tls-outdated",
                            severity=Severity.HIGH,
                            description=f"Host {host} supports insecure/outdated protocol version: {version}",
                            file_path=f"{host}:{port}",
                            content=f"Protocol: {version}",
                            reference="https://datatracker.ietf.org/doc/html/rfc8996"
                        ))

                    if cipher:
                        cipher_name, tls_ver, key_bits = cipher
                        if key_bits < 128:
                            findings.append(Finding(
                                check_name="ssl-weak-cipher",
                                severity=Severity.HIGH,
                                description=f"Host {host} is using a weak cipher suite: {cipher_name} with only {key_bits} bits keys.",
                                file_path=f"{host}:{port}",
                                content=f"Cipher: {cipher_name} ({key_bits} bits)",
                                reference="https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final"
                            ))

                    if cert and "notAfter" in cert:
                        expiry_str = cert["notAfter"]

                        expiry_date = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                        now = datetime.datetime.utcnow()
                        days_left = (expiry_date - now).days

                        if days_left < 0:
                            findings.append(Finding(
                                check_name="ssl-cert-expired",
                                severity=Severity.CRITICAL,
                                description=f"SSL certificate for {host} has EXPIRED on {expiry_str}.",
                                file_path=f"{host}:{port}",
                                content=f"Expired {abs(days_left)} days ago",
                                reference="https://en.wikipedia.org/wiki/Public_key_certificate"
                            ))
                        elif days_left < 30:
                            findings.append(Finding(
                                check_name="ssl-cert-expiring-soon",
                                severity=Severity.MEDIUM,
                                description=f"SSL certificate for {host} will expire soon (in {days_left} days) on {expiry_str}.",
                                file_path=f"{host}:{port}",
                                content=f"Expires in {days_left} days",
                                reference="https://en.wikipedia.org/wiki/Public_key_certificate"
                            ))
        except ssl.SSLError as e:
            findings.append(Finding(
                check_name="ssl-handshake-failed",
                severity=Severity.HIGH,
                description=f"SSL handshake with {host}:{port} failed. The certificate might be self-signed, invalid, or hostname mismatched: {str(e)}",
                file_path=f"{host}:{port}",
                content="Handshake error",
                reference="https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_handshake"
            ))
        except Exception as e:
            findings.append(Finding(
                check_name="ssl-connection-failed",
                severity=Severity.LOW,
                description=f"Could not connect to {host}:{port} to perform SSL check: {str(e)}",
                file_path=f"{host}:{port}",
                content="Connection timeout/failure"
            ))

        return findings

    def audit_dns(self, host: str) -> List[Finding]:
        findings = []
        if not host:
            return findings

        try:

            ip_addresses = socket.gethostbyname_ex(host)[2]
            if not ip_addresses:
                findings.append(Finding(
                    check_name="network-dns-resolution",
                    severity=Severity.HIGH,
                    description=f"DNS resolution failed to return IP addresses for host: {host}",
                    file_path=host,
                    content="No IPs resolved"
                ))
        except Exception as e:
            findings.append(Finding(
                check_name="network-dns-error",
                severity=Severity.HIGH,
                description=f"Failed to resolve DNS for {host}: {str(e)}",
                file_path=host,
                content="DNS Lookup Error"
            ))
        return findings

    def run(self, target: str) -> List[Finding]:
        import os

        if os.path.exists(target) or target in (".", ".."):
            return []

        host, port = self.parse_target(target)
        findings = []
        findings.extend(self.audit_dns(host))
        findings.extend(self.audit_ssl(host, port))
        return findings
