from typing import List, Dict, Any
from devaudit.modules.base_check import Finding

class ScannerOrchestrator:
    def __init__(self):
        self.scanners = {}
        self._initialize_scanners()

    def _initialize_scanners(self):

        try:
            from devaudit.modules.secrets.scanner import SecretsScanner
            self.scanners["secrets"] = SecretsScanner
        except ImportError:
            pass

        try:
            from devaudit.modules.dependencies.scanner import DependencyScanner
            self.scanners["deps"] = DependencyScanner
        except ImportError:
            pass

        try:
            from devaudit.modules.system.scanner import SystemScanner
            self.scanners["system"] = SystemScanner
        except ImportError:
            pass

        try:
            from devaudit.modules.git.scanner import GitScanner
            self.scanners["git"] = GitScanner
        except ImportError:
            pass

        try:
            from devaudit.modules.network.scanner import NetworkScanner
            self.scanners["network"] = NetworkScanner
        except ImportError:
            pass

        try:
            from devaudit.modules.privacy.scanner import PrivacyScanner
            self.scanners["privacy"] = PrivacyScanner
        except ImportError:
            pass

        try:
            from devaudit.modules.docker.scanner import DockerScanner
            self.scanners["docker"] = DockerScanner
        except ImportError:
            pass

    def run_scanner(self, name: str, target: str, **kwargs) -> List[Finding]:
        if name not in self.scanners:
            return []
        scanner_class = self.scanners[name]
        scanner_instance = scanner_class()

        if hasattr(scanner_instance, "run_with_args"):
            return scanner_instance.run_with_args(target, **kwargs)
        else:
            return scanner_instance.run(target)

    def run_all(self, target: str, **kwargs) -> Dict[str, List[Finding]]:
        results = {}
        for name in self.scanners:
            results[name] = self.run_scanner(name, target, **kwargs)
        return results

orchestrator = ScannerOrchestrator()
