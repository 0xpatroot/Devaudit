from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional, Any, Dict

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __lt__(self, other):

        order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        return order[self.value] < order[other.value]

@dataclass
class Finding:
    check_name: str
    severity: Severity
    description: str
    file_path: str
    line_number: Optional[int] = None
    content: Optional[str] = None
    reference: Optional[str] = None
    fixable: bool = False
    fix_payload: Dict[str, Any] = field(default_factory=dict)

class BaseCheck:
    name: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    reference: str = ""

    def __init__(self):
        pass

    def run(self, target: str) -> List[Finding]:
        raise NotImplementedError("Subclasses must implement run()")
