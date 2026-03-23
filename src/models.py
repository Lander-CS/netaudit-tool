from dataclasses import dataclass
from typing import Optional, Dict

@dataclass
class AuditLog:
    timestamp: str
    host: str
    port: int
    status: str
    service: Optional[str]
    risk_level: str
    details: str

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "host": self.host,
            "port": self.port,
            "status": self.status,
            "service": self.service,
            "risk_level": self.risk_level,
            "details": self.details
        }