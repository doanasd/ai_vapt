from abc import ABC, abstractmethod
from typing import Dict, Any

class BasePlugin(ABC):

    @property
    @abstractmethod
    def METADATA(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    def match(self, service_info: Dict[str, Any]) -> bool:
        pass

    @abstractmethod
    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        pass
