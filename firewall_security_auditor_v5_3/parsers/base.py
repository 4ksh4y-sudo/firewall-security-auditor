from abc import ABC, abstractmethod


class FirewallParser(ABC):
    @abstractmethod
    def parse(self, filename):
        raise NotImplementedError
