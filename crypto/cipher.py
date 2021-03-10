from abc import ABC, abstractmethod
from typing import Tuple


class Cipher(ABC):
    """
    A cipher for encrypting and decrypting data.
    """

    @abstractmethod
    def encrypt(self, data: str) -> Tuple[str, int]:
        pass

    @abstractmethod
    def decrypt(self, data: str, padding_size: int = 0) -> str:
        pass
