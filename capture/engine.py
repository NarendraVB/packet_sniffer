from abc import ABC, abstractmethod
from typing import Iterator


class CaptureEngine(ABC):
    """
    Abstract base class for all packet capture engines.
    """

    @abstractmethod
    def start(self) -> Iterator[bytes]:
        """
        Start capturing packets.

        Yields:
            Raw packet bytes.
        """
        pass

    @abstractmethod
    def stop(self) -> None:
        """
        Stop packet capture.
        """
        pass