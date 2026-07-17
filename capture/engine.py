from typing import Iterator


class CaptureEngine:
    """
    Responsible only for capturing packets.

    It does NOT:
    - Parse protocols
    - Print output
    - Detect attacks
    """

    def __init__(self):
        pass

    def start(self) -> Iterator[bytes]:
        """
        Start capturing packets.

        Later this will yield raw packet bytes.
        """
        raise NotImplementedError("Packet capture not implemented yet.")