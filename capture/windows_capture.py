from queue import Queue
from threading import Thread
from typing import Iterator

from scapy.all import sniff

from capture.engine import CaptureEngine


class WindowsCaptureEngine(CaptureEngine):
    """
    Windows packet capture using Scapy + Npcap.
    """

    def __init__(self):

        self._running = False

        self._queue = Queue()

        self._capture_thread = None

    def _packet_handler(self, packet):

        self._queue.put(bytes(packet))

    def _capture(self):

        sniff(
            prn=self._packet_handler,
            store=False
        )

    def start(self) -> Iterator[bytes]:
        ""

        self._running = True

        self._capture_thread = Thread(
            target=self._capture,
            daemon=True
        )
        self._capture_thread.start()

    def stop(self):
        self._running = False