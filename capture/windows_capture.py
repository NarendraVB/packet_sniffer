from queue import Queue, Full, Empty
from threading import Thread
from typing import Iterator

from scapy.all import sniff

from capture.engine import CaptureEngine


class WindowsCaptureEngine(CaptureEngine):
    """
    Windows packet capture using Scapy + Npcap.
    """

    def __init__(self):
        self._captured_packets = 0
        self._dropped_packets = 0

        self._running = False

        self._queue = Queue(maxsize=1000)

        self._capture_thread = None

    def _packet_handler(self, packet):

        try:
            self._queue.put_nowait(bytes(packet))
            self._captured_packets += 1
        except Full:
            self._dropped_packets += 1

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

        while self._running:
            try:
                packet = self._queue.get(timeout=1)
                yield packet

            except Empty:
                continue


    def stop(self):
        self._running = False

    def statistics(self):

        return {
            "captured": self._captured_packets,
            "dropped": self._dropped_packets,
            "queue_size": self._queue.qsize(),
        }