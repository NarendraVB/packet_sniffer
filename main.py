from capture.windows_capture import WindowsCaptureEngine

from dispatcher.protocol_dispatcher import ProtocolDispatcher

from protocols.ethernet import EthernetParser

def main():
    ethernet = EthernetParser()

    dispatcher = ProtocolDispatcher()

    capture = WindowsCaptureEngine()

    try:
        for raw_packet in capture.start():

            ethernet_frame = ethernet.parse(raw_packet)

            network_packet = dispatcher.dispatch_ethernet(
                ethernet_frame
            )

            if network_packet is None:
                continue

            print(network_packet)

    except KeyboardInterrupt:

        capture.stop()

        print("\nCapture stopped.")


if __name__ == "__main__":
    main()