from capture.pcap_reader import PcapReader
from dispatcher.protocol_dispatcher import ProtocolDispatcher
from output.formatter import PacketFormatter

reader = PcapReader("test_pcaps/dns_small.pcapng")
dispatcher = ProtocolDispatcher()
formatter = PacketFormatter()

for i, raw in enumerate(reader.capture(), start=1):
    print(f"\nPacket {i}")
    print("-" * 60)


    packet = dispatcher.dispatch(raw)

    if packet is None:
        continue

    print(formatter.format(packet))
    print("-" * 60)