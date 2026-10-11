
#!/usr/bin/env python3
"""Capture and process network packets using a worker thread."""

import argparse
from queue import Queue
from threading import Thread

from scapy.all import IP, TCP, UDP, ICMP, Raw, sniff

try:
    from scapy.utils import PcapWriter
except ImportError:
    PcapWriter = None


class PacketProcessor:
    """Base class for protocol-specific packet processors."""

    def process(self, packet):
        """Process a network packet."""
        raise NotImplementedError(
            "Subclasses must implement process()"
        )


class TCPProcessor(PacketProcessor):
    """Process TCP packets."""

    def process(self, packet):
        """Display TCP addresses, ports, and flags."""
        if not packet.haslayer(IP):
            return

        ip = packet[IP]
        tcp = packet[TCP]

        print(
            f"[TCP] {ip.src}:{tcp.sport} -> "
            f"{ip.dst}:{tcp.dport} | Flags: {tcp.flags}"
        )


class UDPProcessor(PacketProcessor):
    """Process UDP packets."""

    def process(self, packet):
        """Display UDP source and destination addresses."""
        if not packet.haslayer(IP):
            return

        ip = packet[IP]

        print(f"[UDP] {ip.src} -> {ip.dst}")


class ICMPProcessor(PacketProcessor):
    """Process ICMP packets."""

    def process(self, packet):
        """Display ICMP source and destination addresses."""
        if not packet.haslayer(IP):
            return

        ip = packet[IP]

        print(f"[ICMP] {ip.src} -> {ip.dst}")


class Sniffer:
    """Capture packets and process them asynchronously."""

    def __init__(self, interface, filter_str, output_file):
        """Initialize capture, processing, and statistics."""
        self.interface = interface
        self.filter_str = filter_str
        self.output_file = output_file
        self.verbose = False
        self.search = None
        self.pcap_writer = None

        self.processors = {
            TCP: TCPProcessor(),
            UDP: UDPProcessor(),
            ICMP: ICMPProcessor()
        }

        self.stats = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "OTHER": 0
        }

        self.packet_queue = Queue()
        self.queue = self.packet_queue
        self.stop_signal = object()
        self.worker = None

    def _enqueue_packet(self, packet):
        """Add a captured packet to the processing queue."""
        self.packet_queue.put(packet)

    def _process_queue(self):
        """Process queued packets until the stop signal arrives."""
        while True:
            packet = self.packet_queue.get()

            try:
                if packet is self.stop_signal:
                    return

                self._process_packet(packet)
            finally:
                self.packet_queue.task_done()

    def _update_stats(self, packet):
        """Count packets by protocol."""
        if not hasattr(packet, "haslayer"):
            self.stats["OTHER"] += 1
            return

        for protocol, name in (
            (TCP, "TCP"),
            (UDP, "UDP"),
            (ICMP, "ICMP")
        ):
            if packet.haslayer(protocol):
                self.stats[name] += 1
                return

        self.stats["OTHER"] += 1

    def _print_stats(self):
        """Display the final protocol statistics."""
        total = sum(self.stats.values())

        print()
        print("[STATS] Packet Statistics")
        print("-------------------------")

        for protocol, count in self.stats.items():
            print(f"{protocol:<6}: {count}")

        print("-------------------------")
        print(f"TOTAL : {total}")

    def _search_payload(self, packet):
        """Search the Raw payload for the configured string."""
        if not self.search:
            return

        if not hasattr(packet, "haslayer"):
            return

        if not packet.haslayer(Raw):
            return

        payload = packet[Raw].load
        text = payload.decode("utf-8", errors="replace")

        if self.search in text:
            print("[ALERT] Payload Match found!")

    def _process_packet(self, packet):
        """Save, count, analyze, and inspect a packet."""
        self._update_stats(packet)

        if self.pcap_writer is not None:
            self.pcap_writer.write(packet)

        if hasattr(packet, "haslayer"):
            for protocol, processor in self.processors.items():
                if packet.haslayer(protocol):
                    processor.process(packet)
                    break

        self._search_payload(packet)

        if self.verbose:
            from scapy.all import hexdump
            hexdump(packet)

    def start(self):
        """Capture packets while a worker processes the queue."""
        print("[INFO] PySniffer initialized.")

        try:
            if self.output_file:
                if PcapWriter is None:
                    raise RuntimeError(
                        "PCAP writing requires scapy.utils.PcapWriter"
                    )

                self.pcap_writer = PcapWriter(
                    self.output_file,
                    append=True,
                    sync=True
                )

            self.worker = Thread(
                target=self._process_queue,
                daemon=False
            )
            self.worker.start()

            sniff(
                iface=self.interface,
                filter=self.filter_str,
                prn=self._enqueue_packet,
                store=False
            )

        except KeyboardInterrupt:
            print("[INFO] Stopping capture...")

        except OSError as error:
            print(f"[ERROR] Packet capture failed: {error}")
            raise SystemExit(1)

        finally:
            if self.worker is not None and self.worker.is_alive():
                self.packet_queue.put(self.stop_signal)
                self.packet_queue.join()
                self.worker.join()

            if self.pcap_writer is not None:
                self.pcap_writer.close()

            self._print_stats()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PySniffer - Network packet analyzer"
    )

    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to capture packets from"
    )

    parser.add_argument(
        "-f",
        "--filter",
        help="BPF filter expression for packet capture"
    )

    parser.add_argument(
        "--write",
        metavar="FILE",
        help="Save captured packets to a PCAP file"
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Display hexadecimal packet dumps"
    )

    parser.add_argument(
        "-s",
        "--search",
        metavar="STRING",
        help="Search for a string in packet payloads"
    )

    args = parser.parse_args()

    sniffer = Sniffer(
        args.interface,
        args.filter,
        args.write
    )

    sniffer.verbose = args.verbose
    sniffer.search = args.search

    sniffer.start()
