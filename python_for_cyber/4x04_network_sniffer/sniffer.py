#!/usr/bin/env python3
"""Capture, inspect, and analyze network packets with Scapy."""

import argparse
from queue import Queue
from threading import Thread

from scapy.all import ICMP, IP, Raw, TCP, UDP, sniff
from scapy.utils import PcapWriter


class PacketProcessor:
    """Define the interface for protocol-specific processors."""

    def process(self, packet):
        """Process a packet in a concrete subclass."""
        raise NotImplementedError(
            "Subclasses must implement process()"
        )


class TCPProcessor(PacketProcessor):
    """Display information about TCP packets."""

    def process(self, packet):
        """Extract and display TCP addresses, ports, and flags."""
        if not hasattr(packet, "haslayer"):
            return

        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        print(
            f"[TCP] {ip_layer.src}:{tcp_layer.sport} -> "
            f"{ip_layer.dst}:{tcp_layer.dport} | "
            f"Flags: {tcp_layer.flags}"
        )


class UDPProcessor(PacketProcessor):
    """Display information about UDP packets."""

    def process(self, packet):
        """Extract and display UDP source and destination IPs."""
        if not hasattr(packet, "haslayer"):
            return

        if not packet.haslayer(IP) or not packet.haslayer(UDP):
            return

        ip_layer = packet[IP]

        print(f"[UDP] {ip_layer.src} -> {ip_layer.dst}")


class ICMPProcessor(PacketProcessor):
    """Display information about ICMP packets."""

    def process(self, packet):
        """Extract and display ICMP source and destination IPs."""
        if not hasattr(packet, "haslayer"):
            return

        if not packet.haslayer(IP) or not packet.haslayer(ICMP):
            return

        ip_layer = packet[IP]

        print(f"[ICMP] {ip_layer.src} -> {ip_layer.dst}")


class Sniffer:
    """Manage packet capture, processing, and statistics."""

    def __init__(self, interface, filter_str, output_file):
        """Initialize capture options and processing resources."""
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
        """Place a captured packet into the processing queue."""
        self.packet_queue.put(packet)

    def _process_queue(self):
        """Consume queued packets until the stop signal arrives."""
        while True:
            packet = self.packet_queue.get()

            try:
                if packet is self.stop_signal:
                    return

                self._process_packet(packet)
            finally:
                self.packet_queue.task_done()

    def _update_stats(self, packet):
        """Update protocol counters for a captured packet."""
        if not hasattr(packet, "haslayer"):
            self.stats["OTHER"] += 1
            return

        protocol_layers = (
            (TCP, "TCP"),
            (UDP, "UDP"),
            (ICMP, "ICMP")
        )

        for layer_class, protocol_name in protocol_layers:
            if packet.haslayer(layer_class):
                self.stats[protocol_name] += 1
                return

        self.stats["OTHER"] += 1

    def _print_stats(self):
        """Print the final protocol statistics."""
        total_packets = sum(self.stats.values())

        print()
        print("[STATS] Packet Statistics")
        print("-------------------------")

        for protocol_name, count in self.stats.items():
            print(f"{protocol_name:<6}: {count}")

        print("-------------------------")
        print(f"TOTAL : {total_packets}")

    def _search_payload(self, packet):
        """Search packet payloads for a configured text string."""
        if not self.search:
            return

        if not hasattr(packet, "haslayer"):
            return

        if not packet.haslayer(Raw):
            return

        raw_layer = packet[Raw]
        payload = raw_layer.load

        if isinstance(payload, bytes):
            payload_text = payload.decode(
                "utf-8",
                errors="replace"
            )
        else:
            payload_text = str(payload)

        if self.search in payload_text:
            print("[ALERT] Payload Match found!")

    def _process_packet(self, packet):
        """Write, count, inspect, and display a captured packet."""
        self._update_stats(packet)

        if self.pcap_writer is not None:
            self.pcap_writer.write(packet)

        if hasattr(packet, "haslayer"):
            for layer_class, processor in self.processors.items():
                if packet.haslayer(layer_class):
                    processor.process(packet)
                    break

        self._search_payload(packet)

        if self.verbose:
            from scapy.all import hexdump
            hexdump(packet)

    def start(self):
        """Start capture and process packets in a worker thread."""
        print("[INFO] PySniffer initialized.")

        try:
            if self.output_file:
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
            raise SystemExit(1) from error

        finally:
            if self.worker is not None and self.worker.is_alive():
                self.packet_queue.put(self.stop_signal)
                self.packet_queue.join()
                self.worker.join()

            if self.pcap_writer is not None:
                self.pcap_writer.close()

            self._print_stats()


def main():
    """Parse command-line arguments and start PySniffer."""
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


if __name__ == "__main__":
    main()
