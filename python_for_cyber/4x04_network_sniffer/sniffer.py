#!/usr/bin/env python3
"""Capture, analyze, and optionally save network packets."""

import argparse
import sys

from scapy.all import sniff


def _layer_keys(name):
    """Return supported Scapy layer keys without requiring class imports."""
    scapy_all = sys.modules.get("scapy.all")
    layer_class = getattr(scapy_all, name, None)
    if isinstance(layer_class, type):
        return (layer_class, name)
    return (name,)


def _get_layer(packet, name):
    """Retrieve a layer from real Scapy packets or simple test doubles."""
    layers = getattr(packet, "layers", None)
    if isinstance(layers, dict):
        for key, layer in layers.items():
            if key == name or getattr(key, "__name__", None) == name:
                return layer

    for attr in (name.lower(), name, name.lower() + "_layer"):
        layer = getattr(packet, attr, None)
        if layer is not None:
            return layer

    for key in _layer_keys(name):
        try:
            layer = packet[key]
        except (TypeError, KeyError, AttributeError, IndexError, ValueError):
            continue
        if layer is not None:
            return layer

    getlayer = getattr(packet, "getlayer", None)
    if callable(getlayer):
        for key in _layer_keys(name):
            try:
                layer = getlayer(key)
            except (TypeError, KeyError, AttributeError, ValueError):
                continue
            if layer is not None:
                return layer

    if name == "IP" and hasattr(packet, "src") and hasattr(packet, "dst"):
        return packet
    if name == "TCP" and hasattr(packet, "sport") and hasattr(packet, "dport"):
        return packet
    return None


def _has_layer(packet, name):
    """Check for a layer with either class-based or string-based APIs."""
    haslayer = getattr(packet, "haslayer", None)
    if callable(haslayer):
        for key in _layer_keys(name):
            try:
                if haslayer(key):
                    return True
            except (TypeError, KeyError, AttributeError, ValueError):
                continue
    return _get_layer(packet, name) is not None


class PacketProcessor:
    """Declare the interface for protocol-specific processors."""

    def process(self, packet):
        """Process a packet; subclasses must override this method."""
        raise NotImplementedError("Subclasses must implement process()")


class TCPProcessor(PacketProcessor):
    """Format TCP source, destination, ports and flags."""

    def process(self, packet):
        """Print TCP information when the required layers are available."""
        ip_layer = _get_layer(packet, "IP")
        tcp_layer = _get_layer(packet, "TCP")
        if ip_layer is None or tcp_layer is None:
            return
        print(
            f"[TCP] {ip_layer.src}:{tcp_layer.sport} -> "
            f"{ip_layer.dst}:{tcp_layer.dport} | Flags: {tcp_layer.flags}"
        )


class UDPProcessor(PacketProcessor):
    """Format UDP source and destination addresses."""

    def process(self, packet):
        """Print UDP information when an IP layer is present."""
        ip_layer = _get_layer(packet, "IP")
        if ip_layer is not None:
            print(f"[UDP] {ip_layer.src} -> {ip_layer.dst}")


class ICMPProcessor(PacketProcessor):
    """Format ICMP source and destination addresses."""

    def process(self, packet):
        """Print ICMP information when an IP layer is present."""
        ip_layer = _get_layer(packet, "IP")
        if ip_layer is not None:
            print(f"[ICMP] {ip_layer.src} -> {ip_layer.dst}")


class Sniffer:
    """Capture packets and delegate protocol processing."""

    def __init__(self, interface, filter_str, output_file):
        """Configure capture settings and protocol strategies."""
        self.interface = interface
        self.filter_str = filter_str
        self.output_file = output_file
        self.verbose = False
        self.pcap_writer = None
        self.processors = {
            "TCP": TCPProcessor(),
            "UDP": UDPProcessor(),
            "ICMP": ICMPProcessor(),
        }

    def start(self):
        """Capture packets continuously, closing PCAP output on shutdown."""
        print("[INFO] PySniffer initialized.")
        try:
            if self.output_file:
                from scapy.utils import PcapWriter

                self.pcap_writer = PcapWriter(
                    self.output_file, append=True, sync=True
                )

            sniff(
                iface=self.interface,
                filter=self.filter_str,
                prn=self._process_packet,
                store=False,
            )
        except KeyboardInterrupt:
            print("[INFO] Stopping capture...")
        except OSError as error:
            print(f"[ERROR] Packet capture failed: {error}")
            raise SystemExit(1)
        finally:
            if self.pcap_writer is not None:
                self.pcap_writer.close()
                self.pcap_writer = None

    def _process_packet(self, packet):
        """Save each packet, then dispatch to the appropriate strategy."""
        if self.pcap_writer is not None:
            self.pcap_writer.write(packet)

        for name, processor in self.processors.items():
            if _has_layer(packet, name):
                processor.process(packet)
                break

        if self.verbose:
            from scapy.all import hexdump

            hexdump(packet)


def main():
    """Parse CLI options and launch the network sniffer."""
    parser = argparse.ArgumentParser(
        description="PySniffer - Network packet analyzer"
    )
    parser.add_argument("-i", "--interface", help="Interface to capture from")
    parser.add_argument("-f", "--filter", help="BPF capture filter")
    parser.add_argument(
        "--write", metavar="FILE", help="Write captured packets to PCAP"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show packet hex dumps"
    )
    args = parser.parse_args()
    sniffer = Sniffer(args.interface, args.filter, args.write)
    sniffer.verbose = args.verbose
    sniffer.start()


if __name__ == "__main__":
    main()
