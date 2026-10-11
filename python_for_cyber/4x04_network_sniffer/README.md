
# PySniffer - Network Packet Analyzer

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Scapy](https://img.shields.io/badge/Scapy-Network%20Analysis-green)
![License](https://img.shields.io/badge/License-Educational-orange)
![Code Style](https://img.shields.io/badge/Code%20Style-PEP8-brightgreen)

## Description

PySniffer is a Python-based network packet analyzer developed as
part of the Holberton School cybersecurity curriculum.

The tool captures network packets using Scapy, identifies common
network protocols, analyzes packet information, and displays
relevant results in the terminal.

PySniffer uses a modular architecture based on protocol
processors and a multithreaded packet-processing system.

### Features

- Real-time network packet capture using Scapy.
- TCP, UDP, and ICMP protocol identification.
- TCP source and destination port extraction.
- TCP flag inspection.
- Network interface selection.
- BPF packet filtering.
- Packet capture export to PCAP files.
- Verbose hexadecimal packet inspection.
- Payload keyword searching.
- Protocol statistics.
- Queue-based asynchronous packet processing.
- Unit testing using Python's unittest framework.
- Code quality verification using pylint or flake8.

## Installation

### Requirements

- Python 3.8 or later.
- pip package manager.
- Scapy library.
- Linux or a compatible environment.
- Appropriate permissions for packet capture.

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/holbertonschool-cybersecurity.git
```

Replace `YOUR_USERNAME` with your GitHub username.

### 2. Navigate to the project directory

```bash
cd holbertonschool-cybersecurity/python_for_cyber/4x04_network_sniffer
```

### 3. Create a virtual environment

```bash
python3 -m venv venv
```

### 4. Activate the virtual environment

```bash
source venv/bin/activate
```

### 5. Install dependencies

```bash
python3 -m pip install scapy
```

For development and code quality checks:

```bash
python3 -m pip install pylint flake8 pycodestyle
```

## Usage

### Basic packet capture

Start PySniffer with:

```bash
sudo python3 sniffer.py
```

The tool captures network packets and displays information
about supported protocols.

Press `Ctrl+C` to stop the capture and display statistics.

### Select a network interface

Use the `-i` or `--interface` option:

```bash
sudo python3 sniffer.py -i eth0
```

Replace `eth0` with the network interface available on
your system.

### Apply a packet filter

Use the `-f` or `--filter` option:

```bash
sudo python3 sniffer.py -f "tcp"
```

Capture HTTP-related TCP traffic:

```bash
sudo python3 sniffer.py -f "tcp port 80"
```

### Save packets to a PCAP file

Use the `--write` option:

```bash
sudo python3 sniffer.py --write capture.pcap
```

The generated PCAP file can be opened with tools such
as Wireshark for further analysis.

### Enable verbose mode

Use the `-v` or `--verbose` option:

```bash
sudo python3 sniffer.py -v
```

Verbose mode displays hexadecimal packet information.

### Search packet payloads

Use the `-s` or `--search` option:

```bash
sudo python3 sniffer.py -s "password"
```

When a matching payload is detected, PySniffer displays:

```text
[ALERT] Payload Match found!
```

### Combine multiple options

```bash
sudo python3 sniffer.py \
    -i eth0 \
    -f "tcp" \
    --write capture.pcap \
    -v \
    -s "password"
```

### Command-line options

| Option | Description |
|--------|-------------|
| `-i`, `--interface` | Select a network interface |
| `-f`, `--filter` | Apply a BPF capture filter |
| `--write FILE` | Save packets to a PCAP file |
| `-v`, `--verbose` | Display hexadecimal packet data |
| `-s`, `--search STRING` | Search packet payloads |

## Architecture

PySniffer uses a modular design to separate packet capture
from packet processing.

### Main components

#### Sniffer

The `Sniffer` class manages packet capture, processing,
statistics, and optional PCAP export.

It initializes the protocol processors and coordinates
the packet-processing worker.

#### PacketProcessor

`PacketProcessor` is the base class for protocol-specific
packet processors.

Its subclasses implement the `process()` method.

#### TCPProcessor

Extracts and displays TCP information, including:

- Source IP address.
- Destination IP address.
- Source TCP port.
- Destination TCP port.
- TCP flags.

#### UDPProcessor

Extracts and displays source and destination IP addresses
from UDP packets.

#### ICMPProcessor

Extracts and displays source and destination IP addresses
from ICMP packets.

### Thread and Queue Design

PySniffer separates packet capture from packet processing
using Python's `threading` and `queue` modules.

The capture callback places packets into a thread-safe queue.

A dedicated worker thread retrieves packets from the queue
and processes them independently.

This design helps reduce the amount of processing performed
inside the packet capture callback.

### Processing workflow

```text
+--------------------------+
|      Network Traffic     |
+------------+-------------+
             |
             v
+--------------------------+
|      Scapy sniff()       |
|      Packet Capture      |
+------------+-------------+
             |
             v
+--------------------------+
|     _enqueue_packet()    |
+------------+-------------+
             |
             v
+--------------------------+
|      Packet Queue        |
|       queue.Queue        |
+------------+-------------+
             |
             v
+--------------------------+
|       Worker Thread      |
|      _process_queue()    |
+------------+-------------+
             |
             v
+--------------------------+
|     _process_packet()    |
+------------+-------------+
             |
             v
+--------------------------+
|     Protocol Detection   |
+------------+-------------+
             |
      +------+------+ 
      |      |      |
      v      v      v
    TCP     UDP    ICMP
      |      |      |
      +------+------+ 
             |
             v
+--------------------------+
| Statistics and Analysis  |
| Payload Search / PCAP    |
+--------------------------+
```

### Queue lifecycle

1. Scapy captures a packet.
2. The capture callback adds the packet to the queue.
3. The worker thread retrieves the packet.
4. The packet is processed by the appropriate processor.
5. Protocol statistics are updated.
6. Optional payload inspection and PCAP export are performed.
7. During shutdown, a stop signal is sent to the worker.
8. The application waits for queued work to finish.
9. Final packet statistics are displayed.

## Unit Testing

PySniffer includes unit tests that validate packet-processing
logic without requiring live network traffic.

The tests use Python's built-in `unittest` framework and
artificial packets constructed with Scapy.

Run the tests with:

```bash
python3 -m unittest tests.py -v
```

The tests cover:

- Base processor behavior.
- TCP address and port extraction.
- TCP output formatting.
- UDP packet processing.
- ICMP packet processing.
- Protocol statistics.

## Code Quality

PySniffer follows Python coding conventions.

Check the code with:

```bash
pycodestyle sniffer.py tests.py
```

Run flake8:

```bash
python3 -m flake8 sniffer.py
```

Run pylint:

```bash
python3 -m pylint sniffer.py
```

The project's code quality target is a pylint score
strictly greater than 8/10.

## Project Structure

```text
4x04_network_sniffer/
|
|-- sniffer.py
|-- tests.py
|-- README.md
```

- `sniffer.py`: Main network sniffer implementation.
- `tests.py`: Unit tests for packet-processing logic.
- `README.md`: Installation, usage, and architecture guide.

## Security and Responsible Use

PySniffer is intended for educational purposes,
network diagnostics, and authorized security analysis.

Only capture or inspect network traffic on systems
and networks where you have explicit permission.

Unauthorized packet interception may violate
privacy laws and organizational security policies.

## Author

Developed as part of the Holberton School
Cybersecurity curriculum.

## Acknowledgments

- Holberton School.
- Python Software Foundation.
- Scapy project contributors.
