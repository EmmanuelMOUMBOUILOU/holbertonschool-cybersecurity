
# Python - Intelligence Broker

IntelBroker is a Python cybersecurity intelligence tool.

## Task 0 - Mock Environment

The mock API server simulates three threat intelligence services:

- VirusTotal: IP reputation and malicious status.
- Shodan: Open ports, operating system, and ISP.
- AbuseIPDB: Abuse confidence score and report count.

## Usage

Start the local server:

```bash
./mock_api.py
```

Test the VirusTotal endpoint:

```bash
curl http://localhost:5000/virustotal/8.8.8.8
```

The server runs locally on port 5000.
