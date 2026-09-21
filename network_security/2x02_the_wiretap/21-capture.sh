#!/bin/bash
sudo tcpdump -i INTERFACE -w 21-capture.pcap '((icmp and host GATEWAY_IP) or (tcp port 80 and host WEB_SERVER_IP))'