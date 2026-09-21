#!/bin/bash
sudo nft add rule inet filter input ip saddr 10.200.0.0/24 tcp dport 3128 accept
