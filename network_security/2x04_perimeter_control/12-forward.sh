#!/bin/bash
sudo sysctl -w net.ipv4.ip_forward=1; grep -q '^net.ipv4.ip_forward=1$' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf >/dev/null
