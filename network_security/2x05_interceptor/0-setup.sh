#!/bin/bash
sudo apt update && sudo apt install -y squid && sudo systemctl enable squid && sudo systemctl stop squid && sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.bak
