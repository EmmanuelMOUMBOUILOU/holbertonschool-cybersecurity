#!/bin/bash
sudo nft insert rule inet filter forward ip saddr 10.200.0.0/24 oifname != "wg0" tcp dport 80 drop; sudo nft insert rule inet filter forward ip saddr 10.200.0.0/24 oifname != "wg0" tcp dport 443 drop; sudo nft insert rule inet filter output tcp dport { 80, 443 } accept
