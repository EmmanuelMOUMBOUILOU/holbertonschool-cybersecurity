#!/bin/bash
sudo nft flush ruleset; echo 'table inet filter { chain input { type filter hook input priority 0; policy accept; } chain forward { type filter hook forward priority 0; policy accept; } chain output { type filter hook output priority 0; policy accept; } }' | sudo nft -f -; [ "$1" = "--rollback" ] || (sleep 300 && "$0" --rollback) &
