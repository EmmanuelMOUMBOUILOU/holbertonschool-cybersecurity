#!/bin/bash
sed -i -E 's/^[#[:space:]]*PermitRootLogin.*/PermitRootLogin no/; s/^[#[:space:]]*PasswordAuthentication.*/PasswordAuthentication no/; s/^[#[:space:]]*PubkeyAuthentication.*/PubkeyAuthentication yes/' "$1"
if sshd -t -f "$1"; then
    service ssh reload 2>/dev/null || service sshd reload 2>/dev/null || pkill -HUP sshd
fi