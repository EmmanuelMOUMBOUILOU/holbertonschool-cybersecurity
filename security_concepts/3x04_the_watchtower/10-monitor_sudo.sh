#!/bin/bash
tail -f /var/log/auth.log | while read -r line; do
    if echo "$line" | grep -q "sudo" && echo "$line" | grep -Eq "COMMAND|authentication failure"; then
        echo "ALERT: Sudo violation detected!"
    fi
done