#!/bin/bash
awk -F: '$3 >= 1000 {print $1}' "$1" | while read -r user; do
    for group in disk docker shadow; do
        if id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -Fxq "$group"; then
            echo "$user:$group"
        fi
    done
done