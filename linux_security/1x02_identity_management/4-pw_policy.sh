#!/bin/bash
if ! dpkg -s "$1" >/dev/null 2>&1; then
    apt-get update
    apt-get install -y "$1"
fi

if grep -q '^password.*pam_pwquality.so' "$2"; then
    sed -i -E 's|^password.*pam_pwquality.so.*|password requisite pam_pwquality.so minlen=12 minclass=3|' "$2"
else
    echo 'password requisite pam_pwquality.so minlen=12 minclass=3' >> "$2"
fi