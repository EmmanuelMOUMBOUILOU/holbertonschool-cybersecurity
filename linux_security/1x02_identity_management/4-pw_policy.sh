#!/bin/bash
dpkg -s "$1" >/dev/null 2>&1 || apt-get update && apt-get install -y "$1"
grep -q '^password.*pam_pwquality.so' "$2" && sed -i -E 's|^password.*pam_pwquality.so.*|password requisite pam_pwquality.so minlen=12 minclass=3|' "$2" || echo 'password requisite pam_pwquality.so minlen=12 minclass=3' >> "$2"