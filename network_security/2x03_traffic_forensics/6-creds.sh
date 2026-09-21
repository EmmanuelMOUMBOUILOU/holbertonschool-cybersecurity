#!/bin/bash
tshark -r "$1" -T fields -e urlencoded-form.value -e urlencoded-form.key | awk -F'\t' '$2 ~ /^(password|pass|pwd)$/ {print $1}'
