#!/bin/bash
tshark -r "$1" -T fields -e urlencoded-form.key -e urlencoded-form.value | awk -F'\t' '$1 ~ /^(password|pass|pwd)$/ {print $2}'
