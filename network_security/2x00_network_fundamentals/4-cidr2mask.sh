#!/bin/bash
cidr=$1; for i in 0 1 2 3; do bits=$((cidr-i*8)); if ((bits>=8)); then octet=255; elif ((bits<=0)); then octet=0; else octet=$((256-(1<<(8-bits)))); fi; ((i<3)) && printf "%d." "$octet" || printf "%d\n" "$octet"; done
