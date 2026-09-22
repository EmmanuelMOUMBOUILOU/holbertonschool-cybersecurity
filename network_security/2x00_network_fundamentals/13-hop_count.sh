#!/bin/bash
traceroute -n "$1" 2>/dev/null | awk 'NR>1 {hop=$1} END {printf "%s",hop}'
