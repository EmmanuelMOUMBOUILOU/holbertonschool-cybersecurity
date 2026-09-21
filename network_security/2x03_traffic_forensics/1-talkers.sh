#!/bin/bash
tshark -r "$1" -Y ip -T fields -e ip.src | sort | uniq -c | sort -nr | awk '{print $2}'
