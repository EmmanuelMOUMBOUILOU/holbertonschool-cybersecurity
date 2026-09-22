#!/bin/bash
attacker=$(tshark -r "$1" -T fields -e ip.src | sort | uniq -c | sort -rn | awk 'NR==1 {print $2}'); tshark -r "$1" -Y "ip.addr == $attacker" -T fields -e frame.time_epoch | awk 'NR==1 {first=$0} {last=$0} END {print first; print last}'
