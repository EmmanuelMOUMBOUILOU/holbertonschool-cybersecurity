#!/bin/bash
dig +trace "$1" | awk '/Received/ && /root-servers\.net/ {split($6,a,"#"); print a[1]; exit}'
