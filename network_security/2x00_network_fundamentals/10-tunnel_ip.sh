#!/bin/bash
ip addr | awk '/^[0-9]+: tun0:/ {tun=1; next} tun && /inet / {split($2,a,"/"); print a[1]; exit}'
