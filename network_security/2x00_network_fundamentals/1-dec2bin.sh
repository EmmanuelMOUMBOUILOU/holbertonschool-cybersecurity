#!/bin/bash
n=$1; binary=""; for ((i=7; i>=0; i--)); do binary+=$(( (n >> i) & 1 )); done; echo "$binary"
