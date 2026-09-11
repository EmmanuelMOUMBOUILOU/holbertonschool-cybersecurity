#!/bin/bash
IFS="." read -r a b c d <<< "$1"; printf "%08d.%08d.%08d.%08d\n" "$(echo "obase=2;$a" | bc)" "$(echo "obase=2;$b" | bc)" "$(echo "obase=2;$c" | bc)" "$(echo "obase=2;$d" | bc)"
