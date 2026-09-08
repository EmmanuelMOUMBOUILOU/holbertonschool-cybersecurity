#!/bin/bash
ss -lnt4 | awk 'NR>1 {n=split($4,a,":"); print a[n]}' | sort -n -u