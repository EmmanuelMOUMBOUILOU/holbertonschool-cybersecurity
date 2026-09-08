#!/bin/bash
ss -ltn4H | awk '{n=split($4,a,":"); print a[n]}' | sort -n -u