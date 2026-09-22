#!/bin/bash
awk '$4 ~ /\/403$/ {print $1, $3, $7}' /var/log/squid/access.log
