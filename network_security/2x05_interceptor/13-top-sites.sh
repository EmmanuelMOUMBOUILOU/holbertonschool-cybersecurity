#!/bin/bash
awk '{print $7}' /var/log/squid/access.log | awk -F/ '{print $3}' | sort | uniq -c | sort -rn | head -10
