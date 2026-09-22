#!/bin/bash
grep -h "option dhcp-server-identifier" /var/lib/dhcp/* 2>/dev/null | tail -1 | awk '{gsub(/;/,"",$3); printf "%s",$3}'
