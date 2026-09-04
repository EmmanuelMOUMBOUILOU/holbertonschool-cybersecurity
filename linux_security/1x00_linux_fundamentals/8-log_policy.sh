#!/bin/bash
mkdir -p "$1" && chown root:$2 "$1" && chmod 2770 "$1"
printf '%s\n' "$1/*.log {" " create 0640 root $2" " rotate 7" " daily" "}" > /etc/logrotate.d/app