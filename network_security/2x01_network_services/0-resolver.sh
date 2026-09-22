#!/bin/bash
awk '/^[[:space:]]*nameserver[[:space:]]+/ {printf "%s",$2; exit}' /etc/resolv.conf
