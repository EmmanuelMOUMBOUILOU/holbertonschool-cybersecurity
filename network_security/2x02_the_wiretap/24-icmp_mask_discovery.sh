#!/bin/bash
[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }; nmap -sn -PM "$1"
