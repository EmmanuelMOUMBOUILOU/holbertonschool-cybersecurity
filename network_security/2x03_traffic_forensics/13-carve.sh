#!/bin/bash
rm -rf carved_files && mkdir carved_files && tshark -r "$1" --export-objects http,carved_files >/dev/null 2>&1 && md5sum carved_files/* | awk '{print $1}'
