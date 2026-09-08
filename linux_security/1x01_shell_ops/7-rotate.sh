#!/bin/bash
if [ ! -d "$1" ]; then
    exit 1
fi

mkdir -p "$1/backups"

for file in "$1"/*.log; do
    [ -e "$file" ] || continue

    if [ "$(stat -c%s "$file")" -gt 1024 ]; then
        gzip "$file"
        mv "$file.gz" "$1/backups/"
    else
        echo "Skipping small file: $(basename "$file")"
    fi
done