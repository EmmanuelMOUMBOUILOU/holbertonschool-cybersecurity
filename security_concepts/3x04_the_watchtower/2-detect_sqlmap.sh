#!/bin/bash
grep "sqlmap" "$1" | awk '{ip=$1; match($0, /"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) ([^ ]+)/, a); print ip "," a[1] "," a[2]}'