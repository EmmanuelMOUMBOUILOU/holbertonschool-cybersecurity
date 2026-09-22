#!/bin/bash
lsof -n -P -iTCP:$1 -sTCP:LISTEN | awk 'NR==2 {print $1}'