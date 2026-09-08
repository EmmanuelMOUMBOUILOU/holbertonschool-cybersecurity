#!/bin/bash
lsof -n -P -iTCP:$1 -sTCP:LISTEN -t | xargs -r ps -o comm= -p