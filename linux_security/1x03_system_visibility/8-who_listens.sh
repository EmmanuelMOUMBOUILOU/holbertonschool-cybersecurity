#!/bin/bash
lsof -n -iTCP:$1 -sTCP:LISTEN -t | xargs -r ps -o comm= -p