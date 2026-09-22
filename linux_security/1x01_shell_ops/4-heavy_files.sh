#!/bin/bash
ls -l "$1" | awk 'NR>1 && $5 > 1024 {print $9}'