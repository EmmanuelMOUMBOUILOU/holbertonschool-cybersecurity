#!/bin/bash
ps -eo pid,comm,%cpu --sort=-%cpu | awk 'NR==2 {print $1, $2}'