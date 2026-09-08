#!/bin/bash
ps -o ppid= -p "$1" | awk '{print $1}'