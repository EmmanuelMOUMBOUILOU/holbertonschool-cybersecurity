#!/bin/bash
route=$(ip route | grep '^default')
printf "%s" "$(echo "$route" | awk '{print $3}')"
