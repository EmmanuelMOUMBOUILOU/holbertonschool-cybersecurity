#!/bin/bash
ip route | grep '^default' | awk '{printf "%s",$3}'
