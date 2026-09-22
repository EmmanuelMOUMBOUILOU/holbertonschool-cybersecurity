#!/bin/bash
dig +short A "$1" | grep -m1 -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
