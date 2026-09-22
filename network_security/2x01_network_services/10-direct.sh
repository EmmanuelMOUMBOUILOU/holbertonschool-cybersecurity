#!/bin/bash
dig @$1 +short A "$2" | grep -m1 -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
