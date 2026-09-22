#!/bin/bash
scp skeleton.conf 2-panic.sh engineer@acme-gw01:/tmp/ && ssh -t engineer@acme-gw01 'chmod +x /tmp/2-panic.sh && /tmp/2-panic.sh && sudo nft -f /tmp/skeleton.conf && sudo nft list ruleset'
