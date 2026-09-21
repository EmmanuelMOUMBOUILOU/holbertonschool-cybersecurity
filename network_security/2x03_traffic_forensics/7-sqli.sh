#!/bin/bash
tshark -r "$1" -Y 'http.request.uri contains "UNION" || http.request.uri contains "SELECT" || http.request.uri contains "union" || http.request.uri contains "select"' -T fields -e http.request.uri
