#!/bin/bash
tshark -r "$1" -T fields -e http.request.full_uri | grep -Ei 'UNION|SELECT|%55%4E%49%4F%4E|%53%45%4C%45%43%54'
