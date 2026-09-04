#!/bin/bash

grep -rlF "password =" "$1" 2>/dev/null
