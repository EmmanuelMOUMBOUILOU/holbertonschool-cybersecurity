#!/bin/bash
ip route | awk '$1=="default" {printf "%s",$3; exit}'
