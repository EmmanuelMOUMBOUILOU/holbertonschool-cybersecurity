# Linux Capstone: Hardening Automation

## Description

This project implements a modular Linux hardening framework designed for Ubuntu 22.04 LTS.

The goal is to automate the transformation of a fresh Linux server into a hardened Bastion Host while enforcing security controls in an idempotent and maintainable way.

## Architecture

```text
hardening/
├── harden.sh
├── config/
│   └── harden.cfg
├── lib/
│   ├── network.sh
│   ├── ssh.sh
│   ├── identity.sh
│   └── system.sh
└── README.md
