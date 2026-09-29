# Nexus Financial - Final Security Audit Report

## 1. Purpose

This report provides verification evidence for the security controls implemented
as part of the Nexus Financial defensive architecture.

Each control is evaluated using:

1. Verification Command
2. Expected Output
3. Self-Assessment

The audit covers system hardening, identity and access management, network
defense, centralized logging, auditing, and incident response readiness.

---

# 2. System Hardening Audit

## Control: SSH Root Login Disabled

### Verification Command

```bash
sshd -T | grep permitrootlogin