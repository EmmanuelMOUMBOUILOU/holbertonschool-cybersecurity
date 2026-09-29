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

## Control: SSH and Login Security

### Verification Command

```bash
grep PermitRootLogin /etc/ssh/sshd_config
grep PasswordAuthentication /etc/ssh/sshd_config
grep PubkeyAuthentication /etc/ssh/sshd_config
cat /etc/login.defs | grep PASS
sshd -T | grep permitrootlogin
sshd -T | grep passwordauthentication
sshd -T | grep pubkeyauthentication
```

### Expected Output

The SSH configuration should enforce the following security settings:

```text
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
```

The effective SSH configuration should include:

```text
permitrootlogin no
passwordauthentication no
pubkeyauthentication yes
```

The login policy command should display the configured password policy parameters
from `/etc/login.defs`, including values beginning with `PASS`.

### Self-Assessment

PASS - Direct SSH login as root is disabled.

PASS - SSH password authentication is disabled.

PASS - Public-key authentication is enabled.

PASS - The system login policy can be reviewed through `/etc/login.defs`.

These controls reduce unauthorized administrative access and strengthen the
server security baseline.

---

# 3. Identity and Access Management Audit

## Control: RBAC and Least Privilege

### Verification Command

```bash
getent group devs
getent group ops
getent group auditors
id sarah
id dave
sudo -l -U sarah
sudo -l -U dave
ls -la /home/
stat -c "%a %U %G %n" /home/sarah /home/opsuser /home/dave
```

### Expected Output

The RBAC groups must exist:

```text
devs:x:<GID>:sarah
ops:x:<GID>:opsuser
auditors:x:<GID>:dave
```

Sarah must belong to the `devs` group and must only receive the approved
Nginx sudo permissions, including:

```text
/bin/systemctl restart nginx
/bin/systemctl status nginx
```

Dave must belong to the `auditors` group and must not have unrestricted
administrative sudo privileges.

The home directories must have strict permissions such as:

```text
700 sarah sarah /home/sarah
700 opsuser opsuser /home/opsuser
700 dave dave /home/dave
```

### Self-Assessment

PASS - The RBAC implementation creates separate development, operations, and
auditing roles.

Sarah can perform the required Nginx operations without receiving unrestricted
root access.

Dave receives auditing access without general administrative privileges,
supporting separation of duties.

User home directories are protected with strict permissions.

The implementation therefore applies Role-Based Access Control, least privilege,
individual accountability, and separation of duties.

---

---

# 4. Network Defense Audit

## Control: UFW Firewall and Network Segmentation

### Verification Command

```bash
ufw status verbose
ufw status numbered
ss -tlnp | grep 5432
ss -tlnp | grep ':22'
```

### Expected Output

The UFW firewall must be active and enforce a default-deny policy:

```text
Status: active
Default: deny (incoming), allow (outgoing)
```

PostgreSQL TCP port 5432 must not be accessible from the public Internet.

The firewall rules should allow PostgreSQL only from the approved Web Server
private IP:

```text
5432/tcp ALLOW IN 10.0.1.10
```

SSH TCP port 22 must be restricted to the approved Bastion Host:

```text
22/tcp ALLOW IN 10.0.1.5
```

No rule should allow PostgreSQL port 5432 or SSH port 22 from arbitrary public
sources.

The `ss` commands should confirm which local services are listening on ports
5432 and 22 so that their exposure can be compared with the UFW rules.

### Self-Assessment

PASS - UFW is enabled with a default-deny incoming policy.

PASS - PostgreSQL port 5432 is restricted to the approved Web Server private IP.

PASS - SSH port 22 is restricted to the approved Bastion Host.

PASS - Public access to sensitive administrative and database services is blocked.

These controls implement network least privilege and reduce unnecessary exposure
of critical Nexus Financial services.