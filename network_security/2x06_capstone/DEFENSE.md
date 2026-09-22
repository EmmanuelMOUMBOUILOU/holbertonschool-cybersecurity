# LogiCorp Security Architecture Defense

## Introduction

This document explains and defends the main engineering decisions made during the LogiCorp Network Security Capstone.

The proposed security architecture was designed around four priorities:

1. Reduce the attack surface.
2. Prevent lateral movement.
3. Preserve essential business operations.
4. Introduce stronger controls without creating an avoidable production outage.

The design follows a Zero-Trust approach based on default deny, least privilege, segmentation, authenticated remote access, and layered security controls.

---

## Challenge 1 — Risk Acceptance

### Challenge

> "You kept FTP running, even tunneled over VPN. FTP is inherently insecure. Why not force the client to upgrade to SFTP?"

### Business Constraint Analysis

The client explicitly stated that the Finance team currently depends on FTP for invoice transfers and that this workflow cannot be changed immediately because the existing software is legacy and too difficult to replace during the current remediation window.

From a purely technical security perspective, replacing FTP with SFTP or another encrypted protocol would be preferable.

However, the goal of this engagement is not only to improve security. It is also to maintain business continuity.

Immediately removing FTP would create a significant operational risk:

- Finance could lose the ability to transfer invoices.
- Business processes could be interrupted.
- The remediation itself could become more damaging to the client than the temporary risk being reduced.

For this reason, FTP is treated as an accepted legacy dependency rather than as an approved long-term protocol.

### Risk Mitigation Measures

The design reduces the FTP risk using compensating controls.

#### 1. No Direct Internet Exposure

FTP must not be accessible directly from the WAN.

The firewall policy blocks direct Internet access to TCP port 21.

Remote Finance users must first establish an authenticated WireGuard VPN connection.

The intended flow becomes:

```text
Finance User
    |
    | Encrypted WireGuard Tunnel
    v
LogiCorp Gateway
    |
    | Restricted FTP Flow
    v
Finance FTP Service
```

This prevents FTP credentials and file content from crossing the public Internet in cleartext.

#### 2. Anonymous FTP Disabled

The live audit confirmed that anonymous FTP access was enabled.

The hardening process disables anonymous authentication:

```text
anonymous_enable=NO
```

Only explicitly authorized Finance accounts should remain.

#### 3. Least-Privilege Access

Finance VPN users are assigned a restricted VPN address range and are only permitted to reach the required FTP service.

They do not automatically receive:

- SSH access
- Database access
- Administrative access
- Unrestricted LAN access

#### 4. Firewall Restrictions

The firewall limits FTP access to:

- Approved Finance VPN source addresses
- TCP port 21
- A defined passive FTP port range

All other FTP access is denied.

#### 5. Logging and Monitoring

FTP authentication and transfer activity should be logged and reviewed.

Security monitoring remains active so suspicious activity can be identified.

### Residual Risk

The residual risk is acknowledged.

FTP still lacks native confidentiality and modern transport protection.

Even when it is carried through an encrypted VPN tunnel, a compromised authorized Finance endpoint could still expose:

- FTP credentials
- Uploaded invoices
- Downloaded files
- Session content after decryption on the endpoint

The VPN therefore reduces the transport risk but does not transform FTP into a modern secure protocol.

### Phase 2 Recommendation

FTP should be considered a temporary exception.

The Phase 2 recommendation is to migrate the Finance workflow to one of the following:

- SFTP
- HTTPS-based secure file transfer
- Managed file transfer platform
- Another encrypted and authenticated modern protocol

The migration should include:

1. Application compatibility testing.
2. Finance user acceptance testing.
3. Parallel operation during transition.
4. A defined retirement date for FTP.
5. Formal removal of the FTP firewall exception after migration.

### Defense Summary

The decision was not to declare FTP secure.

The decision was to preserve a mandatory business process while reducing its exposure through:

```text
VPN encryption
+ source restrictions
+ segmentation
+ named accounts
+ default deny
+ monitoring
```

This is a controlled risk acceptance, not a permanent endorsement of FTP.

---

## Challenge 2 — Firewall Strategy

### Challenge

> "Explain your segmentation logic. How does it specifically prevent the lateral movement that caused the previous breach?"

### Security Problem

The previous breach succeeded because the environment was effectively flat.

Guest systems, internal users, Finance systems, and the critical database were not sufficiently isolated.

This meant that once an attacker compromised a less trusted device, they could move laterally toward more sensitive systems.

The redesign removes this implicit trust.

---

## Zone Definitions and Trust Levels

The target architecture separates systems into distinct security zones.

### WAN

Trust level: **Untrusted**

Contains:

- Internet-originated traffic
- Unknown external systems

Allowed access is extremely limited.

Typical permitted inbound traffic:

- WireGuard UDP/51820 only

Direct SSH and FTP access from the WAN are denied.

### VPN

Trust level: **Authenticated but restricted**

VPN users are authenticated, but VPN access does not imply unrestricted network trust.

Different VPN users receive different permissions.

Examples:

- Administrators may access approved management services.
- Finance users may access only the Finance FTP service.

### LAN

Trust level: **Internal but not fully trusted**

Corporate users are allowed only the services necessary for their roles.

LAN membership does not automatically grant access to the critical database.

### Finance

Trust level: **Restricted business zone**

Contains Finance systems and the temporary legacy FTP workflow.

Access is limited to approved Finance users and required business services.

### DMZ

Trust level: **Controlled / semi-trusted**

Contains services that may need controlled communication with other zones.

A DMZ host does not automatically receive access to internal or database systems.

### Database Zone

Trust level: **Critical**

This is the most sensitive zone.

Only explicitly approved systems may communicate with the database, and only on the confirmed application port.

### Guest

Trust level: **Low / Untrusted**

Guest devices are allowed Internet access only.

They cannot reach:

- LAN
- Finance
- DMZ management services
- Database systems

---

## Traffic Flow Restrictions

The firewall follows a default-deny policy.

The high-level policy is:

```text
INPUT   -> DROP
FORWARD -> DROP
OUTPUT  -> DROP
```

Only explicitly required flows are permitted.

Examples:

```text
WAN -> WireGuard UDP/51820                    ALLOW
WAN -> SSH                                    DENY
WAN -> FTP                                    DENY

VPN Admin -> Approved SSH targets             ALLOW
VPN Finance -> Finance FTP                    ALLOW

Guest -> Internet HTTP/HTTPS/DNS              ALLOW
Guest -> LAN                                  DENY
Guest -> Finance                              DENY
Guest -> Database                             DENY

Approved Application -> Database DB port      ALLOW
General LAN -> Database                       DENY
```

---

## How the Previous Attack Path Is Blocked

The documented previous attack path was:

```text
Compromised Guest Device
        |
        v
Flat Internal Network
        |
        v
Critical Database
```

In the new architecture:

```text
Compromised Guest Device
        |
        v
Guest Zone
        |
        X
Firewall Default Deny
        |
        X
Database Zone
```

The Guest network has no authorized route to the database.

Even if a Guest device is fully compromised, the attacker cannot simply scan and connect to the database because the firewall prevents that inter-zone traffic.

This converts the network from:

```text
connected = trusted
```

to:

```text
explicitly authorized = allowed
everything else = denied
```

---

## Rule Ordering

Rules are evaluated from specific and trusted state handling toward general denial.

The intended order is:

```text
1. Loopback
2. Established / Related
3. Invalid traffic -> DROP
4. Required infrastructure traffic
5. VPN entry
6. Approved administrative flows
7. Approved business flows
8. Segmentation denies
9. Security logging
10. Default DROP
```

This ordering prevents a broad allow rule from accidentally bypassing a more specific security restriction.

---

## Defense in Depth

Segmentation is not the only control.

The design applies multiple security layers.

### Layer 1 — VPN

Remote users must authenticate through WireGuard before reaching protected resources.

### Layer 2 — Firewall

The firewall decides which VPN users and internal zones may communicate.

### Layer 3 — SSH Hardening

SSH uses:

```text
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
```

### Layer 4 — Service Hardening

Examples include:

- Anonymous FTP disabled
- Unnecessary services stopped
- Suspicious cron persistence removed

### Layer 5 — Monitoring

Suricata and security logging provide detection capability.

### Layer 6 — Validation

Automated compliance checks verify that controls remain in place after changes.

---

## Defense Summary

The previous breach depended on unrestricted lateral movement.

The new design blocks that attack path because each zone has a defined trust level and inter-zone traffic is denied unless explicitly required.

Compromise of one device therefore does not automatically provide access to the rest of the environment.

---

## Challenge 3 — Resilience

### Challenge

> "The Gateway is still a Single Point of Failure. What happens if it goes down?"

### Scope Acknowledgment

This concern is valid.

The original technical specifications explicitly identified the gateway as a Single Point of Failure, while redundancy was marked as out of scope for the current engagement.

The current project therefore focuses on:

- Security hardening
- Segmentation
- Remote-access protection
- Firewall enforcement
- Monitoring
- Validation

It does not fully solve infrastructure availability.

---

## Current Risk Exposure

The centralized gateway performs several critical functions:

- Routing between zones
- Firewall enforcement
- VPN termination
- NAT
- Administrative access path
- Security boundary enforcement

If the gateway fails, the likely impact includes:

- Loss of Internet access
- Loss of VPN access
- Loss of inter-zone routing
- Loss of Finance remote FTP access
- Potential loss of access to critical services

The gateway therefore remains a high-impact infrastructure dependency.

---

## Why High Availability Was Not Implemented Immediately

Adding high availability is not simply a software switch.

A proper HA design may require:

- A second gateway
- Additional network interfaces
- Switch redundancy
- Shared or synchronized firewall state
- VPN failover
- Routing failover
- Additional IP addressing
- Configuration synchronization
- Monitoring
- Testing
- Operational procedures

Trying to introduce all of these changes during an emergency security remediation increases complexity and deployment risk.

The first priority was to stop the immediate security weaknesses that enabled the breach.

---

## Phase 2 High-Availability Plan

A future resilience phase should introduce a second gateway.

Example target architecture:

```text
                 Internet
                    |
             Redundant Upstream
                    |
          +---------+---------+
          |                   |
      Gateway A           Gateway B
      Active              Standby
          |                   |
          +---------+---------+
                    |
             Internal Zones
```

Possible technologies and controls include:

- VRRP / Keepalived for gateway failover
- Synchronized nftables configurations
- WireGuard configuration synchronization
- Configuration management
- Health checks
- Redundant switches where required
- Centralized logging outside the gateway
- Tested failover procedures

The architecture could use an active/passive model initially because it is simpler to operate and troubleshoot than a fully active/active gateway design.

---

## High-Level Phase 2 Sequence

1. Deploy a second hardened gateway.
2. Reproduce the security policy from the primary gateway.
3. Synchronize required configurations.
4. Configure a shared virtual gateway address.
5. Implement health monitoring.
6. Test controlled failover.
7. Test VPN recovery.
8. Test Finance workflow during failover.
9. Document operational procedures.
10. Perform scheduled resilience exercises.

---

## Cost-Benefit Analysis

### Current Phase Benefit

The current project delivers immediate security improvements at relatively low infrastructure cost:

- Prevents direct exposure of sensitive services
- Reduces lateral movement
- Introduces least privilege
- Improves remote access
- Adds automated validation

These controls address the direct causes and weaknesses associated with the recent incident.

### HA Phase Cost

High availability requires:

- Additional hardware or virtual infrastructure
- Additional network design
- Engineering time
- Testing time
- Operational monitoring
- Ongoing maintenance

### HA Phase Benefit

The benefits include:

- Reduced downtime
- Greater business continuity
- Safer maintenance windows
- Reduced dependency on one gateway
- Improved disaster recovery capability

For a logistics company whose operations depend on central infrastructure, the business impact of gateway failure can be significant.

Therefore, HA should be treated as a high-priority Phase 2 investment, even though it was outside the scope of the immediate remediation.

---

## Defense Summary

The Single Point of Failure remains a known residual risk.

It was not ignored; it was consciously deferred because redundancy was outside the approved scope and because the immediate priority was to close critical security gaps.

The recommended roadmap is:

```text
Phase 1
Security remediation
    |
    v
Segmentation + VPN + Firewall + Hardening
    |
    v
Stable secure baseline
    |
    v
Phase 2
High Availability + Redundancy
```

This approach reduces immediate security risk first, then improves resilience on top of a stable and documented architecture.

---

# Final Position

The LogiCorp design intentionally balances ideal security with operational reality.

The main engineering decisions are defensible because they follow these principles:

- **Do not break critical business operations.**
- **Reduce risk immediately where full replacement is not yet possible.**
- **Remove implicit trust between network zones.**
- **Use multiple security layers instead of relying on a single control.**
- **Preserve administrative access while hardening it.**
- **Acknowledge residual risks rather than hiding them.**
- **Separate immediate remediation from longer-term modernization.**

The result is not presented as a perfect final architecture.

It is a controlled transition from a vulnerable flat environment toward a Zero-Trust security model, with clearly documented residual risks and a defined Phase 2 roadmap.
