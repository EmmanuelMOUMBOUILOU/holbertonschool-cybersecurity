# LogiCorp Firewall Policy

## 1. Objective

This policy defines the target firewall behavior for the LogiCorp Gateway using Zero-Trust principles:

- Default deny
- Least privilege
- Explicitly authorized traffic only
- Stateful filtering
- Administrative access through the VPN only
- Isolation of Guest, Finance, DMZ, and Critical Database resources

The policy is designed from the Gap Analysis and Technical Audit findings.

---

## 2. Security Zones

| Zone | Proposed Network | Purpose |
|---|---|---|
| WAN | Existing Internet-facing interface | Untrusted Internet |
| LAN | `192.168.10.0/24` | Internal corporate users |
| FINANCE | `192.168.20.0/24` | Finance workstations and legacy workflow |
| DATABASE | `192.168.30.0/24` | Critical database systems |
| DMZ | `192.168.40.0/24` | Services requiring controlled cross-zone access |
| GUEST | `192.168.50.0/24` | Guest WiFi; Internet-only access |
| VPN | `10.200.0.0/24` | Authenticated remote access |

The exact VLAN IDs and physical/sub-interface mapping must be confirmed during implementation.

---

## 3. Default Policies

Target nftables policies:

```text
INPUT   -> DROP
FORWARD -> DROP
OUTPUT  -> DROP
```

All required traffic must be explicitly allowed.

During staged deployment, OUTPUT may temporarily remain ACCEPT until the gateway's required outbound dependencies have been validated.

---

## 4. Global Rules

Rules are processed from most specific to most general.

1. Accept loopback traffic.
2. Accept `established,related` connections.
3. Drop `invalid` connections.
4. Permit required ICMP/ICMPv6 for diagnostics and correct network operation.
5. Apply zone-specific rules.
6. Log selected denied traffic with rate limiting.
7. Final implicit/default DROP.

This ordering prevents a broad allow rule from bypassing a more specific deny or segmentation control.

---

## 5. INPUT Policy — Traffic to the Gateway

| Source | Destination | Service | Action | Justification |
|---|---|---|---|---|
| Any established connection | Gateway | Established/related | ALLOW | Preserve legitimate sessions |
| Loopback | Gateway | Any | ALLOW | Local system operation |
| WAN | Gateway | UDP/51820 | ALLOW | WireGuard VPN entry point |
| VPN Admin clients | Gateway | TCP/22 | ALLOW | SSH administration only after VPN authentication |
| Authorized monitoring sources | Gateway | Required monitoring ports | ALLOW | Security operations |
| WAN | Gateway | TCP/22 | DENY | No direct Internet SSH |
| WAN | Gateway | TCP/21 | DENY | No direct Internet FTP |
| Any other source | Gateway | Any | DENY | Default deny |

Root SSH login and password authentication must also be disabled at the SSH service layer.

---

## 6. FORWARD Policy — Traffic Between Zones

### VPN Administration

| Source | Destination | Service | Action |
|---|---|---|---|
| VPN Admin clients | Gateway / approved management targets | SSH | ALLOW |
| VPN Admin clients | Other internal systems | Only explicitly approved management services | ALLOW |
| VPN non-admin clients | Management services | Any | DENY |

### Finance Legacy FTP

| Source | Destination | Service | Action |
|---|---|---|---|
| Authorized Finance VPN clients | Finance FTP service | TCP/21 | ALLOW |
| Authorized Finance VPN clients | Finance FTP service | Configured passive FTP range | ALLOW |
| WAN directly | Finance FTP service | FTP | DENY |
| Guest / general LAN | Finance FTP service | FTP | DENY unless business-approved |

FTP is permitted only inside the encrypted VPN path. The cleartext FTP session must never be exposed directly to the Internet.

### LAN and Database

| Source | Destination | Service | Action |
|---|---|---|---|
| Approved application systems | Database zone | Application-specific DB port | ALLOW after validation |
| General LAN | Database zone | Any other traffic | DENY |
| Guest | Database zone | Any | DENY |
| DMZ | Database zone | Any | DENY unless explicitly required |
| Database zone | Internet | Only validated update/DNS/NTP dependencies | ALLOW |
| Database zone | Other internal zones | Any unapproved traffic | DENY |

The exact database service port must be confirmed before implementation. It must not be guessed.

### Guest Network

| Source | Destination | Service | Action |
|---|---|---|---|
| Guest | Internet | DNS to approved resolver, HTTP/HTTPS | ALLOW |
| Guest | LAN | Any | DENY |
| Guest | Finance | Any | DENY |
| Guest | Database | Any | DENY |
| Guest | DMZ management services | Any | DENY |

This directly addresses the lateral-movement path involved in the previous incident.

### General LAN Egress

Allow only required business egress such as:

- DNS to approved resolver(s)
- NTP to approved time source(s)
- HTTP/HTTPS as required
- Explicitly approved application destinations

Everything else remains denied.

---

## 7. OUTPUT Policy — Traffic Originating From the Gateway

The final target is default DROP with explicit allowances for:

- Loopback
- Established/related traffic
- DNS to approved resolver(s)
- NTP
- HTTP/HTTPS required for approved software updates
- VPN responses
- Approved logging/monitoring destinations

Unexpected outbound connections, including recurring root-owned HTTP requests such as the audited cron beacon, must not be allowed without documented justification.

---

## 8. Logging Policy

Log security-relevant denies with rate limiting, including:

- WAN attempts to SSH or FTP
- Guest attempts to reach internal zones
- Unauthorized attempts to access the database
- Unauthorized VPN-to-management traffic
- Unexpected outbound traffic from the gateway

Logging must not be so verbose that it creates a denial-of-service condition or fills the disk.

---

## 9. Rule Ordering Rationale

Recommended high-level order:

```text
1. loopback
2. established/related
3. invalid drop
4. required infrastructure traffic
5. VPN entry
6. explicit administrative allows
7. explicit business-flow allows
8. segmentation denies
9. logging
10. default drop
```

Specific rules must appear before broad rules. This prevents trusted-source rules from accidentally overriding controls protecting sensitive destinations.

---

## 10. Validation Criteria

The firewall policy is considered successful when:

- Internet users cannot directly reach SSH or FTP.
- VPN administrators can reach approved management services.
- Finance users can use the required FTP workflow only through the VPN.
- Guest systems cannot reach LAN, Finance, DMZ management, or Database zones.
- Only approved systems can reach the database service.
- Existing legitimate sessions survive the staged deployment.
- Denied traffic is visible in logs.
