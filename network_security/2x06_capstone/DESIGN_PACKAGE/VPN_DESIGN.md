# LogiCorp VPN Design

## 1. Objective

Provide encrypted and authenticated remote access without exposing SSH or the legacy FTP workflow directly to the Internet.

WireGuard is selected because it is lightweight, uses modern cryptography, and fits the network-security tooling already used by the team.

---

## 2. Topology

```text
Remote Administrator
        |
        | WireGuard
        v
Internet / WAN
        |
        | UDP 51820 only
        v
LogiCorp Gateway
wg0: 10.200.0.1/24
        |
        +----> Management access (SSH) to approved systems
        |
        +----> Finance FTP service through the encrypted tunnel
```

Direct Internet access to TCP/22 and TCP/21 is not part of the target design.

---

## 3. Proposed Addressing

| Component | Address |
|---|---|
| WireGuard Gateway | `10.200.0.1/24` |
| Admin VPN pool | `10.200.0.10-10.200.0.49` |
| Finance VPN pool | `10.200.0.50-10.200.0.99` |
| Reserved/future | `10.200.0.100-10.200.0.254` |

Each user/device receives an individual WireGuard key pair and a fixed VPN address.

Private keys must never be shared between users.

---

## 4. Access Control

### Administrators

Administrators may access:

- SSH on the LogiCorp Gateway
- Explicitly approved management services
- Internal systems only where administration is required

Administrators do not automatically receive unrestricted access to every business subnet.

### Finance Users

Finance VPN users may access:

- The approved FTP service
- TCP/21
- The configured passive FTP port range

They must not receive general administrative access to the gateway or database.

### Other Remote Users

Remote users receive no internal access unless a business requirement is documented and approved.

---

## 5. Zero-Trust Principles

The VPN does not mean "trusted network."

WireGuard authenticates the device/user path, but the firewall still enforces:

- Source identity by VPN address
- Destination restrictions
- Service restrictions
- Least privilege
- Default deny between zones

A VPN client can therefore reach only the resources specifically assigned to its role.

---

## 6. Legacy FTP Handling

### Business Constraint

Finance currently depends on FTP and the application cannot be replaced immediately.

The audit confirmed that the existing FTP service:

- Uses cleartext transport
- Allows anonymous authentication
- Exposes Finance-related content

This state is unacceptable for direct Internet exposure.

### Tunneling Approach

The temporary design is:

```text
Finance user
   |
   | Encrypted WireGuard tunnel
   v
LogiCorp Gateway
   |
   | Restricted internal FTP flow
   v
Finance FTP service
```

FTP remains cleartext only inside the encrypted VPN path and controlled internal segment.

Required controls:

1. Disable anonymous FTP.
2. Use named Finance accounts.
3. Restrict FTP to VPN Finance source addresses.
4. Block direct WAN access to TCP/21.
5. Configure a narrow passive FTP port range and allow only that range.
6. Restrict filesystem permissions to the required Finance directory.
7. Log authentication and file-transfer activity.
8. Define a migration plan to SFTP/HTTPS or another modern transfer mechanism.

---

## 7. Risk Acceptance — Legacy FTP

### Accepted Temporary Risk

FTP itself does not provide confidentiality or strong transport security.

The business requires the legacy workflow to remain operational temporarily.

### Compensating Controls

The temporary risk is reduced through:

- WireGuard encryption
- Network segmentation
- Source IP restrictions
- Named accounts
- Anonymous access disabled
- Firewall default deny
- Logging and monitoring

### Residual Risk

A compromised authorized VPN endpoint could still expose FTP credentials or transferred data inside that endpoint.

### Required Business Decision

Management must formally accept this residual risk and approve a deadline for migration away from legacy FTP.

---

## 8. Key Management

- One key pair per user/device
- Private keys stored only on the client
- Public keys registered on the gateway
- Lost or compromised devices must have their peer removed immediately
- Keys must not be reused between staff
- Peer inventory must be maintained

---

## 9. VPN Validation

Before removing existing remote-access paths, verify:

1. WireGuard handshake succeeds.
2. Admin VPN client can SSH to the approved target.
3. Finance VPN client can access FTP.
4. Finance VPN client cannot access administrative SSH.
5. Guest and non-authorized networks cannot access the VPN-only services.
6. Direct Internet SSH and FTP are blocked only after VPN tests pass.
