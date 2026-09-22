# LogiCorp Implementation Plan

## 1. Objective

Deploy the Zero-Trust design without locking administrators out or interrupting critical Finance operations.

The implementation must be incremental, tested after every stage, and reversible.

---

## 2. Pre-Change Requirements

Before making any production change:

1. Confirm an approved maintenance window.
2. Maintain at least one existing administrative session.
3. Record current interfaces, routes, services, SSH configuration, FTP configuration, and firewall state.
4. Back up all files that will be modified.
5. Prepare rollback commands before applying changes.
6. Define validation tests for SSH, VPN, FTP, DNS, Internet access, and database connectivity.
7. Notify Finance and system owners of the test window.

Suggested configuration backups:

```text
/etc/ssh/sshd_config
/etc/vsftpd.conf
/etc/nftables.conf
/etc/wireguard/
```

---

## 3. Phase 1 — Remove Immediate Dangerous Configuration

### Actions

- Disable anonymous FTP access.
- Remove or disable the suspicious `/etc/cron.d/logicorp` task after evidence is preserved.
- Review unnecessary management services.
- Preserve audit evidence and logs.

### Validation

- Required Finance authenticated FTP access still works.
- No unexpected service outage occurs.

### Rollback

Restore the backed-up service configuration and restart only the affected service.

---

## 4. Phase 2 — Deploy WireGuard Before Restricting SSH

### Actions

1. Install/configure WireGuard.
2. Configure gateway address `10.200.0.1/24`.
3. Add individual administrator and Finance peers.
4. Permit UDP/51820 on the WAN boundary.
5. Keep the existing SSH path temporarily available during testing.

### Validation

- Confirm VPN handshake.
- Confirm admin can reach SSH through `wg0`.
- Confirm Finance client reaches only required FTP resources.

### Rollback

Disable the WireGuard interface and restore the previous routing/firewall snapshot. Existing SSH remains available because it has not yet been removed.

---

## 5. Phase 3 — Introduce Network Segmentation

### Actions

Create logical zones/VLANs for:

- LAN
- Finance
- Database
- DMZ
- Guest

Where possible, use VLANs/subinterfaces so the design does not require an immediate physical redesign.

Migrate one zone at a time.

### Validation

After each zone migration verify:

- Addressing
- Gateway reachability
- DNS
- Required application access
- Prohibited lateral access

### Rollback

Return affected hosts/switch ports to their previous VLAN/subnet and restore the previous route configuration.

---

## 6. Phase 4 — Stage the Firewall

### Safety Procedure

Before applying the final ruleset:

1. Export the current nftables ruleset.
2. Prepare a known-good rollback file.
3. Keep a root/local console or second administrative session available.
4. Schedule or prepare an automatic rollback before loading restrictive rules.
5. Apply the new policy.
6. Test immediately.
7. Cancel the rollback only after successful validation.

### Initial Rule Deployment

Apply rules in this order:

1. Loopback
2. Established/related
3. WireGuard UDP/51820
4. Temporary existing management access
5. VPN administrative access
6. Finance FTP tunnel access
7. Required LAN/Database business flows
8. Guest Internet-only flow
9. Segmentation denies
10. Logging
11. Default deny

### Rollback

Restore the saved nftables configuration from the local console or automatic rollback mechanism.

---

## 7. Phase 5 — Harden SSH

Only after VPN administration has been validated:

```text
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AllowUsers student
```

Restrict TCP/22 at the firewall to the approved VPN administrator addresses.

### Validation

- New SSH connection through VPN succeeds using keys.
- Root login fails.
- Password login fails.
- Direct WAN SSH fails.

Do not close the existing administrative session until all tests pass.

### Rollback

Restore the previous `sshd_config` backup from the still-open session/local console and reload SSH.

---

## 8. Phase 6 — Secure the Legacy FTP Workflow

### Actions

- Disable anonymous access.
- Create/retain named Finance accounts only.
- Restrict TCP/21 and passive FTP ports to the Finance VPN pool.
- Block WAN FTP.
- Restrict the FTP filesystem to the required Finance directory.
- Enable transfer/authentication logging.
- Document the migration deadline to a modern protocol.

### Validation

- Authorized Finance VPN client can authenticate and transfer a test file.
- Anonymous login fails.
- Non-Finance VPN client fails.
- WAN access fails.
- Finance user cannot escape the intended directory.

### Rollback

Restore the previous FTP configuration only if required for business continuity, then immediately reapply network isolation while the issue is corrected.

---

## 9. Phase 7 — Protect the Database

### Actions

- Place the database in its dedicated security zone.
- Allow only the application systems that require database access.
- Permit only the confirmed database application port.
- Deny Guest, general VPN users, and DMZ systems unless explicitly required.

### Validation

- Approved application transaction succeeds.
- Guest-to-database test fails.
- Unauthorized LAN-to-database test fails.
- Logging records denied attempts.

### Rollback

Return the database interface/VLAN and firewall entries to the previously validated state.

---

## 10. Phase 8 — Monitoring and Final Validation

### Actions

- Keep Suricata active.
- Enable firewall deny logging with rate limiting.
- Review SSH and FTP authentication logs.
- Validate that the suspicious cron beacon is no longer active.
- Confirm all required services after reboot/reload where applicable.

### Mandatory Tests

```text
VPN handshake                PASS / FAIL
Admin SSH through VPN        PASS / FAIL
Direct WAN SSH blocked       PASS / FAIL
Finance FTP through VPN      PASS / FAIL
Anonymous FTP blocked        PASS / FAIL
Direct WAN FTP blocked       PASS / FAIL
Guest -> Database blocked    PASS / FAIL
Guest -> LAN blocked         PASS / FAIL
Approved app -> DB works     PASS / FAIL
Suricata/logging operational PASS / FAIL
```

---

## 11. Production Cutover Principle

Never remove the old access path before the replacement path has been successfully tested.

The deployment order is therefore:

```text
Backup
   ->
Deploy VPN
   ->
Test VPN
   ->
Create segmentation
   ->
Stage firewall
   ->
Validate
   ->
Restrict SSH
   ->
Restrict FTP
   ->
Protect database
   ->
Final validation
   ->
Remove temporary compatibility rules
```

---

## 12. Final Rollback Strategy

A full rollback package must contain:

- Previous firewall ruleset
- Previous SSH configuration
- Previous FTP configuration
- Previous network/VLAN configuration
- WireGuard disable procedure
- Contact list for affected business owners

If a critical production service fails and cannot be corrected inside the approved window, restore the last known-good configuration, preserve logs, document the failure, and reschedule the change.
