# LogiCorp Technical Audit Report

## 1. Executive Summary

A live technical audit of the LogiCorp Gateway identified several high-risk weaknesses that confirm many concerns raised during the documentation review. The most significant findings are an unencrypted and anonymously accessible FTP service, weak remote-access configuration, a disabled firewall policy, and a suspicious root cron job that performs recurring outbound HTTP requests.

The audit also identified active monitoring through Suricata, but the current security posture remains insufficient to prevent lateral movement, credential exposure, or unauthorized access. The findings below are based on direct observation of the live lab environment.

---

## 2. System Information

- **Hostname:** `d1804b3194494c92a5e2d8f9305ccd97-2377118072`
- **Operating System:** Ubuntu 22.04.5 LTS (Jammy Jellyfish)
- **Kernel:** Linux 6.1.182 x86_64
- **Observed uptime during audit:** approximately 11 minutes
- **Init environment:** systemd is not running as PID 1; PID 1 is a shell-based lab startup process

### Observation

The target is implemented as a containerized lab environment rather than a conventional systemd-based Ubuntu server. This affects how services and firewall controls can be inspected.

---

## 3. Network Topology

### Interfaces

| Interface | State | Address |
|---|---|---|
| `lo` | UNKNOWN | `127.0.0.1/8`, `::1/128` |
| `eth0` | UP | `169.254.172.2/22` |
| `eth1` | UP | `10.42.226.134/16` |

### Routing

- Default route: `10.42.0.1` via `eth1`
- Connected network: `10.42.0.0/16`
- Link-local/container route present through `eth0`

### Neighbor Information

The gateway `10.42.0.1` was visible as a reachable neighbor on `eth1`.

### Assessment

The observed interface addressing does not match the documented flat `192.168.1.x` network. However, internal lab artifacts still reference `192.168.1.x`, including a recurring connection to `192.168.1.200` and simulated authentication activity involving `192.168.1.99`. This confirms that documentation and the live runtime environment are not identical and must not be treated as interchangeable.

---

## 4. Attack Surface

The following TCP listeners were observed:

| Protocol | Listening Address | Port | Service / Process | Security Observation |
|---|---|---:|---|---|
| TCP | `*:21` | 21 | `vsftpd` | FTP exposed; anonymous login and cleartext transport confirmed |
| TCP | `0.0.0.0:22`, `[::]:22` | 22 | `sshd` | SSH listens on all IPv4 and IPv6 interfaces |
| TCP | `0.0.0.0:3000` | 3000 | OpenVSCode Server / Node.js | Web-based management service exposed on all IPv4 interfaces |
| TCP | `0.0.0.0:3001` | 3001 | `ttyd` | Web terminal exposed on all IPv4 interfaces and protected only by Basic authentication |

No UDP listening sockets were shown by `ss -tuln`.

### Management Services

Port `3001` returned HTTP `401 Unauthorized` with a `ttyd` server header and HTTP Basic authentication. The running process showed that `ttyd` launches `/bin/bash` as root.

Port `3000` is associated with OpenVSCode Server and returned `Forbidden` when queried locally without its connection token.

These services appear to be part of the lab runtime, but they remain part of the observable attack surface and should be clearly distinguished from production business services.

---

## 5. Security Controls

### Firewall

The lab startup script contains:

```bash
nft flush ruleset 2>/dev/null
```

This explicitly removes nftables rules during startup.

Direct execution of `nft list ruleset` returned an operation-permitted error despite a root shell, indicating that the container does not expose the required kernel/network administration capability. The `iptables` command is not installed.

Therefore, the live ruleset could not be queried directly, but the startup configuration explicitly confirms that nftables rules are flushed.

### IDS / Monitoring

The service audit showed:

- `suricata` — active
- `fail2ban` — inactive

Suricata logging is present under `/var/log/suricata/`.

The startup script also creates simulated authentication and IDS events for the exercise. These entries must be treated as lab evidence rather than real historical production incidents.

### SELinux / AppArmor

No conclusive SELinux/AppArmor status output was captured during the audit. No unsupported conclusion is made about their effective state.

---

## 6. User Accounts and Privileged Access

### Interactive Accounts

The main interactive accounts observed were:

- `root` — UID 0, shell `/bin/bash`
- `student` — UID 1000, shell `/bin/bash`

Several service accounts are also present, including `ftp`, `sshd`, and `telnetd`.

### Sudo

The `sudo` group contains no members.

The `student` account does not have passwordless sudo access. A `sudo -n -l` test returned:

```text
sudo: a password is required
```

The sudoers configuration contains standard root/admin/sudo group rules. An additional debug configuration only preserves the `DEBUG` environment variable.

### SSH Keys

An `authorized_keys` file exists for the `student` account.

No root `authorized_keys` file was identified during the performed search.

### SSH Configuration

The SSH configuration contains:

```text
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
AllowUsers student
```

This configuration is internally inconsistent from a hardening perspective. `PermitRootLogin yes` and password authentication are insecure settings, while `AllowUsers student` restricts SSH access to the `student` account and therefore limits effective root SSH access under the observed configuration.

The recommended target state is still to set `PermitRootLogin no` and disable password authentication explicitly rather than relying only on `AllowUsers`.

---

## 7. FTP Security Assessment

The `vsftpd` service is active and listening on TCP port 21.

Relevant configuration includes:

```text
local_enable=YES
write_enable=YES
ssl_enable=NO
anonymous_enable=YES
```

Although the configuration file contains an earlier `anonymous_enable=NO`, a later `anonymous_enable=YES` is present and the effective behavior was verified directly.

### Functional Test

An anonymous FTP connection succeeded:

```text
230 Login successful.
```

The anonymous user was able to list the FTP directory, which contained:

```text
readme.txt
```

The file contains:

```text
Finance invoices here
```

### Risk

This confirms that:

1. FTP is active.
2. TLS is disabled.
3. Anonymous authentication is enabled.
4. A Finance-related directory is accessible anonymously.

This represents a **Critical** confidentiality and access-control risk.

---

## 8. Running Services

The following service states were observed:

| Service | State | Observation |
|---|---|---|
| `cron` | Active | Executes scheduled tasks |
| `ssh` | Active | Remote administration |
| `suricata` | Active | IDS / monitoring |
| `vsftpd` | Active | Cleartext FTP service |
| `fail2ban` | Inactive | No active brute-force blocking through this service |
| `openbsd-inetd` | Inactive | No active inetd-managed service observed |

Additional runtime processes include `ttyd`, OpenVSCode Server, and Node.js processes used by the lab environment.

---

## 9. Scheduled Tasks

Standard system cron jobs were present in `/etc/crontab`.

A custom file was found at:

```text
/etc/cron.d/logicorp
```

It contains a root-owned job that executes every minute:

```text
* * * * * root /usr/bin/curl http://192.168.1.200/ping
```

### Risk

This is an unexpected recurring outbound HTTP connection executed as root. In a real environment, this behavior would require immediate investigation because it resembles persistence or beaconing activity.

The associated audit flag identifies the task as a cron backdoor.

---

## 10. Documentation vs. Reality

| Documentation / Assumption | Live Audit Result | Assessment |
|---|---|---|
| Flat network documented as `192.168.1.x` | Runtime interface is `10.42.226.134/16`; internal artifacts still reference `192.168.1.x` | Documentation does not fully match the live environment |
| FTP required for Finance | `vsftpd` is active on TCP/21 | Confirmed |
| FTP is insecure | `ssl_enable=NO`; anonymous login succeeds | Confirmed and worse than documented |
| SSH exposed | SSH listens on all IPv4 and IPv6 interfaces | Broad listener confirmed |
| Root SSH enabled | `PermitRootLogin yes`, but `AllowUsers student` is also configured | Insecure directive present, but effective access is partially constrained |
| No firewall active | Startup script explicitly flushes nftables rules | Confirmed by startup configuration |
| No monitoring documented | Suricata is active | Documentation incomplete; IDS is present |
| Legacy/insecure services may exist | `telnetd` account exists, but no active Telnet listener was observed | Account exists; active service not confirmed |
| Production-like Linux gateway | Environment is containerized and not systemd-based | Runtime differs from a conventional server |

---

## 11. Security Findings and Risk Matrix

| Finding | Severity | Evidence | Impact |
|---|---|---|---|
| Anonymous cleartext FTP for Finance data | **Critical** | TCP/21, `ssl_enable=NO`, anonymous login successful | Credential/data exposure and unauthorized file access |
| Firewall rules flushed at startup | **Critical** | `/etc/run.sh` executes `nft flush ruleset` | Loss of network access control and segmentation enforcement |
| Suspicious root cron beacon/backdoor | **Critical** | `/etc/cron.d/logicorp` calls `192.168.1.200/ping` every minute | Persistence, command-and-control style behavior, unauthorized outbound traffic |
| Weak SSH hardening | **High** | `PermitRootLogin yes`, `PasswordAuthentication yes` | Increased risk of password-based attack and administrative compromise |
| Root web terminal exposed on TCP/3001 | **High** | `ttyd` runs `/bin/bash` as root on `0.0.0.0:3001` | High-impact administrative access if credentials are compromised |
| OpenVSCode service exposed on TCP/3000 | **Medium** | Listener and OpenVSCode process | Additional management attack surface |
| Fail2ban inactive | **Medium** | Service state | Reduced resistance to repeated authentication attacks |
| Documentation mismatch | **Medium** | Live network differs from documented addressing | Incorrect security decisions if documentation is trusted blindly |
| Suricata active | **Positive Control** | Active service and IDS log | Detection capability exists, though prevention remains weak |

---

## 12. Preliminary Remediation Priorities

1. Restore a default-deny firewall policy and explicitly allow only required flows.
2. Segment the network into trusted, guest, Finance, DMZ, and critical database zones.
3. Remove anonymous FTP access immediately.
4. Protect the legacy Finance transfer workflow through a restricted network path and migrate away from cleartext FTP when possible.
5. Set `PermitRootLogin no` and disable SSH password authentication after validating key-based access.
6. Restrict SSH to an administrative VPN or management subnet.
7. Remove or investigate the `/etc/cron.d/logicorp` recurring root HTTP request.
8. Restrict or remove unnecessary web-based management interfaces such as `ttyd` and OpenVSCode from production-facing networks.
9. Keep Suricata enabled and integrate its alerts into an operational monitoring process.
10. Validate all changes before production deployment to avoid breaking the Finance workflow or legitimate remote administration.

---

## 13. Conclusion

The live audit confirms that LogiCorp's gateway has multiple security weaknesses capable of enabling unauthorized access, data exposure, and persistence.

The most urgent issues are the lack of effective firewall enforcement, anonymously accessible cleartext FTP, weak remote-access hardening, and the recurring root cron task. The audit also demonstrates why live verification is essential: several aspects of the runtime environment differ from the client documentation.

These findings should now be used as the factual basis for the architecture design and remediation phases of the capstone.
