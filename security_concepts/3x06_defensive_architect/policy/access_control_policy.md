# Nexus Financial Access Control Policy

## 1. Purpose

This policy defines the technical access control requirements for Nexus Financial
systems, production servers, databases, and internal networks.

The objective is to eliminate shared credentials, enforce individual accountability,
apply least privilege, and restrict network access without preventing authorized
employees from performing their duties.

## 2. Scope

This policy applies to all employees, contractors, administrators, developers,
servers, databases, administrative services, and production environments operated
by Nexus Financial.

## 3. Authentication

### 3.1 Individual Accounts

Every user must authenticate using an individually assigned account.

Shared user accounts and shared administrative credentials are prohibited.

The shared `nexus_master.pem` SSH key must be revoked and removed from all
authorized key stores.

Each administrator and developer requiring SSH access must use an individual
SSH key pair associated with their personal account.

### 3.2 SSH Authentication

Production Linux servers must use public-key authentication.

The SSH configuration must enforce:

`PermitRootLogin no`

`PasswordAuthentication no`

`PubkeyAuthentication yes`

Direct SSH login as `root` is prohibited.

Users must first authenticate with their individual account and use approved
privilege elevation mechanisms when administrative access is required.

### 3.3 SSH Key Management

Private SSH keys must never be shared through Slack, email, source code
repositories, shared folders, or other collaboration platforms.

Private keys must remain under the control of the individual user.

When an employee or contractor leaves Nexus Financial, their SSH public keys
must be removed from authorized systems.

Lost, exposed, or compromised keys must be revoked and replaced immediately.

### 3.4 Administrative Authentication

Administrative interfaces must not use weak or predictable credentials.

Default passwords and simple PIN codes such as `1975` are prohibited.

Administrative access should use strong authentication and MFA where supported.

## 4. Authorization

### 4.1 Least Privilege

Users must receive only the permissions required to perform their assigned duties.

Developers must not receive unrestricted `root` access by default.

### 4.2 Role-Based Access Control

Nexus Financial must implement Role-Based Access Control (RBAC).

Access must be assigned according to job responsibilities rather than convenience.

At minimum, the following roles must exist:

- `developers`: access required for application development and approved deployment tasks.
- `admins`: authorized system administration privileges.
- `auditors`: read-only access to security and audit information where required.

Users must be assigned to the appropriate Linux groups corresponding to their roles.

### 4.3 Privileged Access

Administrative commands must be performed through `sudo`.

Direct routine use of the `root` account is prohibited.

Only the `admins` role may receive broad administrative privileges.

Developers requiring specific privileged operations must receive explicit
command-level `sudo` permissions rather than unrestricted root access.

Privileged access must be attributable to an individual user.

### 4.4 Access Reviews

User accounts, group memberships, SSH keys, and privileged access must be
reviewed regularly.

Access that is no longer required must be removed.

Accounts belonging to departed employees and contractors must be disabled
or removed promptly.

## 5. Network Access Control

### 5.1 Default-Deny Principle

Production systems must follow a default-deny network policy.

Only network traffic explicitly required for business operations should be allowed.

Unnecessary services and ports must not be exposed to the Internet.

### 5.2 Production Database

The PostgreSQL production database on TCP port `5432` must not be exposed to
`0.0.0.0/0`.

Public Internet access to the production database must be blocked.

Port `5432` should accept connections only from explicitly authorized application
servers, administrative networks, or other approved trusted sources.

### 5.3 Remote Administrative Access

Remote administrative access must use an approved secure access path such as
the corporate VPN or another controlled administrative network.

SSH port `22` must not be unnecessarily exposed to untrusted networks.

Firewall rules should restrict SSH access to approved administrative sources.

### 5.4 Network Segmentation

Guest, employee, administrative, and production networks should be separated.

The Guest Wi-Fi network must not provide direct access to production servers,
administrative systems, or internal databases.

Production database systems should reside on a restricted network segment.

### 5.5 Firewall Enforcement

Host and network firewalls must enforce the access rules defined by this policy.

Firewall configuration must follow the principle:

`Default Deny -> Explicit Allow`

Rules must be limited to required sources, destinations, ports, and protocols.

## 6. Logging and Accountability

Authentication attempts, SSH access, `sudo` activity, privilege changes, and
administrative actions must be logged.

Security logs should be forwarded to a centralized logging system so that a local
system compromise cannot easily destroy all evidence.

Shared identities must not be used because actions must be attributable to a
specific individual.

## 7. Exceptions

Exceptions to this policy must be documented, justified by a business requirement,
risk-assessed, approved by authorized management, and reviewed regularly.

Temporary access must have an expiration date and must be removed when it is no
longer required.

## 8. Enforcement

Violations of this policy must be investigated and corrected.

Technical controls should automatically enforce this policy wherever possible.

Implementation scripts must be idempotent and safe to execute multiple times.

## 9. Technical Implementation Requirements

The technical implementation must be capable of automatically enforcing at least
the following requirements:

- Remove or revoke the shared `nexus_master.pem` access mechanism.
- Disable direct SSH root login.
- Disable SSH password authentication.
- Enable SSH public-key authentication.
- Create role-based Linux groups.
- Assign users to approved roles.
- Configure controlled `sudo` privileges.
- Apply default-deny firewall rules.
- Restrict PostgreSQL TCP port `5432` to authorized sources.
- Restrict SSH TCP port `22` to authorized administrative sources.
- Preserve authentication and privileged-access logs.

## 10. Policy Summary

Nexus Financial access control follows four principles:

1. Every person uses an individual identity.
2. Every identity receives only the privileges required for its role.
3. Every network connection is denied unless explicitly authorized.
4. Every privileged action must be attributable and auditable.