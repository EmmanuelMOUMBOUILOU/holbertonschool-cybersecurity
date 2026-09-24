# ApexVault Security Design Document

## Executive Summary

ApexVault is designed around a **Zero-Trust and cryptographic separation** model. No user, administrator, or server process is trusted by default. Access must be strongly authenticated, explicitly authorized, and fully auditable.

The design removes passwords, prevents system administrators from decrypting client files, and sends security logs to an independent immutable logging platform so that compromise of the ApexVault server does not allow an attacker to erase evidence.

The core principles are:

- Phishing-resistant authentication
- Least privilege
- Separation of duties
- Client-side encryption
- Strong key protection
- Centralized immutable logging
- Non-repudiation and auditability

---

# 1. Authentication Strategy

## Selected Technology

**FIDO2 / WebAuthn hardware-backed authentication**

ApexVault users authenticate using FIDO2-compatible hardware security keys or hardware-backed passkeys.

For high-value VIP accounts, the preferred implementation is:

- A registered FIDO2 hardware token
- Local biometric or PIN verification on the trusted device/token
- No reusable password stored or transmitted to ApexVault

Passwords are completely disabled for client authentication.

## Justification

FIDO2 is selected because it provides **phishing-resistant authentication**.

Unlike passwords, a FIDO2 private key is never sent to the ApexVault server. The private key remains protected inside the user's hardware token or trusted device.

Authentication works through a cryptographic challenge-response process:

```text
ApexVault sends a challenge
        ↓
User confirms presence / biometric / PIN
        ↓
Hardware token signs the challenge
        ↓
ApexVault verifies the signature
```

The private authentication secret never leaves the authenticator.

### Why this is stronger than passwords

Passwords can be guessed, reused, stolen from databases, captured by phishing pages, exposed through credential stuffing, or shared accidentally.

FIDO2 credentials are bound to the legitimate service origin and are not reusable secrets that a user can type into a fraudulent website.

### Why this is stronger than SMS MFA

SMS-based authentication can be attacked through SIM swapping, social engineering, number-porting attacks, SMS interception, and phishing proxies.

FIDO2 provides stronger resistance because authentication is based on asymmetric cryptography and origin binding.

## Authentication Security Requirements

```text
Password authentication        DISABLED
FIDO2/WebAuthn                  REQUIRED
Hardware-backed credentials     REQUIRED for VIP accounts
Recovery procedure              CONTROLLED and audited
Credential registration         STRONGLY authenticated
```

Lost authenticators must be revoked immediately.

Recovery must never silently fall back to a password.

---

# 2. Authorization Model

## Model Selected

**Attribute-Based Access Control (ABAC)**

ABAC is selected because ApexVault requires fine-grained access decisions based on multiple attributes rather than only static user roles.

Authorization decisions may consider:

- User identity
- Client/account identifier
- Device trust level
- Resource ownership
- Requested operation
- Administrative role
- Authentication strength
- Network context
- Time or risk conditions

Example:

```text
IF
    user.client_id == file.owner_id
AND authentication_method == FIDO2
AND device_trust == approved
THEN
    allow file access
ELSE
    deny
```

A default-deny policy is applied.

## Admin Restriction

### Client-Side Encryption

All VIP client files are encrypted **before they are uploaded to ApexVault**.

The server stores only ciphertext.

```text
Client File
    ↓
Client-side encryption
    ↓
Encrypted File
    ↓
ApexVault Storage
```

The ApexVault server never receives the client's plaintext decryption key.

Therefore, even a root-level system administrator can manage the operating system, storage, and services but cannot decrypt VIP client files.

This creates cryptographic separation between:

```text
Infrastructure control
and
Data confidentiality
```

## Key Management

Each client receives a cryptographic identity and uses a hardware-backed key.

Recommended architecture:

- Client encryption keys are generated on the trusted client side
- Private keys remain inside a hardware-backed secure element where possible
- ApexVault stores only encrypted data and public metadata required for operation
- Server-side service keys are protected by an HSM
- No administrator has direct access to client private decryption keys

If recovery keys are required for business continuity, they must use a controlled multi-party recovery process, for example:

```text
2-of-3 approval
or
3-of-5 approval
```

rather than a single administrator-controlled master key.

## Defense Against Root Access

Traditional Unix permissions alone are not sufficient because root can normally bypass them.

Therefore ApexVault does **not** rely only on:

```text
chmod
ACLs
sudo
SELinux
```

These controls are still useful as defense in depth, but the primary protection is cryptographic.

Even if an attacker obtains root privileges on the storage server:

```text
Root access
    ↓
Can access ciphertext
    ↓
Cannot access client private keys
    ↓
Cannot decrypt VIP files
```

## Additional Authorization Controls

ApexVault should also enforce:

- Least privilege
- Default deny
- Short-lived access tokens
- Device-bound sessions
- Separation of administrative and client identities
- Explicit authorization checks for every object request
- Session re-authentication for sensitive operations

SELinux or another Mandatory Access Control mechanism should be used as an additional layer to restrict service processes.

---

# 3. Accounting Architecture

## Objective

The accounting architecture must make it impossible for an attacker who compromises the ApexVault application server to erase the authoritative audit trail.

This directly addresses the failure observed in the Bob incident, where stopping the local audit service destroyed reliable evidence for later actions.

## Storage Location

Logs must be transmitted in real time to a **centralized remote logging platform** that is separate from the ApexVault production server.

Recommended flow:

```text
ApexVault Server
      |
      | TLS-protected log forwarding
      v
Central Security Logging Platform
      |
      +--> SIEM
      |
      +--> Immutable / WORM Archive
```

The production server must not have permission to delete or modify records once they have been received by the central logging system.

## Logs to Collect

At minimum:

- Authentication attempts
- FIDO2 credential registration and revocation
- Authorization decisions
- File access
- Upload/download events
- Administrative actions
- Privilege escalation
- Configuration changes
- Key-management operations
- Failed access attempts
- Security-control failures
- Service startup/shutdown events

Each log record should contain:

```text
timestamp
user identity
device/session identity
source address
requested action
target resource
authorization result
event identifier
```

## Integrity Mechanism

ApexVault uses multiple mechanisms to protect audit integrity.

### 1. Remote Logging

Logs are transmitted immediately to infrastructure outside the control of the application host.

Compromise of the ApexVault server therefore does not automatically provide control over historical audit records.

### 2. Append-Only / WORM Storage

Long-term audit records are stored using immutable retention controls.

Once written, records cannot be modified or deleted until the retention period expires.

### 3. Cryptographic Integrity

Audit records should be protected using:

- Cryptographic hashes
- Hash chaining
- Digital signatures or authenticated log batches

Example concept:

```text
Hash(Log 1)
     ↓
Hash(Log 1 + Log 2)
     ↓
Hash(previous hash + Log 3)
```

Modification or deletion of an earlier event breaks the chain and becomes detectable.

### 4. Separation of Duties

Production administrators must not have administrative rights over the centralized audit platform.

Example:

```text
System Admin
    → manages ApexVault infrastructure

Security Team
    → manages SIEM / audit platform
```

This prevents a compromised infrastructure administrator account from deleting the evidence of its own actions.

## Availability of Logs

Audit logs must also remain available during an incident.

Controls include:

- Redundant log collectors
- Time synchronization
- Secure buffering if the log platform is temporarily unavailable
- Multiple storage copies
- Defined retention periods
- Monitoring for stopped or interrupted log forwarding

Failure to receive expected logs must itself generate an alert.

## Non-Repudiation

Accounting supports non-repudiation by creating reliable evidence that connects:

```text
Identity
+
Timestamp
+
Action
+
Resource
+
Result
```

Strong FIDO2 authentication improves confidence in identity, while immutable remote logging improves confidence in the recorded action.

Together they provide stronger evidence than a local log file that a privileged attacker could erase.

---

# Security Architecture Summary

ApexVault combines three complementary controls:

```text
AUTHENTICATION
FIDO2 / WebAuthn
        ↓
Strong phishing-resistant identity proof

AUTHORIZATION
ABAC + client-side encryption
        ↓
Least privilege and cryptographic data isolation

ACCOUNTING
Remote immutable logging
        ↓
Tamper-resistant audit trail and non-repudiation
```

The central design principle is that no single administrator, server, or control is trusted enough to compromise the complete system.

ApexVault therefore protects client data even if an infrastructure administrator account or an individual application server is compromised.
