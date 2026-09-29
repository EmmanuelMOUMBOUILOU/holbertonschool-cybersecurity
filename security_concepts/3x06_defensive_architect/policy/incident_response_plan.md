# Nexus Financial Incident Response Playbook

## Scenario: Compromised Database

## 1. Purpose

This playbook defines the actions Nexus Financial personnel must take when the
production database is suspected or confirmed to be compromised.

The objectives are to protect customer and financial data, contain the attacker,
preserve evidence, restore secure operations, and prevent recurrence.

The response process follows five phases:

1. Identification
2. Containment
3. Eradication
4. Recovery
5. Lessons Learned

## 2. Roles and Responsibilities

### Incident Commander

The Incident Commander coordinates the response, records major decisions,
assigns actions, and determines when the incident moves between phases.

### Operations Team

The Operations team performs system isolation, firewall changes, credential
revocation, recovery actions, and infrastructure validation.

### Development Team

The Development team assists with application analysis, database dependencies,
application credentials, and validation after recovery.

### Security and Audit Personnel

Security personnel preserve evidence, analyze logs, identify indicators of
compromise, determine the scope of the incident, and maintain the incident
timeline.

---

# Phase 1 - Identification

## Objective

Confirm whether the database has been compromised and determine the initial
scope of the incident.

## Actions

1. Open an incident ticket and record the date, time, reporter, affected system,
   and initial symptoms.

2. Treat unexpected database connections, unauthorized accounts, unusual queries,
   unexplained data modifications, suspicious authentication activity, or abnormal
   outbound connections as potential indicators of compromise.

3. Review centralized rsyslog records for authentication, system, firewall, and
   application events.

4. Review auditd logs for modifications to sensitive files and privileged command
   execution.

5. Review PostgreSQL logs for suspicious logins, failed authentication attempts,
   unexpected queries, privilege changes, and unusual client IP addresses.

6. Identify the affected database server, accounts, applications, and network
   connections.

7. Record all discovered indicators of compromise, including suspicious IP
   addresses, usernames, processes, files, timestamps, and network connections.

8. Preserve relevant evidence before making unnecessary changes to the affected
   system.

9. Record cryptographic hashes of collected evidence where appropriate to help
   demonstrate evidence integrity.

## Decision Point

If the evidence indicates unauthorized database access or modification, declare
a security incident and immediately begin containment.

---

# Phase 2 - Containment

## Objective

Stop unauthorized access while preserving evidence and limiting disruption to
business operations.

## Immediate Containment

1. Restrict network access to the compromised database server.

2. Remove unauthorized firewall rules and ensure PostgreSQL TCP port 5432 is not
   accessible from the public Internet.

3. Allow database access only from explicitly authorized systems such as the
   approved Web Server private IP.

4. Block identified malicious source IP addresses.

5. Revoke compromised database credentials, SSH keys, API keys, tokens, and
   other affected secrets.

6. Disable unauthorized or suspicious user accounts.

7. Preserve centralized logs and audit records.

8. Do not immediately power off or reboot the compromised server unless required
   for safety or containment.

9. If necessary, isolate the database server from untrusted networks while
   maintaining controlled access for incident responders.

## Evidence Preservation

Before deleting malicious files or making major changes:

- Record timestamps.
- Record active processes.
- Record active network connections.
- Record logged-in users.
- Preserve relevant logs.
- Preserve suspicious files when safe to do so.
- Calculate cryptographic hashes of collected evidence.

All actions taken during containment must be documented in the incident timeline.

---

# Phase 3 - Eradication

## Objective

Remove the attacker's access, persistence mechanisms, and root cause of the
compromise.

## Actions

1. Identify the initial attack vector.

2. Remove unauthorized accounts, SSH keys, scheduled jobs, services, files, and
   other persistence mechanisms.

3. Remove malicious software or unauthorized tools discovered during the
   investigation.

4. Rotate all credentials and secrets that may have been exposed.

5. Remove the shared `nexus_master.pem` SSH access mechanism if it is still
   present anywhere in the environment.

6. Verify that direct root SSH login is disabled.

7. Verify that SSH password authentication is disabled.

8. Verify that production database port 5432 is restricted to authorized private
   sources.

9. Apply required operating system, application, and database security updates.

10. Correct insecure permissions and excessive privileges identified during the
    investigation.

11. Review application and database accounts according to the principle of least
    privilege.

12. Scan the affected system for additional indicators of compromise.

## Validation

Do not proceed to recovery until the known attack vector has been addressed and
known persistence mechanisms have been removed.

---

# Phase 4 - Recovery

## Objective

Restore business services safely without reintroducing the attacker.

## Actions

1. Restore the database from a known-good backup if database integrity cannot be
   trusted.

2. Verify the integrity and expected contents of the backup before restoration.

3. Rebuild the affected server from a trusted baseline when the integrity of the
   operating system cannot be established.

4. Apply the approved hardening configuration before reconnecting the system.

5. Reapply RBAC, firewall, SSH, logging, and audit controls.

6. Confirm that PostgreSQL port 5432 is accessible only from authorized systems.

7. Confirm that SSH access is restricted to the approved Bastion Host.

8. Confirm that centralized logging is functioning.

9. Confirm that auditd monitoring is active.

10. Test application connectivity and database functionality.

11. Verify that authorized users can perform required business operations.

12. Monitor the recovered environment closely for renewed suspicious activity.

## Return to Production

The database may return to normal production operation only after security and
operations personnel confirm that:

- The root cause has been addressed.
- Unauthorized access has been removed.
- Required credentials have been rotated.
- Security controls are active.
- Logging and monitoring are operational.
- Database integrity has been validated.
- Business functionality has been tested.

---

# Phase 5 - Lessons Learned

## Objective

Understand what happened and improve Nexus Financial's security controls.

## Actions

Conduct a blameless post-incident review after the incident has been contained
and normal operations have been restored.

Document:

- What happened.
- When the compromise began.
- How the attacker gained access.
- Which systems and data were affected.
- How the incident was detected.
- Which controls succeeded.
- Which controls failed or were missing.
- How long identification, containment, eradication, and recovery required.
- Which actions delayed the response.
- Which technical and policy changes are required.

## Corrective Actions

Create remediation actions for every significant control gap identified during
the incident.

Each action must include:

- Description of the issue.
- Required remediation.
- Responsible owner.
- Priority.
- Target completion date.
- Validation method.

Update security policies, hardening scripts, RBAC rules, firewall rules,
monitoring rules, and incident response procedures when necessary.

Relevant lessons must be incorporated into future security awareness and
technical training.

---

# Incident Documentation Requirements

Throughout the incident, responders must maintain an incident timeline.

The timeline should record:

- Date and time.
- Person performing the action.
- Action performed.
- Reason for the action.
- System affected.
- Result of the action.

Evidence must be preserved carefully and changes to evidence must be minimized.

Important decisions and approvals must also be documented.

---

# Final Principle

Preserve evidence before unnecessary modification.

Contain before eradication.

Eradicate before recovery.

Validate security before reconnecting production.

Learn from every incident.