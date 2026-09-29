# Nexus Financial Physical & Human Security Plan

## Objective

This plan defines practical physical and human security controls for Nexus Financial.
The objective is to reduce unauthorized access, protect critical infrastructure,
improve employee security behavior, and establish accountability without requiring
expensive security solutions.

## Current Security Risks

The physical walkthrough identified several major weaknesses:

- There is no effective visitor control at the front desk.
- The visitor check-in iPad is not operational.
- The server room door is propped open.
- Unauthorized visitors can approach critical infrastructure.
- Unused network switch ports remain active.
- Generic keycards are shared between developers.
- Spare access cards are stored unsecured and unlabeled.
- Employee laptops are frequently left unlocked.
- Sensitive passwords are displayed on a public whiteboard.
- Visitors can photograph or record sensitive areas.

## 1. Immediate Actions - 0 Cost

The following actions must be implemented immediately using existing resources.

### Secure the Server Room

Remove the fire extinguisher holding the server room door open and keep the door
closed and locked at all times.

Only authorized technical personnel should enter the server room.

Until the air-conditioning issue is resolved, server temperature must be monitored
and temporary cooling measures must not require leaving the security door open.

### Remove Exposed Credentials

Erase the Guest Wi-Fi password, staging database password, and other credentials
from the office whiteboard.

Credentials must never be displayed in publicly visible or shared physical areas.

Any exposed company credentials must be changed because visitors may already have
seen or photographed them.

### Lock Workstations

Employees must lock their laptops whenever they leave their desks.

The existing automatic screen-lock functionality should be enabled with a short
inactivity timeout.

### Control Existing Access Cards

Stop using generic developer access cards.

Assign existing cards to specific individuals wherever possible and maintain a
basic access register showing who has each card.

The box of spare cards must be moved from under the Office Manager's desk to a
locked location.

Lost or unaccounted-for cards must be reported immediately.

### Disable Unused Network Ports

Unused switch ports in the office and server room must be disabled.

Only ports required for approved business devices should remain active.

## 2. Short-Term Actions - Low Cost

The following controls should be implemented as soon as possible.

### Visitor Management

Restore or replace the visitor check-in process.

All visitors and delivery personnel must:

- Sign in on arrival.
- Be identified by an employee host.
- Receive a temporary visitor badge.
- Remain escorted in restricted areas.
- Return the badge before leaving.

A simple paper visitor log can be used temporarily if the electronic system is
unavailable.

### Individual Access Cards

Replace shared generic cards with individually assigned cards.

Access rights should follow the principle of least privilege.

Server room access should be restricted to employees whose responsibilities
require physical access to infrastructure.

### Access Review

Maintain an inventory of active and spare access cards.

Access must be revoked immediately when an employee or contractor leaves the
company or no longer requires access.

Physical access rights should be reviewed regularly.

### Clean Desk and Clear Screen

Introduce a clean-desk and clear-screen requirement.

Passwords, credentials, confidential documents, access cards, and sensitive
information must not be left visible in shared workspaces.

### Server Room Environment

Repair the cooling problem that caused employees to leave the server room door
open.

Security controls must not be bypassed as a workaround for environmental or
operational problems.

## 3. Long-Term Actions

Nexus Financial should establish a sustainable physical and endpoint security program
that addresses the root causes identified during the physical walkthrough.

### Dedicated Office and Secure Infrastructure

Nexus Financial should evaluate moving critical operations away from an open
co-working environment to a dedicated office where physical access can be fully
controlled.

Critical production infrastructure should be moved to a proper secured data center
or reputable managed cloud environment instead of being hosted in a glass-walled
meeting room.

The selected environment should provide controlled access, redundant cooling,
fire protection, environmental monitoring, and appropriate physical security.

### Badge and Biometric Access Control

Sensitive areas such as the server room should use individually assigned access
badges combined with biometric access control where appropriate.

Access must be granted according to job responsibilities and the principle of
least privilege.

Every entry into sensitive areas should be logged with the identity of the person,
date, and time.

Access permissions must be reviewed regularly and revoked immediately when an
employee or contractor leaves the company.

### CCTV Monitoring

CCTV cameras should be installed at entrances, exits, the server room entrance,
and other sensitive infrastructure areas.

Cameras should be positioned to monitor unauthorized physical access without
unnecessarily recording private employee activity.

CCTV recordings should be securely stored, access-controlled, retained according
to company policy, and available for security investigations.

### Mobile Device Management

Nexus Financial should deploy a Mobile Device Management (MDM) solution for
company MacBooks.

MDM should enforce security requirements such as automatic screen locking,
full-disk encryption, operating system updates, approved security configurations,
and remote lock or wipe capabilities for lost or stolen devices.

This ensures that workstation security does not depend entirely on individual
employee behavior.

### Network Access Protection

Network segmentation should separate guest, employee, administrative, and
production environments.

Unused network switch ports should remain disabled.

Nexus Financial should implement stronger network access controls to prevent
unauthorized devices from connecting to internal networks.

### Professional Physical Security Audit

Nexus Financial should conduct a periodic professional and independent physical
security audit.

The audit should evaluate office access, visitor management, server room security,
access cards, CCTV coverage, endpoint practices, and network infrastructure.

Audit findings should be documented, assigned to responsible owners, prioritized
according to risk, and tracked until remediation is complete.

### Periodic Access Reviews

Physical access permissions, active badges, spare cards, and access logs should
be reviewed regularly.

The review should identify unnecessary privileges, inactive credentials, missing
cards, and unusual access activity.

## 4. Security Awareness and Training

Physical security depends on employee behavior as well as technical controls.

All employees should receive security awareness training covering:

- Visitor identification and escort requirements.
- Workstation locking.
- Credential protection.
- Clean-desk practices.
- Access-card security.
- Tailgating and piggybacking.
- Reporting suspicious behavior.
- Photography and recording restrictions in sensitive areas.

Training should be provided during onboarding and refreshed periodically.

## Delivery Guy TikTok Incident

The delivery person should be escorted out of the restricted server area
immediately without creating an unnecessary confrontation.

The incident should be reported internally and documented as a physical security
event.

Security staff or management should determine what equipment, screens, labels,
network information, credentials, or other sensitive information may have been
visible in the recording.

If sensitive information may have been exposed, the appropriate credentials or
access mechanisms should be changed and the affected systems reviewed.

Employees should be reminded that visitors and delivery personnel must never be
left unescorted in restricted areas.

Photography and video recording should be prohibited in sensitive technical areas
unless explicitly authorized.

The objective is not simply to blame the delivery person. The root problem is that
Nexus Financial allowed an unauthorized visitor to enter a sensitive area without
effective access control or supervision.

## Enforcement and Ownership

The Office Manager is responsible for maintaining visitor and access-card records.

The IT team is responsible for securing network ports, workstations, and the
server room infrastructure.

Managers are responsible for ensuring that employees follow physical security
requirements.

All employees are responsible for reporting lost cards, unauthorized visitors,
exposed credentials, and other suspicious physical security events.

## Conclusion

Nexus Financial does not need expensive guards or biometric systems to achieve an
immediate improvement in physical security.

Closing and locking restricted areas, controlling visitors, assigning individual
access cards, locking workstations, protecting credentials, disabling unused
network ports, and training employees will significantly reduce the current
physical and human attack surface.