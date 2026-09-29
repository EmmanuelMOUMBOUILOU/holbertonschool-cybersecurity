# Nexus Financial Threat Model

## Objective

This threat model identifies the primary security threats affecting Nexus Financial based on the current environment. The STRIDE methodology is used to classify the most significant threat for each major component and identify the threat actor most likely to exploit it.

## STRIDE Analysis

| Component | STRIDE Category | Top Threat | Most Likely Threat Actor |
|---|---|---|---|
| Physical Office Access | Spoofing | An unauthorized person can enter the office or use a generic/spare keycard to impersonate an authorized employee. | External attacker / unauthorized visitor |
| Server Room ("The Core") | Tampering | An unauthorized person can physically access servers or network equipment because the server room door is propped open. | Visitor / malicious insider |
| Employee Workstations | Elevation of Privilege | An attacker can use an unlocked employee MacBook to access systems and privileges belonging to that employee. | Opportunistic visitor / malicious insider |
| Shared SSH Access | Repudiation | The shared `nexus_master.pem` key prevents reliable attribution of production actions to a specific individual. | Malicious or compromised insider |
| Production PostgreSQL Database | Information Disclosure | PostgreSQL port 5432 is exposed to the Internet through `0.0.0.0/0`, increasing the risk of unauthorized access to financial and customer data. | External attacker |
| Credentials and Secrets | Information Disclosure | Sensitive credentials displayed on the office whiteboard can be observed and reused by unauthorized people. | Visitor / malicious insider |
| Production Privileges | Elevation of Privilege | Developers have excessive `root` privileges, allowing a compromised or malicious account to obtain unrestricted control of production systems. | Compromised developer / malicious insider |
| Logging and Monitoring | Repudiation | The absence of centralized logs prevents Nexus Financial from reliably determining who performed an action or reconstructing a security incident. | Malicious insider / external attacker |
| Network Availability | Denial of Service | The lack of effective monitoring and defensive visibility can prevent the company from identifying and responding quickly to service disruption. | External attacker |
| Database Backups | Tampering | Unverified and unmanaged backup processes could result in backups being modified, deleted, or becoming unusable without detection. | Malicious insider / compromised account |

## Highest Priority Risks

The most urgent risks are the Internet-exposed production database, shared production SSH credentials, unrestricted root privileges, lack of centralized logging, weak physical access controls, and unverified backups.

These risks directly threaten the confidentiality, integrity, availability, and accountability of Nexus Financial's critical systems and data.

## Recommended Security Direction

Nexus Financial should apply defense in depth by combining:

- Strong physical access controls.
- Individual authentication and least privilege.
- RBAC for production access.
- Network segmentation and firewall restrictions.
- Host hardening and mandatory access controls.
- Centralized and protected logging.
- Verified and regularly tested backups.
- A documented incident response process.