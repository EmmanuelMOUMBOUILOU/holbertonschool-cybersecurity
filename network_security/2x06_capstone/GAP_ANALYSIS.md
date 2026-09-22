# GAP ANALYSIS — LogiCorp Network Security Overhaul

## 1. Executive Summary

LogiCorp présente actuellement plusieurs risques de sécurité critiques, principalement liés à l'absence de segmentation réseau, à l'exposition directe de services sensibles et à l'absence de politique de filtrage réseau.

La priorité est de segmenter l'infrastructure, sécuriser les accès distants, réduire l'exposition des services et mettre en place une politique "Default Deny", tout en maintenant les services indispensables à l'activité de l'entreprise.

---

## 2. Current State Assessment

D'après la documentation fournie :

- Le réseau est actuellement plat et utilise le sous-réseau `192.168.1.x`.
- Le réseau Guest WiFi, les postes Finance et la base de données critique ne sont pas segmentés.
- SSH est accessible depuis Internet.
- L'accès SSH root est activé.
- Le serveur FTP fonctionne en clair.
- Aucun firewall actif n'est documenté.
- L'infrastructure repose sur une gateway Linux centrale.
- La gateway constitue un Single Point of Failure.
- L'équipe Finance doit continuer à utiliser FTP pour le moment.
- L'administration distante du serveur doit rester possible.

Cette analyse repose uniquement sur les documents fournis. L'état réel devra être confirmé pendant l'audit technique.

---

## 3. Critical Gaps Identified

### 3.1 Network Architecture Gaps

**Current State:**
- Réseau plat.
- Guest WiFi, Finance et base de données critique sur le même segment.
- Absence de zones de sécurité clairement séparées.

**Target State:**
- Segmentation entre WAN, LAN, DMZ et ressources critiques.
- Isolation de la base de données.
- Limitation des communications entre zones.

**Gap / Risk:**
Un équipement compromis sur le réseau Guest peut potentiellement effectuer un mouvement latéral vers les systèmes critiques.

---

### 3.2 Access Control Gaps

**Current State:**
- SSH accessible depuis Internet.
- Connexion root SSH activée.
- Aucun firewall actif documenté.
- Pas de politique "Default Deny".

**Target State:**
- Accès distant réservé aux utilisateurs autorisés.
- Accès SSH via un canal sécurisé.
- Blocage par défaut des connexions non autorisées.
- Administration root directe désactivée.

**Gap / Risk:**
La surface d'attaque distante est trop importante et les accès administratifs sont insuffisamment restreints.

---

### 3.3 Encryption Gaps

**Current State:**
- FTP est utilisé en clair.
- Les identifiants et données FTP peuvent être exposés sur le réseau.

**Target State:**
- Communications sensibles chiffrées.
- Accès distant protégé par un tunnel sécurisé.
- Flux FTP legacy contenu dans une zone ou un canal sécurisé.

**Gap / Risk:**
Les identifiants et fichiers transférés via FTP peuvent être interceptés.

---

### 3.4 Monitoring Gaps

**Current State:**
- Aucun mécanisme de monitoring, journalisation centralisée ou détection réseau n'est décrit dans la documentation.

**Target State:**
- Journalisation des accès.
- Surveillance des événements de sécurité.
- Capacité à détecter les comportements anormaux et les tentatives d'accès non autorisées.

**Gap / Risk:**
Une attaque peut être difficile à détecter ou à reconstruire rapidement.

---

## 4. Risk Matrix

| Risk | Severity | Impact |
|---|---|---|
| Flat network allowing lateral movement | Critical | Compromise of critical systems from less trusted zones |
| No active firewall documented | Critical | Unrestricted network exposure |
| SSH exposed to the Internet with root enabled | Critical | Direct compromise of the gateway |
| Critical database not isolated | Critical | Unauthorized access to business-critical data |
| FTP credentials and data transmitted in cleartext | High | Credential theft and data interception |
| No documented monitoring or centralized logging | Medium | Reduced detection and forensic capability |
| Single Point of Failure on central gateway | Medium | Potential service interruption |

---

## 5. Preliminary Recommendations

### Network Segmentation
Create separate security zones for:

- WAN
- Internal LAN
- Finance
- Guest WiFi
- DMZ
- Critical Database

Traffic between zones should be explicitly controlled.

### Firewall
Implement a stateful firewall using a **Default Deny** policy.

Only explicitly required services should be permitted.

### Remote Administration
Restrict SSH access.

Recommended approach:

- SSH accessible only through a VPN.
- Disable direct root SSH login.
- Use authorized SSH keys.

### Legacy FTP
Because Finance currently requires FTP, the service should not simply be removed.

Instead:

- Restrict FTP access to authorized Finance systems.
- Isolate the FTP service from critical systems.
- Limit allowed source and destination addresses.
- Protect remote access to the FTP environment through a secure network path where possible.

### Monitoring
Implement:

- Firewall logging.
- Authentication logging.
- Network monitoring.
- Review of suspicious connection attempts.

### Deployment Safety
Security changes should be deployed progressively and validated before production rollout to avoid disrupting LogiCorp's business operations.

---

## 6. Conclusion

The documentation indicates that LogiCorp's primary security weakness is the absence of segmentation and access control.

The remediation strategy should prioritize:

1. Network segmentation.
2. Default-deny firewalling.
3. Secure remote access.
4. Protection of the legacy FTP workflow.
5. Monitoring and validation.

The next phase must be a live technical audit to verify whether the documented environment matches the actual infrastructure.