# 3. Identity and Access Management Audit

## Control: RBAC and Least Privilege

### Verification Command

```bash
getent group devs
getent group ops
getent group auditors
id sarah
id dave
sudo -l -U sarah
sudo -l -U dave
ls -la /home/
stat -c "%a %U %G %n" /home/sarah /home/opsuser /home/dave
```

### Expected Output

The RBAC groups must exist:

```text
devs:x:<GID>:sarah
ops:x:<GID>:opsuser
auditors:x:<GID>:dave
```

Sarah must belong to the `devs` group and must only receive the approved
Nginx sudo permissions, including:

```text
/bin/systemctl restart nginx
/bin/systemctl status nginx
```

Dave must belong to the `auditors` group and must not have unrestricted
administrative sudo privileges.

The home directories must have strict permissions such as:

```text
700 sarah sarah /home/sarah
700 opsuser opsuser /home/opsuser
700 dave dave /home/dave
```

### Self-Assessment

PASS - The RBAC implementation creates separate development, operations, and
auditing roles.

Sarah can perform the required Nginx operations without receiving unrestricted
root access.

Dave receives auditing access without general administrative privileges,
supporting separation of duties.

User home directories are protected with strict permissions.

The implementation therefore applies Role-Based Access Control, least privilege,
individual accountability, and separation of duties.