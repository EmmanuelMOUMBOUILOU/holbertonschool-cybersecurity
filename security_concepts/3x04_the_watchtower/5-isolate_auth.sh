#!/bin/bash
echo 'authpriv.info /var/log/secure_remote.log' > /etc/rsyslog.d/60-auth.conf
systemctl restart rsyslog