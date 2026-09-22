#!/bin/bash
echo "$1 ALL=(root) /usr/bin/systemctl restart apache2, /usr/bin/journalctl" > /etc/sudoers.d/junior
chmod 440 /etc/sudoers.d/junior
visudo -c -f /etc/sudoers.d/junior