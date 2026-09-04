#!/bin/bash
echo '#!/bin/bash' > /usr/local/bin/audit-read-secret
echo 'cat /var/www/html/secret_config.php' >> /usr/local/bin/audit-read-secret
chmod 755 /usr/local/bin/audit-read-secret
echo "$1 ALL=(root) NOPASSWD: /usr/local/bin/audit-read-secret" > /etc/sudoers.d/audit-read-secret
chmod 440 /etc/sudoers.d/audit-read-secret