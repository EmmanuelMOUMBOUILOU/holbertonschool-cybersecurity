#!/bin/bash
echo -e '/var/log/secure_remote.log {\n    daily\n    rotate 7\n    compress\n    missingok\n}' > /etc/logrotate.d/secure_remote