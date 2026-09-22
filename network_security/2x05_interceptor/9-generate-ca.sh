#!/bin/bash
sudo mkdir -p /etc/squid/ssl_cert && sudo openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -keyout /etc/squid/ssl_cert/myCA.key -out /etc/squid/ssl_cert/myCA.pem -subj "/CN=ACME Squid CA" && sudo /usr/lib/squid/security_file_certgen -c -s /var/lib/ssl_db -M 4MB
