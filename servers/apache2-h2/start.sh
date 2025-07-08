#!/bin/bash

# Start php-fpm
php-fpm8.3 -D &
# Start apache
apache2ctl -D FOREGROUND &

# error log
touch /var/log/apache2/error.log
tail -f /var/log/apache2/error.log