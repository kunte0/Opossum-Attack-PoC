#!/bin/bash

# cyrus wants to use /dev/log otherwise it crashes
/usr/sbin/syslog-ng -F &

# not to fast
sleep 1
touch /var/log/mail.log

tail -f /var/log/mail.log &


# strace -f -s 50000 -e trace=sendto   /usr/lib/cyrus/bin/master
/usr/lib/cyrus/bin/master
