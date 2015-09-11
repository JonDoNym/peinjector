#!/bin/sh

# peinjector-control start script
# Autor: A.A.

# Check root
if [ "$(id -u)" != "0" ]; then
	echo "must be run as root user"
	exit 1
fi

# set Log files and working dir
LOG_FILE=/var/log/peinjector-control/control.log
ERROR_FILE=/var/log/peinjector-control/control.err
WORKING_DIR=/etc/peinjector-control

# start server
cd $WORKING_DIR
((python3 ./peinjector_control.py) >> $LOG_FILE 2>> $ERROR_FILE </dev/null) &

exit 0