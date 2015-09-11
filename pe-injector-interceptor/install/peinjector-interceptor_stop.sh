#!/bin/sh

# peinjector interceptor  stop script
# Autor: A.A.

# Check root
if [ "$(id -u)" != "0" ]; then
	echo "must be run as root user"
	exit 1
fi

# kill peinjector
pkill -f peinjector_interceptor.py

exit 0