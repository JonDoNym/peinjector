#!/bin/sh

# peinjector interceptor dependencies script
# Autor: A.A.

# Check root
if [ "$(id -u)" != "0" ]; then
	echo "must be run as root user"
	exit 1
fi

# Dependencies ...
apt-get install -y gcc python git python-pip python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev

# Check minimum python version
if $(python2 -c 'import sys; print(1 if sys.hexversion<0x02070000 else 0)'); then
  echo "python 2.7 is required at least"
  exit 1
fi

# Install MITMPROXY
pip install mitmproxy

exit 0
