#!/bin/sh

# peinjector-control install script
# Autor: A.A.

# Check root
if [ "$(id -u)" != "0" ]; then
	echo "must be run as root user"
	exit 1
fi

# Dependencies
apt-get install -y python3

# Check minimum python version
if $(python3 -c 'import sys; print(1 if sys.hexversion<=0x03040000 else 0)'); then
  echo "python 3.4 is required at least"
  exit 1
fi

# install start script
cp ./peinjector-control_start.sh /usr/local/bin/peinjector-control_start.sh
chmod a+x /usr/local/bin/peinjector-control_start.sh

# install stop script
cp ./peinjector-control_stop.sh /usr/local/bin/peinjector-control_stop.sh
chmod a+x /usr/local/bin/peinjector-control_stop.sh

# install service script
cp ./peinjector-control_service.sh /etc/init.d/peinjector-control
chmod a+x /etc/init.d/peinjector-control

# register service
update-rc.d peinjector-control defaults

# make working and log dir
mkdir /etc/peinjector-control
mkdir /var/log/peinjector-control

# Copy server & data
cd ..
cp -r ./* /etc/peinjector-control
# Remove install dir
rm -rf /etc/peinjector-control/install

# run server
service peinjector-control start

exit 0