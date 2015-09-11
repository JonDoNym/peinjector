#!/bin/sh

# peinjector install script
# Autor: A.A.

# Check root
if [ "$(id -u)" != "0" ]; then
	echo "must be run as root user"
	exit 1
fi

# Dependencies
apt-get install -y gcc

# install start script
cp ./peinjector_start.sh /usr/local/bin/peinjector_start.sh
chmod a+x /usr/local/bin/peinjector_start.sh

# install stop script
cp ./peinjector_stop.sh /usr/local/bin/peinjector_stop.sh
chmod a+x /usr/local/bin/peinjector_stop.sh

# install service script
cp ./peinjector_service.sh /etc/init.d/peinjector
chmod a+x /etc/init.d/peinjector

# register service
update-rc.d peinjector defaults

cd ..
# build
chmod a+x ./peinjector_make.sh
./peinjector_make.sh

# install server binary
cp ./build/peinjector /usr/bin/peinjector
chmod a+x /usr/bin/peinjector

# make working and log dir
mkdir /etc/peinjector
mkdir /var/log/peinjector

# copy config file
cp ./config.ini /etc/peinjector/config.ini

# run server
service peinjector start

exit 0