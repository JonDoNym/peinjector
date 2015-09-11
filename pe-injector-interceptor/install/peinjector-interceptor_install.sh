#!/bin/sh

# peinjector interceptor  install script
# Autor: A.A.

# Check root
if [ "$(id -u)" != "0" ]; then
	echo "must be run as root user"
	exit 1
fi

# Install dependencies
chmod a+x ./peinjector-interceptor_dependencies.sh
./peinjector-interceptor_dependencies.sh

# install start script
cp ./peinjector-interceptor_start.sh /usr/local/bin/peinjector-interceptor_start.sh
chmod a+x /usr/local/bin/peinjector-interceptor_start.sh

# install stop script
cp ./peinjector-interceptor_stop.sh /usr/local/bin/peinjector-interceptor_stop.sh
chmod a+x /usr/local/bin/peinjector-interceptor_stop.sh

# install service script
cp ./peinjector-interceptor_service.sh /etc/init.d/peinjector-interceptor
chmod a+x /etc/init.d/peinjector-interceptor

# register service
update-rc.d peinjector-interceptor defaults

# make working and log dir
mkdir /etc/peinjector-interceptor
mkdir /var/log/peinjector-interceptor

# Copy server & data
cd ..
cp -r ./* /etc/peinjector-interceptor
# Remove install dir
rm -rf /etc/peinjector-interceptor/install

# run server
service peinjector-interceptor start

exit 0