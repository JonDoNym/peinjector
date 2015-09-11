#!/bin/sh

# peinjector build script
# Author: A.A.

# make build directory
rm -rf ./build
mkdir ./build
cd ./build

# build executable
gcc -O3 -Wall -c -o libpetool.o ../libpetool.c
gcc -O3 -Wall -c -o libpefile.o ../libpefile.c
gcc -O3 -Wall -c -o libpeserver.o ../libpeserver.c
gcc -O3 -Wall -c -o peinjector.o ../peinjector.c
gcc -O3 -Wall -c -o libpeinfect.o ../libpeinfect.c
gcc -O3 -Wall -c -o libpeinfect_obfuscator.o ../libpeinfect_obfuscator.c 
gcc -O3 -Wall -c -o libpeprotocol.o ../libpeprotocol.c 
gcc -O3 -Wall -c -o minIni.o ../3rdparty/ini/minIni.c
gcc -s -o peinjector peinjector.o libpetool.o libpeserver.o libpeprotocol.o minIni.o libpeinfect.o libpeinfect_obfuscator.o libpefile.o -lpthread

# make executable
chmod +x ./peinjector

# clean up
rm -rf ./*.o

exit 0