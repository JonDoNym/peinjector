@echo off

REM Make build directory
rmdir /s /q build
mkdir build
cd build

REM build executable 
gcc -O3 -Wall -c -o libpetool.o ..\libpetool.c
gcc -O3 -Wall -c -o libpefile.o ..\libpefile.c 
gcc -O3 -Wall -c -o libpeserver.o ..\libpeserver.c 
gcc -O3 -Wall -c -o peinjector.o ..\peinjector.c 
gcc -O3 -Wall -c -o libpeinfect.o ..\libpeinfect.c 
gcc -O3 -Wall -c -o libpeinfect_obfuscator.o ..\libpeinfect_obfuscator.c 
gcc -O3 -Wall -c -o libpeprotocol.o ..\libpeprotocol.c 
gcc -O3 -Wall -c -o minIni.o ..\3rdparty\ini\minIni.c 
gcc -s -o peinjector.exe peinjector.o libpetool.o libpeserver.o libpeprotocol.o minIni.o libpeinfect.o libpeinfect_obfuscator.o libpefile.o -lpthread -lws2_32

REM clean up
del *.o
cd ..