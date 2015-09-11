# peinjector

## Description
The executable file format on the Windows platform is PE COFF. The peinjector provides different ways to in-fect these files with custom payloads without changing the original functionality. It creates patches, which are then applied seamlessly during file transfer. It is very performant, lightweight, modular and can be oper-ated on embedded hardware.	

## Features
-	Full x86 and x64 PE file support.
-	Open Source
-	Fully working on Windows and Linux, including automated installation scripts.
-	On Linux, all servers will be automatically integrated as service, no manual configuration required.
-	Plain C, no external libraries required (peinjector). 
-	MITM integration is available in C, Python and Java. A sample Python MITM implementation is included.
-	Foolproof, mobile-ready web interface. Anyone who can configure a home router can configure the injector server.
-	Easy to use integrated shellcode factory, including re-verse shells, meterpreter, ... or own shellcode. Every-thing is available in 32 and 64 bit with optional auto-mated encryption to drop AV detection rates. Custom shellcode can be injected directly or as a new thread. 
-	An awesome about page and much more, check it out.
