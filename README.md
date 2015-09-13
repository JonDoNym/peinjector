# peinjector

## Description
The executable file format on the Windows platform is PE COFF. The peinjector provides different ways to infect these files with custom payloads without changing the original functionality. It creates patches, which are then applied **seamlessly during file transfer**. It is very performant, lightweight, modular and can be **[operated on embedded hardware](https://github.com/JonDoNym/peinjector/wiki/Guide:-Raspberry-Pi-image)**.	

## Features
-	Full x86 and x64 PE file support.
-	Open Source
-	Fully working on Windows and Linux, including automated installation scripts.
-	Can be  operated on embedded hardware, tested on a [Rasperberry Pi 2](https://github.com/JonDoNym/peinjector/wiki/Guide:-Raspberry-Pi-image).
-	On Linux, all servers will be automatically integrated as service, no manual configuration required.
-	Plain C, no external libraries required (peinjector). 
-	MITM integration is available in C, Python and Java. A sample Python MITM implementation is included.
-	Foolproof, mobile-ready web interface. Anyone who can configure a home router can configure the injector server.
-	Easy to use integrated shellcode factory, including reverse shells, meterpreter, ... or own shellcode. Everything is available in 32 and 64 bit with optional automated encryption. Custom shellcode can be injected directly or as a new thread. 
-	An awesome about page and much more, check it out.

## Installation
[Installation Guide](https://github.com/JonDoNym/peinjector/wiki/Guide:-full-installation)

## Screenshots
[Screenshots](https://github.com/JonDoNym/peinjector/wiki/Screenshots)

## Contact the developers on
```
anon.zMisc@gmail.com
```

## peinjector
                                      + configuration                  
                                      | payload                        
                                      | ...                            
                          +-----------v------------+                   
          +-------+       |                        |                   
          | PATCH <-------+      libpeinfect       <--+                
          +-------+       |                        |  |                
                          +-----------+------------+  |                
                                      |               |                
                          +-----------v------------+  |                
                          |                        |  |                
          +--------------->       libpetool        |  |                
          | change values |                        |  |                
          | add sections  +-----------^------------+  |                
          | resize sect.              |               |                
          + ...                  +----v----+          |                
                                 | PEFILE  +----------+                
                                 +----^----+                           
                                      |                                
                          +-----------v------------+                   
          PE File data    |                        |    PE File data   
          +--------------->       libpefile        +--------------->   
                          |                        |                   
                          +------------------------+   


### libpefile
Provides PE file parsing, modification and reassembling capabilities, based on PE COFF specification. Also works with many non-compliant and deliberately malformed files which the Windows Loader accepts.

### libpetool
Provides more complex modifications (adding/resizing sections). Keeps header values PE COFF compliant.

### libpeinfect
Provides different infection methods, removes integrity checks, certificates, etc. It can fully infect a file (statically, e.g. from disk) or generate a patch (for MITM infection. Connectors which work with these patches are available in C, Python and Java). The infected file keeps its original functionality.

## servers
                                          +-----------------+-+
                                          |   web browser   |X|
                +-------------+           +-----------------+-+
                | peinjector- |           |       _____       |
        ------->+ interceptor +---------> |      /     \      |
        -orig.->+   (MITM)    +-patched-> |     | () () |     |
        -data-->+             +-data----> |      \  ^  /      |
        ------->+ +---------+ +---------> |       |||||       |
                | |connector| |           |                   |
                +-+-+-----^-+-+           +-----+------^------+
             raw    |     |              send   |      | get   
             header |     | patch        config |      | status
                    |     |                     |      |       
                +-+-v-----+-+-+           +-+---v------+---+-+ 
                | |data port| |           | |http(s) server| | 
                | +---------+ |           | +--------------+ | 
                | peinjector  |           |                  | 
                | (core   +---+ crtl      +---+ peinjector-  | 
                | engine) |c p| protocol  |c p| control      | 
                |         |r o+----------->r r| (user        | 
                |         |t r<-----------+t o| interface)   | 
                |         |l t|           |l .|              | 
                +---------+---+           +---+--------------+ 

### peinjector
Provides PE file patching as a service. Just send the raw header of your PE file and you’ll receive a custom-made patch for it. Can be remotely controlled via a command protocol.

### peinjector-control
Web interface to configure and control a peinjector server. A small shellcode factory with some basic shellcodes, automatic encryptoin/obfuscation and thread generation is provided - alternatively, custom shellcode can be injected.

### peinjector-interceptor
Sample MITM integration. Based on Python and libmproxy, supports SSL interception, can act as transparent Proxy, HTTP Proxy, ... . Provides seamless PE patching capabilities.

## related projects

[mitmproxy](https://mitmproxy.org/) - An interactive console program that allows traffic flows to be intercepted, inspected, modified and replayed. Written in Python 2.7. peinjector-interceptor is based on mitmproxy's libmproxy library. 

[BDFProxy](https://github.com/secretsquirrel/BDFProxy) - The idea for peinjector comes from this project. It can also do MITM executable modification, but doesn't provide seamless patching and isn't as performant as peinjector. It provides ELF and MACH-O infection, PE code cave jumping, IAT patching and more "static" patching methods.
