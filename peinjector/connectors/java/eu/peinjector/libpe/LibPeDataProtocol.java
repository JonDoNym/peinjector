package eu.peinjector.libpe;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

import eu.peinjector.libpe.exceptions.LibPeSocketException;

/**
 * The data protocol to for the pe-header and the patches.
 * 
 * <pre>
 *  SEND TO PE_INJECTOR SERVER (pe header):
 *     0               32                              n
 *     +---------------+-------------------------------+
 *     |               |                               |
 *     |     token     | first 4096 bytes of the file  |
 *     |               |  (with the pe header inside)  |
 *     +---------------+-------------------------------+
 * </pre>
 * 
 * <pre>
 *  RECEIVE FROM PE_INJECTOR SERVER (patch):
 *     +------------+------------+------------+----    +-----------+      
 *     | PATCH PART | PATCH PART | PATCH PART | .....  | 000000000 |    
 *     +------------+------------+------------+----    +-----------+  
 * </pre>
 * 
 * @see LibPePatch
 */
public class LibPeDataProtocol {
	
	
	// Class variables
	// ------------------------------------------------------------------------------
	private LibPeControlProtocol control = null;

	
	// Constructors
	// ------------------------------------------------------------------------------
	/**
	 * The {@link LibPeDataProtocol} use the server address, the port and the token from the {@link LibPeControlProtocol} to communicate.
	 */
	public LibPeDataProtocol(LibPeControlProtocol control) {
		super();
		
		if(null == control) {
			throw new NullPointerException("control is null");
		}
		
		this.control = control;
	}

	
	// communication
	// ------------------------------------------------------------------------------
	/**
	 * Send the file header to the pe-injector and return a patch to manipulate the file.<br>
	 * (use the first 4096 byte of the file)
	 * 
	 * @param fileheader {@link #readFileheader(String)}
	 * @return {@link LibPePatch}
	 * 
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket
	 */
	public LibPePatch getPatchFromPEinjector(byte[] fileheader) throws LibPeSocketException {
		// value is not null
		if(null == fileheader) {
			fileheader = new byte[0];
		}
		
		// connect to server
		InetSocketAddress socketAddress = new InetSocketAddress(this.control.getServerAddress(), this.control.getDataPort());
		Socket socket = new Socket();
		byte[] response = new byte[8192];
		int received = 0;
		try {
			socket.connect(socketAddress, 3000);
	
			// build send data
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			baos.write(control.getToken());	// send token (32 byte)
			baos.write(fileheader);			// send file header (n byte)
			
			// SEND
			OutputStream out = socket.getOutputStream();
			out.write(baos.toByteArray());
			out.flush();
	
			// RECIVE DATA
			InputStream in = socket.getInputStream();
			received = in.read(response);
			
		} catch(Exception e) {
			throw new LibPeSocketException(e.getMessage());
			
		} finally {
			try {
				socket.close();		// CLOSE SOCKET
			} catch (Exception e2) {
			}
		}
		
		// copy the received body (patch) in a new array
		byte[] serializedPatch = new byte[received];
		for(int i=0; i<(received); i++) {
			serializedPatch[i] = response[i];
		}
		
		// return patch
		return new LibPePatch(serializedPatch);
	}

	
}
