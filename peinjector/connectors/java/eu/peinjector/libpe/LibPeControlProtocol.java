package eu.peinjector.libpe;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;

import javax.xml.bind.DatatypeConverter;

import eu.peinjector.libpe.exceptions.LibPeProtocolException;
import eu.peinjector.libpe.exceptions.LibPeBadInputException;
import eu.peinjector.libpe.exceptions.LibPeSocketException;


/**
 * The control protocol to manage the pe-injector server.
 * <pre>
 *     0                     32        33                      37                            n
 *     +---------------------+---------+-----------------------+-----------------------------+
 *     |                     |         |                       |                             |
 *     |        token        | command |         length        |            data             |
 *     |                     |         |                       |                             |
 *     +---------------------+---------+-----------------------+-----------------------------+
 * 
 *     token: A 32-byte key. It always has to start with 0xAAAA. The default token is 0xAAAA000...0
 *     command: A 1byte command field (see commands)
 *     length: the size of the data feld
 *     data: The data if the command needs it
 * </pre>
 * 
 */
public class LibPeControlProtocol {

	
	// Class variables
	// ------------------------------------------------------------------------------
	/**
	 * default token == no authentication
	 */
	public static final byte[] DEFAULT_TOKEN = DatatypeConverter.parseHexBinary("aaaa000000000000000000000000000000000000000000000000000000000000");
	
	// Receive Commands
	private static final byte CMD_RECEIVE_SUCCESS                               = (byte) 0xFD;
	private static final byte CMD_RECEIVE_ERROR                                 = (byte) 0xFE;
	
	// Send Commands
	private static final byte CMD_SEND_ECHO                                     = (byte) 0x01;
	private static final byte CMD_SEND_RESTART                                  = (byte) 0x02;
	private static final byte CMD_SEND_SET_SECTION_NAME                         = (byte) 0x03;
	private static final byte CMD_SEND_SET_METHOD_CHANGE_FLAGS                  = (byte) 0x04;
	private static final byte CMD_SEND_SET_METHOD_NEW_SECTION                   = (byte) 0x05;
	private static final byte CMD_SEND_SET_METHOD_ALIGNMENT_RESIZE              = (byte) 0x06;
	private static final byte CMD_SEND_SET_METHOD_ALIGNMENT                     = (byte) 0x07;
	private static final byte CMD_SEND_SET_REMOVE_INTEGRITY_CHECK               = (byte) 0x08;
	private static final byte CMD_SEND_SET_DATA_PORT                            = (byte) 0x09;
	private static final byte CMD_SEND_SET_DATA_INTERFACE                       = (byte) 0x0A;
	private static final byte CMD_SEND_SET_CONTROL_PORT                         = (byte) 0x0B;
	private static final byte CMD_SEND_SET_CONTROL_INTERFACE                    = (byte) 0x0C;
	private static final byte CMD_SEND_SET_PAYLOAD_X86                          = (byte) 0x0D;
	private static final byte CMD_SEND_SET_PAYLOAD_X64                          = (byte) 0x0E;
	private static final byte CMD_SEND_GET_CONFIG                               = (byte) 0x0F;
	private static final byte CMD_SEND_SET_PAYLOAD_NAME_X86                     = (byte) 0x10;
	private static final byte CMD_SEND_SET_TRY_STAY_STEALTH                     = (byte) 0x11;
	private static final byte CMD_SEND_SET_ENABLE                               = (byte) 0x12;
	private static final byte CMD_SEND_SET_RANDOM_SECTION_NAME                  = (byte) 0x13;
	private static final byte CMD_SEND_SHUTDOWN                                 = (byte) 0x14;
	private static final byte CMD_SEND_SET_PAYLOAD_NAME_X64                     = (byte) 0x15;
	private static final byte CMD_SEND_SET_METHOD_CROSS_SECTION_JUMP            = (byte) 0x16;
	private static final byte CMD_SEND_SET_METHOD_CROSS_SECTION_JUMP_ITERATIONS = (byte) 0x17;
	private static final byte CMD_SEND_SET_ENCRYPT                              = (byte) 0x18;
	private static final byte CMD_SEND_SET_ENCRYPT_ITERATIONS                   = (byte) 0x19;
	private static final byte CMD_SEND_SET_TOKEN                                = (byte) 0x20;

	// communication
	private byte[] token = DEFAULT_TOKEN;
	private String libpeServer = "127.0.0.1";
	private int libpeControlPort = 31338;
	private int libpeDataPort = 31337;

	
	// general methods
	// ------------------------------------------------------------------------------
	/**
	 * Generate a valid random token<br>
	 * (32 byte long and starts with 0xAAAA)
	 * 
	 * @return random token
	 */
	public static byte[] generateToken() {
		SecureRandom random = new SecureRandom();
		byte[] token = new byte[32];
		random.nextBytes(token);
		token[0] = (byte) 0xAA;
		token[1] = (byte) 0xAA;
		return token;
	}

	/**
	 * Set a InetSocketAddress to the pe-injector control port.
	 * 
	 * @param host hostname or ip
	 * @param controlPort control port
	 * @param dataPort data port
	 * @throws LibPeBadInputException if host is null or port is invalid
	 * 
	 * @see #getServerAddress()
	 * @see #getControlPort()
	 * @see #getDataPort()
	 */
	public void setServerAddress(String host, int controlPort, int dataPort) throws LibPeBadInputException {
		if(null == host || controlPort < 0 || controlPort > 65535 || dataPort < 0 || dataPort > 65535) {
			throw new LibPeBadInputException("host or port invalid");
		} else {
			this.libpeServer = host;
			this.libpeControlPort = controlPort;
			this.libpeDataPort = dataPort;
		}
	}
	
	/**
	 * @return server ip or host
	 * @see #setServerAddress(String, int)
	 */
	public String getServerAddress() {
		return libpeServer;
	}
	
	/**
	 * @return server control port
	 * @see #setServerAddress(String, int)
	 */
	public int getControlPort() {
		return libpeControlPort;
	}
	
	/**
	 * @return server data port
	 * @see #setServerAddress(String, int)
	 */
	public int getDataPort() {
		return libpeDataPort;
	}

	/**
	 * Set a token for the communication.<br>
	 * 
	 * @param token {@link #generateToken()}
	 * @throws LibPeBadInputException if invalid length or start not with 0xAAAA
	 * 
	 * @see #getToken()
	 */
	public void setToken(byte[] token) throws LibPeBadInputException {
		// token length
		if(null == token || 32 != token.length) {
			throw new LibPeBadInputException("the token musst be 32 byte long");
		}
		// token start with 0xaaaa
		if((byte)0xAA != token[0] || (byte)0xAA != token[1]) {
			throw new LibPeBadInputException("the token musst start with 0xAAAA");
		}
		// token is ok
		this.token = token;
	}

	/**
	 * @return the used token for the communication
	 * 
	 * @see #setToken(byte[])
	 */
	public byte[] getToken() {
		return token;
	}
	
	/**
	 * Sends commands to the server<br>
	 * (see control protocol: {@link LibPeControlProtocol}) 
	 * 
	 * @param cmd command byte  (see CMD_SEND_*)
	 * @param value optional data to send
	 * @return null...CMD_RECEIVE_ERROR;  byte[]...CMD_RECEIVE_SUCCESS
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket
	 */
	private byte[] cmdSend(byte cmd, byte[] value) throws LibPeProtocolException, LibPeSocketException  {
		// value is not null
		if(null == value) {
			value = new byte[0];
		}
		
		// connect to server
		InetSocketAddress socketAddress = new InetSocketAddress(this.getServerAddress(), this.getControlPort());
		Socket socket = new Socket();
		byte[] response = new byte[8192];
		int received = 0;
		try {
			socket.connect(socketAddress, 3000);

			// build send data
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			baos.write(getToken());		// send token (32 byte)
			baos.write(cmd);			// send command (1 byte)
			baos.write( ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value.length).array() );	// send length (4 byte)
			baos.write(value);			// send value (n byte)
			
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
		
		// CHECK DATA
		// min size (header: 32+5 byte)
		if(received < 32+5) {
			throw new LibPeProtocolException("response is too short");
		}
		
		// the header is ok:
		int received_lng = ByteBuffer.wrap(response,(32+1),4).order(ByteOrder.LITTLE_ENDIAN).getInt();
		// is the length feld ok?
		if(received_lng != received-(32+5)) {
			throw new LibPeProtocolException("length feld invalid");
		}
		
		// copy the received body in a new array
		byte[] received_msg = new byte[received_lng];
		for(int i=0; i<received_lng; i++) {
			received_msg[i] = response[i+(32+5)];
		}
		
		// check the command byte
		byte received_cmd = response[32+0];
		if(CMD_RECEIVE_SUCCESS == received_cmd) {
			// CMD_RECEIVE_SUCCESS -> received_msg
			return received_msg;
		}else if(CMD_RECEIVE_ERROR == received_cmd) {
			// CMD_RECEIVE_ERROR -> null
			return null;
		}else {
			// bad cmd byte ?!?!?!?!?!
			throw new LibPeProtocolException("bad command byte received");
		}
	}

	
	// send-boolean-commands
	// ------------------------------------------------------------------------------
	/**
	 * Change unmatching section flags. Might be required for "alignment method" and "alignment resize method" flags.
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetMethodChangeFlags(boolean value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		byte[] protocolBody = {0};
		if(value) {
			protocolBody[0] = 1;
		}
		
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_SET_METHOD_CHANGE_FLAGS, protocolBody);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}

	/**
	 * Insert a new section and inject the shellcode there.
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetMethodNewSection(boolean value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		byte[] protocolBody = {0};
		if(value) {
			protocolBody[0] = 1;
		}
		
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_SET_METHOD_NEW_SECTION, protocolBody);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}

	/**
	 * Try to resize an executable section and to inject the shellcode there. This is possible because of the gap between the FileAlignment and the SectionAlignment value.
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetMethodAlignmentResize(boolean value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		byte[] protocolBody = {0};
		if(value) {
			protocolBody[0] = 1;
		}
		
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_SET_METHOD_ALIGNMENT_RESIZE, protocolBody);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}

	/**
	 * Try to inject the shellcode at the end of an executable section. This is possible because of the gap between the SizeOfRawData and the VirtualSize value.
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetMethodAlignment(boolean value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		byte[] protocolBody = {0};
		if(value) {
			protocolBody[0] = 1;
		}
		
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_SET_METHOD_ALIGNMENT, protocolBody);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}

	/**
	 * Remove integrated integrity checks, such as PE header checksums, certificates, force-check-checksum-flag, ...
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetRemoveIntegrityCheck(boolean value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		byte[] protocolBody = {0};
		if(value) {
			protocolBody[0] = 1;
		}
		
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_SET_REMOVE_INTEGRITY_CHECK, protocolBody);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}

	/**
	 * Sets the server to listen locally (loopback, 127.0.0.1) or globally (any, 0.0.0.0)<br>
	 * (1...local; 0...global)<br>
	 * (active after server restart)
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetDataInterface(boolean value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		byte[] protocolBody = {0};
		if(value) {
			protocolBody[0] = 1;
		}
		
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_SET_DATA_INTERFACE, protocolBody);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}
	
	/**
	 * Sets the server to listen locally (loopback, 127.0.0.1) or globally (any, 0.0.0.0)<br>
	 * (1...local; 0...global)<br>
	 * (active after server restart)
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetControlInterface(boolean value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		byte[] protocolBody = {0};
		if(value) {
			protocolBody[0] = 1;
		}
		
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_SET_CONTROL_INTERFACE, protocolBody);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}
	
	/**
	 * Generate a random name for sections created by the "new section name" flag.
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetRandomSectionName(boolean value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		byte[] protocolBody = {0};
		if(value) {
			protocolBody[0] = 1;
		}
		
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_SET_RANDOM_SECTION_NAME, protocolBody);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}
	
	/**
	 * Try to discover if the executable could possibly detect infection (e.g. NSIS setups) and skip the executable.
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetTryStayStealth(boolean value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		byte[] protocolBody = {0};
		if(value) {
			protocolBody[0] = 1;
		}
		
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_SET_TRY_STAY_STEALTH, protocolBody);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}

	/**
	 * enable/disable the injection of the pe-injector
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetEnable(boolean value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		byte[] protocolBody = {0};
		if(value) {
			protocolBody[0] = 1;
		}
		
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_SET_ENABLE, protocolBody);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}
	
	/**
	 * Encrypt payload with random keys. The decryption stub is generated and obfuscated individually on-the-fly for each injection, using the integrated polymorphic engine.
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetEncrypt(boolean value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		byte[] protocolBody = {0};
		if(value) {
			protocolBody[0] = 1;
		}
		
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_SET_ENCRYPT, protocolBody);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}

	/**
	 * Inject shellcode with one of the enabled methods and insert an obfuscated jump to the payload in another section. The EP doesn't point to the shellcode now, but this can increase some AV's heuristic detection rate.
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetMethodCrossSectionJump(boolean value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		byte[] protocolBody = {0};
		if(value) {
			protocolBody[0] = 1;
		}
		
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_SET_METHOD_CROSS_SECTION_JUMP, protocolBody);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}

	
	// send-string-commands
	// ------------------------------------------------------------------------------
	/**
	 * send a string to the server, he will repeat it
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public String cmdSendEcho(String value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		if(null == value) {
			value = "";
		}
		byte[] protocolBody = value.getBytes();
		
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_ECHO, protocolBody);

		// this and getConfig return a String!!!
		if(null == msg) {
			return "";
		}else {
			try {
				return new String(msg, "UTF-8");
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
				return "";
			}
		}
	}

	/**
	 * Set a static name for sections created by the "new section method" flag.
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetSectionName(String value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		if(null == value) {
			value = "";
		}
		byte[] protocolBody = value.getBytes();
		
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_SET_SECTION_NAME, protocolBody);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}

	/**
	 * set a name für the active shellcode (x86)
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetPayloadNameX86(String value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		if(null == value) {
			value = "";
		}
		byte[] protocolBody = value.getBytes();
		
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_SET_PAYLOAD_NAME_X86, protocolBody);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}

	/**
	 * set a name für the active shellcode (x64)
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetPayloadNameX64(String value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		if(null == value) {
			value = "";
		}
		byte[] protocolBody = value.getBytes();
		
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_SET_PAYLOAD_NAME_X64, protocolBody);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}

	
	// send-integer-commands
	// ------------------------------------------------------------------------------
	/**
	 * Port on which the server listens for raw data (PE files/headers)
	 * (active after server restart)
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetDataPort(int value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		byte[] protocolBody = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array();
				
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_SET_DATA_PORT, protocolBody);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}

	/**
	 * Port on which the server listens for control commands (Like from this interface)
	 * (active after server restart)
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetControlPort(int value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		byte[] protocolBody = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array();
		
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_SET_CONTROL_PORT, protocolBody);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}
	
	/**
	 * Set how many jump-indirections should be inserted before the shellcode (1-64, 1-5 should be enough, increasing this value can improve some AV's heuristic detection rate).
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetMethodCrossSectionJumpIterations(int value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		byte[] protocolBody = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array();
		
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_SET_METHOD_CROSS_SECTION_JUMP_ITERATIONS, protocolBody);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}

	/**
	 * Set how many encryption iterations should be applied (1-16, 1-3 should be enough, increasing this value can improve some AV's heuristic detection rate).
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetEncryptIterations(int value) throws LibPeProtocolException, LibPeSocketException {
		// convert value
		byte[] protocolBody = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array();
		
		// send cmd
		byte[] msg = cmdSend(CMD_SEND_SET_ENCRYPT_ITERATIONS, protocolBody);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}


	// send-byte-commands
	// ------------------------------------------------------------------------------
	/**
	 * set a shellcode for injection
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetPayloadX86(byte[] value) throws LibPeProtocolException, LibPeSocketException {
		byte[] msg = cmdSend(CMD_SEND_SET_PAYLOAD_X86, value);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}

	/**
	 * set a shellcode for injection
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetPayloadX64(byte[] value) throws LibPeProtocolException, LibPeSocketException {
		byte[] msg = cmdSend(CMD_SEND_SET_PAYLOAD_X64, value);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}
	
	/**
	 * set a new token for the data and control communication
	 * 
	 * @param value
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendSetToken(byte[] value) throws LibPeProtocolException, LibPeSocketException {
		byte[] msg = cmdSend(CMD_SEND_SET_TOKEN, value);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}
	
	
	// void commands
	// ------------------------------------------------------------------------------
	/**
	 * If the ports or interfaces set incorrectly you won't be able to contact the server through this interface. If you've changed the control port you'll have to adjust the settings of this interface too.
	 * 
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendRestart() throws LibPeProtocolException, LibPeSocketException {
		byte[] msg = cmdSend(CMD_SEND_RESTART, null);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}
	
	/**
	 * Shutdown?! lol!!!  never do this!
	 * 
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public boolean cmdSendShutdown() throws LibPeProtocolException, LibPeSocketException {
		byte[] msg = cmdSend(CMD_SEND_SHUTDOWN, null);
		return (null != msg); // TRUE: server sends CMD_RECEIVE_SUCCESS
	}

	/**
	 * return the active config of the server (ini file)
	 * 
	 * @return true...all is ok; false...servererror OR WRONG TOKEN!!!!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public String cmdSendGetConfig() throws LibPeProtocolException, LibPeSocketException {
		byte[] msg = cmdSend(CMD_SEND_GET_CONFIG, null);
		
		// this and echo return a String!!!
		if(null == msg) {
			return "";
		}else {
			try {
				return new String(msg, "UTF-8");
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
				return "";
			}
		}
	}
	
	/**
	 * Call {@link #cmdSendGetConfig()} and parse with {@link LibPeServerConfig}!
	 * 
	 * @throws LibPeProtocolException if the control protocol is corrupt
	 * @throws LibPeSocketException if timeout expires before connecting, or if the IP address of the host could not be determined, or if an I/O error occurs when creating the socket 
	 */
	public LibPeServerConfig cmdSendGetConfigAndParse() throws LibPeProtocolException, LibPeSocketException {
		String serverconfigini = cmdSendGetConfig();
		return new LibPeServerConfig(serverconfigini);
	}

	
	
}
