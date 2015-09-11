package eu.peinjector.libpe.exceptions;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

/**
 * Socket exceptions
 * 
 * @see IOException
 * @see SocketTimeoutException
 * @see UnknownHostException
 */
public class LibPeSocketException extends LibPeException {

	private static final long serialVersionUID = 6314115271909409845L;

	public LibPeSocketException() {
		super();
	}
	
	public LibPeSocketException(String message) {
		super(message);
	}
}
