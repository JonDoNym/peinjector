package eu.peinjector.libpe.exceptions;

/**
 * libpe-protocol exceptions  (unknown command, corrupt fields, ...)
 */
public class LibPeProtocolException extends LibPeException {

	private static final long serialVersionUID = 1134748679697805831L;

	public LibPeProtocolException() {
		super();
	}
	
	public LibPeProtocolException(String message) {
		super(message);
	}
}
