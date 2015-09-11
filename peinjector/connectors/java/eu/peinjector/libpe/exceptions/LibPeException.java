package eu.peinjector.libpe.exceptions;

/**
 * From this class expand all libpe-subclasses
 */
public class LibPeException extends Exception {

	private static final long serialVersionUID = -7020499578589899002L;

	public LibPeException() {
		super();
	}
	
	public LibPeException(String message) {
		super(message);
	}
}
