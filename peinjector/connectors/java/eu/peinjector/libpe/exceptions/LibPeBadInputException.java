package eu.peinjector.libpe.exceptions;

/**
 * bad user input
 */
public class LibPeBadInputException extends LibPeException {

	private static final long serialVersionUID = -8790189648003200022L;

	public LibPeBadInputException() {
		super();
	}
	
	public LibPeBadInputException(String message) {
		super(message);
	}
}
