package com.vexsoftware.votifier.net;

public class InvalidVoteException extends Exception {

	private static final long serialVersionUID = 1L;

	public InvalidVoteException(String message) {
		super(message);
	}

	public InvalidVoteException(String message, Throwable cause) {
		super(message, cause);
	}
}