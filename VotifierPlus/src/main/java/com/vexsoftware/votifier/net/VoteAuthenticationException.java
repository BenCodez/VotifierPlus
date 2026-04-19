package com.vexsoftware.votifier.net;

public class VoteAuthenticationException extends Exception {

	private static final long serialVersionUID = 1L;

	public VoteAuthenticationException(String message) {
		super(message);
	}

	public VoteAuthenticationException(String message, Throwable cause) {
		super(message, cause);
	}
}