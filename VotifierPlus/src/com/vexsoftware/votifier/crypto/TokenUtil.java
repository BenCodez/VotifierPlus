package com.vexsoftware.votifier.crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class TokenUtil {
	private static final SecureRandom RANDOM = new SecureRandom();

	public static String newToken() {
		return new BigInteger(130, RANDOM).toString(32);
	}
	
	 public static Key createKeyFrom(String token) {
	        return new SecretKeySpec(token.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
	    }
}
