package com.bencodez.votifierplus.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.Key;

import org.junit.jupiter.api.Test;

import com.vexsoftware.votifier.crypto.TokenUtil;

public class TokenUtilTest {

	@Test
	public void newTokenGeneratesNonEmptyString() {
		String token = TokenUtil.newToken();
		assertNotNull(token);
		assertFalse(token.isEmpty());
	}

	@Test
	public void newTokenGeneratesUniqueTokens() {
		String token1 = TokenUtil.newToken();
		String token2 = TokenUtil.newToken();
		assertNotEquals(token1, token2);
	}

	@Test
	public void createKeyFromValidToken() {
		String token = "testToken";
		Key key = TokenUtil.createKeyFrom(token);
		assertNotNull(key);
		assertEquals("HmacSHA256", key.getAlgorithm());
	}

	@Test
	public void createKeyFromEmptyTokenThrowsException() {
		String token = "";
		assertThrows(IllegalArgumentException.class, () -> {
			TokenUtil.createKeyFrom(token);
		});
	}

	@Test
	public void createKeyFromNullTokenThrowsException() {
		assertThrows(NullPointerException.class, () -> {
			TokenUtil.createKeyFrom(null);
		});
	}
}
