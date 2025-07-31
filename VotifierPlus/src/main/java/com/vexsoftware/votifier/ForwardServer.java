package com.vexsoftware.votifier;

import java.security.Key;

import lombok.Getter;
import lombok.Setter;

public class ForwardServer {
	@Getter
	private String host;
	@Getter
	private int port;
	@Getter
	private String key;
	@Getter
	private boolean enabled;

	@Getter
	@Setter
	private Key Token;

	public ForwardServer(boolean enabled, String host, int port, String key, Key token) {
		this.enabled = enabled;
		this.host = host;
		this.port = port;
		this.key = key;
		this.Token = token;
	}

	public boolean isUseTokens() {
		return Token != null;
	}
}
