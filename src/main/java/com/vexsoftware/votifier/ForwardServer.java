package com.vexsoftware.votifier;

import lombok.Getter;

public class ForwardServer {
	@Getter
	private String host;
	@Getter
	private int port;
	@Getter
	private String key;
	@Getter
	private boolean enabled;

	public ForwardServer(boolean enabled, String host, int port, String key) {
		this.enabled = enabled;
		this.host = host;
		this.port = port;
		this.key = key;
	}
}
