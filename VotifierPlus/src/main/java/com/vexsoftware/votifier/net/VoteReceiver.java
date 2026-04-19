package com.vexsoftware.votifier.net;

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.SocketException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

import javax.crypto.Cipher;

import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.model.Vote;

import lombok.Getter;

public abstract class VoteReceiver extends Thread {

	private final String host;
	private final int port;

	@Getter
	private ServerSocket server;

	private volatile boolean running = true;

	private volatile VoteThrottleService throttleService;
	private volatile VoteForwarder voteForwarder;

	public VoteReceiver(String host, int port) throws Exception {
		super("Votifier I/O");
		this.host = host;
		this.port = port;
		setPriority(Thread.MIN_PRIORITY);
		initialize();
	}

	public void initialize() throws Exception {
		try {
			server = new ServerSocket();
			server.bind(new InetSocketAddress(host, port));
			debug("Bound to " + server.getInetAddress().getHostAddress() + ":" + server.getLocalPort());
		} catch (Exception ex) {
			logSevere(
					"Error initializing vote receiver. Please verify that the configured IP address and port are not already in use.");
			ex.printStackTrace();
			throw new Exception(ex);
		}
	}

	public void shutdown() {
		running = false;
		if (server == null) {
			return;
		}

		try {
			server.close();
		} catch (Exception ex) {
			logWarning("Unable to shut down vote receiver cleanly.");
		}
	}

	@Override
	public void run() {
		throttleService = new VoteThrottleService(getThrottleConfig());
		voteForwarder = new VoteForwarder(this);

		while (running) {
			try {
				VoteConnectionHandler handler = new VoteConnectionHandler(this, throttleService, voteForwarder);
				handler.handle(server.accept());
			} catch (SocketException ex) {
				if (running) {
					throttleService.logSocketError("unknown", ex);
				} else {
					logWarning("Votifier socket closed.");
				}
			} catch (Exception ex) {
				throttleService.logGenericError("unknown", ex);
			}
		}
	}

	public abstract boolean isUseTokens();

	public abstract ThrottleConfig getThrottleConfig();

	public abstract void logWarning(String warn);

	public abstract void logSevere(String msg);

	public abstract void log(String msg);

	public abstract void debug(String msg);

	public abstract void debug(Exception e);

	public abstract String getVersion();

	public abstract Set<String> getServers();

	public abstract KeyPair getKeyPair();

	public abstract Map<String, Key> getTokens();

	public abstract ForwardServer getServerData(String s);

	public abstract void callEvent(Vote e);

	public byte[] encrypt(byte[] data, PublicKey key) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(data);
	}

	public PublicKey getPublicKey(ForwardServer forwardServer) throws Exception {
		byte[] encoded = Base64.getDecoder().decode(forwardServer.getKey());
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
	}

	public String getChallenge() {
		return com.vexsoftware.votifier.crypto.TokenUtil.newToken();
	}
}