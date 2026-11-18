package com.vexsoftware.votifier.net;

import java.io.BufferedReader;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;

import com.google.gson.JsonObject;
import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.model.Vote;

public class VoteForwarder {

	private static final String HANDSHAKE_PREFIX = "VOTIFIER";
	private static final String HANDSHAKE_V2 = "2";
	private static final String OPCODE_VOTE = "VOTE";
	private static final String FIELD_PAYLOAD = "payload";
	private static final String FIELD_SIGNATURE = "signature";
	private static final String FIELD_SERVICE_NAME = "serviceName";
	private static final String FIELD_USERNAME = "username";
	private static final String FIELD_ADDRESS = "address";
	private static final String FIELD_TIMESTAMP = "timestamp";
	private static final String FIELD_CHALLENGE = "challenge";
	private static final int MAX_HANDSHAKE_CHARS = 512;
	private static final int CONNECT_TIMEOUT_MILLIS = 1000;
	private static final int HANDSHAKE_TIMEOUT_MILLIS = 3000;

	private final VoteReceiver receiver;
	private final Set<Socket> activeSockets = new HashSet<>();
	private volatile boolean stopped;

	public VoteForwarder(VoteReceiver receiver) {
		this.receiver = receiver;
	}

	public void forwardVote(Vote vote) {
		for (String name : receiver.getServers()) {
			if (stopped || Thread.currentThread().isInterrupted()) {
				return;
			}
			ForwardServer server = receiver.getServerData(name);

			if (!server.isEnabled()) {
				receiver.debug("Skipping disabled forward server: " + VoteLogSafety.field(name));
				continue;
			}

			receiver.debug("Preparing to forward vote to: " + VoteLogSafety.field(name) + ", tokens mode: " + server.isUseTokens());

			Socket socket = new Socket();
			try (socket) {
				synchronized (activeSockets) {
					if (stopped) {
						return;
					}
					activeSockets.add(socket);
				}
				socket.connect(new InetSocketAddress(server.getHost(), server.getPort()), CONNECT_TIMEOUT_MILLIS);
				String greeting = readHandshakeLine(socket, HANDSHAKE_TIMEOUT_MILLIS);
				OutputStream out = socket.getOutputStream();
				receiver.debug("Received handshake from " + VoteLogSafety.field(name)
						+ " (" + (greeting == null ? 0 : greeting.length()) + " chars)");

				byte[] payload;
				if (server.isUseTokens()) {
					String[] parts = greeting.split(" ");
					if (parts.length < 3 || !HANDSHAKE_PREFIX.equals(parts[0]) || !HANDSHAKE_V2.equals(parts[1])) {
						throw new IllegalStateException("Invalid token-mode handshake");
					}

					String challenge = parts[2];

					JsonObject inner = new JsonObject();
					inner.addProperty(FIELD_SERVICE_NAME, vote.getServiceName());
					inner.addProperty(FIELD_USERNAME, vote.getUsername());
					inner.addProperty(FIELD_ADDRESS, vote.getAddress());
					inner.addProperty(FIELD_TIMESTAMP, vote.getTimeStamp());
					inner.addProperty(FIELD_CHALLENGE, challenge);

					String innerJson = inner.toString();

					Mac mac = Mac.getInstance("HmacSHA256");
					mac.init(server.getToken());
					String sig = Base64.getEncoder()
							.encodeToString(mac.doFinal(innerJson.getBytes(StandardCharsets.UTF_8)));

					JsonObject outer = new JsonObject();
					outer.addProperty(FIELD_PAYLOAD, innerJson);
					outer.addProperty(FIELD_SIGNATURE, sig);

					payload = (outer.toString() + "\r\n").getBytes(StandardCharsets.UTF_8);
				} else {
					String voteString = String.join("\n", OPCODE_VOTE, vote.getServiceName(), vote.getUsername(),
							vote.getAddress(), vote.getTimeStamp(), "") + "\n";
					payload = receiver.encrypt(voteString.getBytes(StandardCharsets.UTF_8), receiver.getPublicKey(server));
				}

				out.write(payload);
				out.flush();
				receiver.debug("Payload forwarded to " + VoteLogSafety.field(name) + " (" + payload.length + " bytes)");
			} catch (Exception ex) {
				if (!stopped) {
					receiver.log("Failed to forward vote to " + VoteLogSafety.field(name) + ": "
							+ VoteLogSafety.exceptionType(ex));
				}
			} finally {
				synchronized (activeSockets) {
					activeSockets.remove(socket);
				}
			}
		}
	}

	int stop() {
		List<Socket> sockets;
		synchronized (activeSockets) {
			stopped = true;
			sockets = List.copyOf(activeSockets);
			activeSockets.clear();
		}
		for (Socket socket : sockets) {
			try {
				socket.close();
			} catch (IOException ex) {
				receiver.debug("Failed to close forwarding socket: " + VoteLogSafety.exceptionType(ex));
			}
		}
		return sockets.size();
	}

	static String readHandshakeLine(Socket socket, int timeoutMillis) throws Exception {
		long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
		// The decoder can make multiple reads to produce one character. Apply the
		// remaining budget at each socket read, including CR lookahead.
		var input = new FilterInputStream(socket.getInputStream()) {
			@Override
			public int read(byte[] bytes, int offset, int length) throws IOException {
				long remaining = deadline - System.nanoTime();
				if (remaining <= 0) {
					throw new SocketTimeoutException("Forward handshake timed out");
				}
				socket.setSoTimeout((int) Math.max(1, TimeUnit.NANOSECONDS.toMillis(remaining)));
				return super.read(bytes, offset, length);
			}
		};
		var reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
		String greeting = readHandshakeLine(reader);
		if (deadline - System.nanoTime() <= 0) {
			throw new SocketTimeoutException("Forward handshake timed out");
		}
		return greeting;
	}

	static String readHandshakeLine(BufferedReader in) throws Exception {
		StringBuilder line = new StringBuilder();
		int value;
		while ((value = in.read()) != -1) {
			if (value == '\r') {
				in.mark(1);
				int next = in.read();
				if (next != '\n' && next != -1) {
					in.reset();
				}
				return line.toString();
			}
			if (value == '\n') {
				return line.toString();
			}
			if (line.length() >= MAX_HANDSHAKE_CHARS) {
				throw new IllegalStateException("Forward server handshake exceeds limit");
			}
			line.append((char) value);
		}
		return line.length() == 0 ? null : line.toString();
	}
}
