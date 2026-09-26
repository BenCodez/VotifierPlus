package com.vexsoftware.votifier.net;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

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

	private final VoteReceiver receiver;

	public VoteForwarder(VoteReceiver receiver) {
		this.receiver = receiver;
	}

	public void forwardVote(Vote vote) {
		for (String name : receiver.getServers()) {
			ForwardServer server = receiver.getServerData(name);

			if (!server.isEnabled()) {
				receiver.debug("Skipping disabled forward server: " + VoteLogSafety.field(name));
				continue;
			}

			receiver.debug("Preparing to forward vote to: " + VoteLogSafety.field(name) + ", tokens mode: " + server.isUseTokens());

			try (Socket socket = new Socket()) {
				socket.connect(new InetSocketAddress(server.getHost(), server.getPort()), 1000);
				socket.setSoTimeout(3000);

				BufferedReader in = new BufferedReader(
						new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
				OutputStream out = socket.getOutputStream();

				String greeting = readHandshakeLine(in);
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
				receiver.log("Failed to forward vote to " + VoteLogSafety.field(name) + ": "
						+ VoteLogSafety.exceptionType(ex));
			}
		}
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
