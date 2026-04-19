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

	private final VoteReceiver receiver;

	public VoteForwarder(VoteReceiver receiver) {
		this.receiver = receiver;
	}

	public void forwardVote(Vote vote) {
		for (String name : receiver.getServers()) {
			ForwardServer server = receiver.getServerData(name);

			if (!server.isEnabled()) {
				receiver.debug("Skipping disabled forward server: " + name);
				continue;
			}

			receiver.debug("Preparing to forward vote to: " + name + ", tokens mode: " + server.isUseTokens());

			try (Socket socket = new Socket()) {
				socket.connect(new InetSocketAddress(server.getHost(), server.getPort()), 1000);

				BufferedReader in = new BufferedReader(
						new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
				OutputStream out = socket.getOutputStream();

				String greeting = in.readLine();
				receiver.debug("Received handshake from " + name + ": '" + greeting + "'");

				byte[] payload;
				if (server.isUseTokens()) {
					String[] parts = greeting.split(" ");
					if (parts.length < 3 || !"VOTIFIER".equals(parts[0]) || !"2".equals(parts[1])) {
						throw new IllegalStateException("Invalid token-mode handshake from " + name + ": " + greeting);
					}

					String challenge = parts[2];

					JsonObject inner = new JsonObject();
					inner.addProperty("serviceName", vote.getServiceName());
					inner.addProperty("username", vote.getUsername());
					inner.addProperty("address", vote.getAddress());
					inner.addProperty("timestamp", vote.getTimeStamp());
					inner.addProperty("challenge", challenge);

					String innerJson = inner.toString();

					Mac mac = Mac.getInstance("HmacSHA256");
					mac.init(server.getToken());
					String sig = Base64.getEncoder()
							.encodeToString(mac.doFinal(innerJson.getBytes(StandardCharsets.UTF_8)));

					JsonObject outer = new JsonObject();
					outer.addProperty("payload", innerJson);
					outer.addProperty("signature", sig);

					payload = (outer.toString() + "\r\n").getBytes(StandardCharsets.UTF_8);
				} else {
					String voteString = String.join("\n", "VOTE", vote.getServiceName(), vote.getUsername(),
							vote.getAddress(), vote.getTimeStamp(), "") + "\n";
					payload = receiver.encrypt(voteString.getBytes(StandardCharsets.UTF_8), receiver.getPublicKey(server));
				}

				out.write(payload);
				out.flush();
				receiver.debug("Payload forwarded to " + name + " (" + payload.length + " bytes)");
			} catch (Exception ex) {
				receiver.log("Failed to forward vote to " + name + ": " + ex.getClass().getSimpleName() + " - "
						+ ex.getMessage());
			}
		}
	}
}