/*
 * Derived from original Votifier VoteReceiver (GPLv3).
 * Refactored into a dedicated component by BenCodez.
 *
 * See VoteReceiver for full modification summary.
 */
package com.vexsoftware.votifier.net;

import java.io.BufferedWriter;
import java.io.OutputStreamWriter;
import java.io.PushbackInputStream;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;

import javax.crypto.BadPaddingException;

import com.google.gson.JsonObject;
import com.google.gson.stream.MalformedJsonException;
import com.vexsoftware.votifier.model.Vote;

/**
 * Handles a single accepted vote connection.
 */
public class VoteConnectionHandler {

	private final VoteReceiver receiver;
	private final VoteThrottleService throttleService;
	private final ProxyHeaderProcessor proxyHeaderProcessor;
	private final VoteParser voteParser;

	public VoteConnectionHandler(VoteReceiver receiver, VoteThrottleService throttleService) {
		this.receiver = receiver;
		this.throttleService = throttleService;
		this.proxyHeaderProcessor = new ProxyHeaderProcessor();
		this.voteParser = new VoteParser();
	}

	/**
	 * Handles a single socket connection.
	 *
	 * @param socket the accepted socket
	 * @return the parsed vote, or null if the connection should be ignored/dropped
	 */
	public Vote handle(Socket socket) {
		String remoteIp = "unknown";
		String address = "";
		String throttleKey = null;
		boolean tunnelMode = false;
		boolean realIpKnown = false;

		try (Socket accepted = socket;
				PushbackInputStream in = new PushbackInputStream(accepted.getInputStream(), 512);
				BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(accepted.getOutputStream()))) {

			remoteIp = accepted.getInetAddress().getHostAddress();
			address = accepted.getRemoteSocketAddress() == null ? "/" + remoteIp
					: accepted.getRemoteSocketAddress().toString();

			receiver.debug("Accepted connection from: " + address);
			accepted.setSoTimeout(5000);

			String challenge = receiver.getChallenge();
			sendHandshakeIfNeeded(in, writer, challenge);

			if (!waitForPayload(in, accepted, address)) {
				return null;
			}

			String realIp = null;
			ProxyHeaderProcessor.ProxyHeaderResult proxyResult = proxyHeaderProcessor.process(in, writer, receiver,
					accepted);
			realIp = proxyResult.getRealIp();

			realIpKnown = realIp != null && !realIp.isEmpty();
			tunnelMode = throttleService.isTunnelMode(remoteIp);
			throttleKey = realIpKnown ? "ip:" + realIp : "tunnel:" + remoteIp;

			if (throttleService.isBlocked(throttleKey)) {
				long retry = throttleService.retryAfterMs(throttleKey);
				throttleService.logWarning(receiver, "throttle|" + throttleKey, "Votifier throttling " + throttleKey
						+ " (tunnel=" + tunnelMode + "), retry in " + Math.max(0, retry / 1000) + "s");
				return null;
			}

			VoteProtocolVersion version = voteParser.detectVersion(in);
			receiver.debug("Detected vote protocol version: " + version);

			if (receiver.isDisableV1() && version == VoteProtocolVersion.V1) {
				throw new VoteAuthenticationException("Votifier V1 votes are disabled by configuration");
			}

			if (version == VoteProtocolVersion.V1 && in.available() < 256) {
				throttleService.fail(throttleKey, tunnelMode, realIpKnown);
				throttleService.logWarning(receiver, "shortv1|" + throttleKey,
						"Invalid vote format: Insufficient data for V1 vote block from "
								+ (realIpKnown ? realIp : remoteIp) + " (expected 256 bytes)");
				return null;
			}

			VoteRequest request = voteParser.parse(in, version, receiver, address, challenge);

			Vote vote = new Vote();
			vote.setServiceName(request.getServiceName());
			vote.setUsername(request.getUsername());
			vote.setAddress(request.getAddress());
			vote.setTimeStamp(request.getTimeStamp());
			vote.setSourceAddress(realIpKnown ? realIp : remoteIp);

			if ("TestVote".equalsIgnoreCase(vote.getTimeStamp())) {
				receiver.log("Test vote received");
			}

			receiver.log("Received vote record -> " + vote);
			throttleService.success(throttleKey);

			if (!"TestVote".equalsIgnoreCase(vote.getTimeStamp())) {
				sendOkResponse(writer);
			}

			return vote;
		} catch (InvalidVoteException ex) {
			if (throttleKey == null) {
				throttleKey = "tunnel:" + remoteIp;
			}

			throttleService.fail(throttleKey, tunnelMode, realIpKnown);
			throttleService.logWarning(receiver, "invalid|" + throttleKey,
					"Invalid vote format from " + remoteIp + ": " + ex.getMessage());
		} catch (VoteAuthenticationException ex) {
			if (throttleKey == null) {
				throttleKey = "tunnel:" + remoteIp;
			}

			throttleService.fail(throttleKey, tunnelMode, realIpKnown);
			throttleService.logWarning(receiver, "auth|" + throttleKey,
					"Authentication failed from " + remoteIp + ": " + ex.getMessage());
		} catch (MalformedJsonException ex) {
			if (throttleKey == null) {
				throttleKey = "tunnel:" + remoteIp;
			}

			throttleService.fail(throttleKey, tunnelMode, false);
			throttleService.logWarning(receiver, "malformedjson|" + throttleKey,
					"Invalid vote format: Malformed JSON payload from " + remoteIp + " - " + ex.getMessage());
		} catch (BadPaddingException ex) {
			if (throttleKey == null) {
				throttleKey = "tunnel:" + remoteIp;
			}

			throttleService.fail(throttleKey, tunnelMode, realIpKnown);
			throttleService.logWarning(receiver, "badpadding|" + throttleKey,
					"Decryption failed: Invalid V1 vote block / public key mismatch from " + remoteIp);
		} catch (SocketTimeoutException ex) {
			throttleService.logWarning(receiver, "timeout|" + remoteIp,
					"Connection timeout while waiting for vote payload from " + remoteIp + " - " + ex.getMessage());
		} catch (SocketException ex) {
			throttleService.logWarning(receiver, "socket|" + remoteIp,
					"Connection error: Protocol error from " + remoteIp + " - " + ex.getLocalizedMessage());
		} catch (Exception ex) {
			throttleService.logWarning(receiver, "generic|" + remoteIp, "Error processing vote from " + remoteIp + ": "
					+ (ex.getLocalizedMessage() == null ? ex.getClass().getSimpleName() : ex.getLocalizedMessage()));
		}

		return null;
	}

	private void sendHandshakeIfNeeded(PushbackInputStream in, BufferedWriter writer, String challenge)
			throws Exception {
		boolean useV2Handshake = receiver.isUseTokens() || receiver.isDisableV1();
		String message = useV2Handshake ? "VOTIFIER 2 " + challenge : "VOTIFIER 1";

		int available = in.available();
		if (available >= 256 && !receiver.isDisableV1()) {
			receiver.debug("Detected V1 vote payload before handshake (available bytes: " + available
					+ "), skipping handshake.");
			return;
		}

		writer.write(message);
		writer.newLine();
		writer.flush();
		receiver.debug("Sent handshake: " + message);
	}

	private boolean waitForPayload(PushbackInputStream in, Socket socket, String address) throws Exception {
		int previousTimeout = socket.getSoTimeout();

		try {
			socket.setSoTimeout(2000);
			int firstByte = in.read();
			if (firstByte == -1) {
				receiver.debug("Connection closed without payload from " + address);
				return false;
			}

			in.unread(firstByte);
			return true;
		} finally {
			socket.setSoTimeout(previousTimeout);
		}
	}

	private void sendOkResponse(BufferedWriter writer) {
		try {
			JsonObject okResponse = new JsonObject();
			okResponse.addProperty("status", "ok");
			String okMessage = okResponse.toString() + "\r\n";
			writer.write(okMessage);
			writer.flush();
			receiver.debug("Sent OK response: " + okMessage);
		} catch (Exception ex) {
			receiver.debug(
					"Failed to send OK response, but will continue to process vote: " + ex.getLocalizedMessage());
		}
	}
}
