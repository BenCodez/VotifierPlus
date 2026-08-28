/*
 * Derived from original Votifier VoteReceiver (GPLv3).
 * Refactored into a dedicated component by BenCodez.
 *
 * See VoteReceiver for full modification summary.
 */
package com.vexsoftware.votifier.net;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PushbackInputStream;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.vexsoftware.votifier.crypto.RSA;

/**
 * Parses incoming vote payloads.
 */
public class VoteParser {

	private static final Gson GSON = new Gson();
	private static final short PROTOCOL_2_MAGIC = (short) 0x733A;
	private static final int PROTOCOL_VERSION_PREFIX_BYTES = 2;
	private static final int V1_BLOCK_BYTES = 256;
	private static final int MAX_V2_PACKET_BYTES = 4 + 0xFFFF;
	private static final int V2_PACKET_READ_TIMEOUT_MS = 5000;
	private static final int V1_COLLISION_GRACE_TIMEOUT_MS = 250;

	private static final String FIELD_PAYLOAD = "payload";
	private static final String FIELD_SIGNATURE = "signature";
	private static final String FIELD_SERVICE_NAME = "serviceName";
	private static final String FIELD_USERNAME = "username";
	private static final String FIELD_ADDRESS = "address";
	private static final String FIELD_TIMESTAMP = "timestamp";
	private static final String FIELD_CHALLENGE = "challenge";
	private static final String OPCODE_VOTE = "VOTE";

	/**
	 * Detects the vote protocol version from the first bytes of the stream.
	 *
	 * @param in the stream
	 * @return the detected protocol version
	 * @throws Exception if there is not enough data to determine the protocol
	 */
	public VoteProtocolVersion detectVersion(PushbackInputStream in) throws Exception {
		return detectVersion(in, null, 0);
	}

	private VoteProtocolVersion detectVersion(PushbackInputStream in, Socket socket, long deadlineNanos)
			throws Exception {
		byte[] header = new byte[PROTOCOL_VERSION_PREFIX_BYTES];
		int bytesRead = 0;
		while (bytesRead < header.length) {
			setRemainingTimeout(socket, deadlineNanos);
			int read = in.read(header, bytesRead, header.length - bytesRead);
			if (read == -1) {
				break;
			}
			bytesRead += read;
		}

		if (bytesRead < 2) {
			throw new Exception("Not enough data available to determine vote protocol version.");
		}

		in.unread(header, 0, bytesRead);

		if ((char) header[0] == '{') {
			return VoteProtocolVersion.V2;
		}

		short magic = (short) (((header[0] & 0xFF) << 8) | (header[1] & 0xFF));
		if (magic == PROTOCOL_2_MAGIC) {
			return VoteProtocolVersion.V2;
		}

		return VoteProtocolVersion.V1;
	}

	/**
	 * Detects and parses a network vote under one packet-read deadline.
	 *
	 * @param in        the input stream
	 * @param receiver  the vote receiver
	 * @param address   remote address string for logging/errors
	 * @param challenge expected challenge for V2
	 * @param socket    accepted connection socket
	 * @return parsed vote request data
	 * @throws Exception on protocol detection, parsing, validation, or authentication errors
	 */
	public VoteRequest parse(PushbackInputStream in, VoteReceiver receiver, String address, String challenge,
			Socket socket) throws Exception {
		int previousTimeout = socket.getSoTimeout();
		long deadlineNanos = System.nanoTime() + V2_PACKET_READ_TIMEOUT_MS * 1_000_000L;
		try {
			VoteProtocolVersion version = detectVersion(in, socket, deadlineNanos);
			receiver.debug("Detected vote protocol version: " + version);

			if (receiver.isDisableV1() && version == VoteProtocolVersion.V1) {
				throw new VoteAuthenticationException("Votifier V1 votes are disabled by configuration");
			}

			return parseWithDeadline(in, version, receiver, address, challenge, socket, deadlineNanos);
		} finally {
			socket.setSoTimeout(previousTimeout);
		}
	}

	/**
	 * Parses the vote payload based on the detected protocol version.
	 *
	 * @param in        the input stream
	 * @param version   the detected protocol version
	 * @param receiver  the vote receiver
	 * @param address   remote address string for logging/errors
	 * @param challenge expected challenge for V2
	 * @return parsed vote request data
	 * @throws Exception on parse/validation/authentication errors
	 */
	public VoteRequest parse(PushbackInputStream in, VoteProtocolVersion version, VoteReceiver receiver, String address,
			String challenge) throws Exception {
		return parse(in, version, receiver, address, challenge, null);
	}

	/**
	 * Parses a vote payload with access to the connection socket so V2 reads have
	 * an absolute deadline and an ambiguous V1 collision can receive a short,
	 * bounded TCP-fragment grace period.
	 *
	 * @param in        the input stream
	 * @param version   the detected protocol version
	 * @param receiver  the vote receiver
	 * @param address   remote address string for logging/errors
	 * @param challenge expected challenge for V2
	 * @param socket    accepted socket, or null when no timeout control is available
	 * @return parsed vote request data
	 * @throws Exception on parse/validation/authentication errors
	 */
	public VoteRequest parse(PushbackInputStream in, VoteProtocolVersion version, VoteReceiver receiver, String address,
			String challenge, Socket socket) throws Exception {
		if (version == VoteProtocolVersion.V1) {
			return parseV1(in, receiver, address);
		}

		int previousTimeout = socket == null ? 0 : socket.getSoTimeout();
		long deadlineNanos = socket == null ? 0
				: System.nanoTime() + V2_PACKET_READ_TIMEOUT_MS * 1_000_000L;
		try {
			return parseWithDeadline(in, version, receiver, address, challenge, socket, deadlineNanos);
		} finally {
			if (socket != null) {
				socket.setSoTimeout(previousTimeout);
			}
		}
	}

	private VoteRequest parseWithDeadline(PushbackInputStream in, VoteProtocolVersion version, VoteReceiver receiver,
			String address, String challenge, Socket socket, long deadlineNanos) throws Exception {
		if (version == VoteProtocolVersion.V1) {
			return parseV1(in, receiver, address);
		}

		ByteArrayOutputStream voteData = new ByteArrayOutputStream();
		if (!readToSize(in, voteData, PROTOCOL_VERSION_PREFIX_BYTES, socket, deadlineNanos)) {
			throw new InvalidVoteException("Incomplete V2 protocol prefix from " + address);
		}

		byte[] prefix = voteData.toByteArray();
		short magic = (short) (((prefix[0] & 0xFF) << 8) | (prefix[1] & 0xFF));
		if (magic == PROTOCOL_2_MAGIC) {
			return parseFramedV2(in, voteData, receiver, address, challenge, socket, deadlineNanos);
		}
		if ((char) prefix[0] == '{') {
			return parseUnframedV2(in, voteData, receiver, address, challenge, socket, deadlineNanos);
		}

		throw new InvalidVoteException("Invalid V2 protocol prefix from " + address);
	}

	private VoteRequest parseFramedV2(PushbackInputStream in, ByteArrayOutputStream voteData, VoteReceiver receiver,
			String address, String challenge, Socket socket, long deadlineNanos) throws Exception {
		if (!readToSize(in, voteData, 4, socket, deadlineNanos)) {
			throw new InvalidVoteException("Incomplete V2 frame header from " + address);
		}

		byte[] header = voteData.toByteArray();
		int payloadBytes = ((header[2] & 0xFF) << 8) | (header[3] & 0xFF);
		int frameBytes = 4 + payloadBytes;
		Exception v1Failure = null;

		// A randomized V1 block can claim a framed length greater than 256. Test
		// the complete V1-sized prefix before blocking for the rest of that frame.
		if (frameBytes > V1_BLOCK_BYTES && !receiver.isDisableV1()) {
			if (!readToSize(in, voteData, V1_BLOCK_BYTES, socket, deadlineNanos)) {
				throw new InvalidVoteException("Incomplete V2 frame from " + address + " (expected " + frameBytes
						+ " bytes, got " + voteData.size() + ")");
			}
			try {
				return parseV1Candidate(voteData.toByteArray(), receiver, address);
			} catch (Exception ex) {
				v1Failure = ex;
			}
		}

		if (!readToSize(in, voteData, frameBytes, socket, deadlineNanos)) {
			throw new InvalidVoteException("Incomplete V2 frame from " + address + " (expected " + frameBytes
					+ " bytes, got " + voteData.size() + ")");
		}

		try {
			return parseV2(voteData.toByteArray(), receiver, address, challenge);
		} catch (Exception v2Failure) {
			if (v1Failure != null) {
				v2Failure.addSuppressed(v1Failure);
			}
			return fallbackToBufferedV1OrThrow(in, voteData, receiver, address, v2Failure, socket, deadlineNanos);
		}
	}

	private VoteRequest parseUnframedV2(PushbackInputStream in, ByteArrayOutputStream voteData, VoteReceiver receiver,
			String address, String challenge, Socket socket, long deadlineNanos) throws Exception {
		JsonObjectBoundaryScanner scanner = new JsonObjectBoundaryScanner();
		byte[] prefix = voteData.toByteArray();
		int jsonBoundaryBytes = scanner.scan(prefix, 0, prefix.length);
		boolean complete = jsonBoundaryBytes >= 0;
		Exception v1Failure = null;
		boolean v1Attempted = false;
		byte[] buffer = new byte[4096];

		while (!complete) {
			if (!receiver.isDisableV1() && !v1Attempted && voteData.size() == V1_BLOCK_BYTES) {
				v1Attempted = true;
				try {
					return parseV1Candidate(voteData.toByteArray(), receiver, address);
				} catch (Exception ex) {
					v1Failure = ex;
				}
			}

			if (voteData.size() >= MAX_V2_PACKET_BYTES) {
				InvalidVoteException failure = new InvalidVoteException(
						"V2 JSON payload exceeds maximum size from " + address);
				if (v1Failure != null) {
					failure.addSuppressed(v1Failure);
				}
				throw failure;
			}

			int nextBoundary = voteData.size() < V1_BLOCK_BYTES ? V1_BLOCK_BYTES : MAX_V2_PACKET_BYTES;
			int maxRead = Math.min(buffer.length, nextBoundary - voteData.size());
			setRemainingTimeout(socket, deadlineNanos);
			int read = in.read(buffer, 0, maxRead);
			if (read == -1) {
				InvalidVoteException failure = new InvalidVoteException("Incomplete V2 JSON payload from " + address);
				if (v1Failure != null) {
					failure.addSuppressed(v1Failure);
				}
				throw failure;
			}

			int previousSize = voteData.size();
			int completeAt = scanner.scan(buffer, 0, read);
			// The entire chunk has already been consumed from the socket. Preserve its
			// suffix for a possible fixed-size V1 fallback, while parsing V2 only up
			// to the detected JSON boundary.
			voteData.write(buffer, 0, read);
			if (completeAt >= 0) {
				jsonBoundaryBytes = previousSize + completeAt;
			}
			complete = completeAt >= 0;
		}

		try {
			byte[] candidate = voteData.toByteArray();
			return parseV2(Arrays.copyOf(candidate, jsonBoundaryBytes), receiver, address, challenge);
		} catch (Exception v2Failure) {
			if (v1Failure != null) {
				v2Failure.addSuppressed(v1Failure);
			}
			return fallbackToBufferedV1OrThrow(in, voteData, receiver, address, v2Failure, socket, deadlineNanos);
		}
	}

	private VoteRequest parseV1(PushbackInputStream in, VoteReceiver receiver, String address) throws Exception {
		byte[] block = new byte[V1_BLOCK_BYTES];
		int totalRead = 0;

		while (totalRead < block.length) {
			int read = in.read(block, totalRead, block.length - totalRead);
			if (read == -1) {
				break;
			}
			totalRead += read;
		}

		if (totalRead != V1_BLOCK_BYTES) {
			throw new InvalidVoteException("Failed to read complete V1 vote block from " + address
					+ " (expected " + V1_BLOCK_BYTES + " bytes, got " + totalRead + ")");
		}

		byte[] decrypted;
		try {
			decrypted = RSA.decrypt(block, receiver.getKeyPair().getPrivate());
		} catch (BadPaddingException ex) {
			throw ex;
		}

		int position = 0;

		String opcode = readString(decrypted, position);
		position += opcode.length() + 1;
		if (!OPCODE_VOTE.equals(opcode)) {
			throw new InvalidVoteException(
					"Expected opcode '" + OPCODE_VOTE + "' but got '" + opcode + "' from " + address);
		}

		VoteRequest request = new VoteRequest();

		String serviceName = readString(decrypted, position);
		position += serviceName.length() + 1;

		String username = readString(decrypted, position);
		position += username.length() + 1;

		String voteAddress = readString(decrypted, position);
		position += voteAddress.length() + 1;

		String timeStamp = readString(decrypted, position);

		request.setServiceName(serviceName);
		request.setUsername(username);
		request.setAddress(voteAddress);
		request.setTimeStamp(timeStamp);

		return request;
	}

	private boolean readToSize(PushbackInputStream in, ByteArrayOutputStream data, int targetBytes) throws Exception {
		return readToSize(in, data, targetBytes, null, 0);
	}

	private boolean readToSize(PushbackInputStream in, ByteArrayOutputStream data, int targetBytes, Socket socket,
			long deadlineNanos) throws Exception {
		byte[] buffer = new byte[Math.min(4096, Math.max(1, targetBytes - data.size()))];
		while (data.size() < targetBytes) {
			setRemainingTimeout(socket, deadlineNanos);
			int read = in.read(buffer, 0, Math.min(buffer.length, targetBytes - data.size()));
			if (read == -1) {
				return false;
			}
			data.write(buffer, 0, read);
		}
		return true;
	}

	private void setRemainingTimeout(Socket socket, long deadlineNanos) throws SocketException, SocketTimeoutException {
		if (socket == null) {
			return;
		}

		long remainingNanos = deadlineNanos - System.nanoTime();
		if (remainingNanos <= 0) {
			throw new SocketTimeoutException("V2 packet read deadline exceeded");
		}

		int remainingMillis = (int) Math.max(1, (remainingNanos + 999_999L) / 1_000_000L);
		int currentTimeout = socket.getSoTimeout();
		socket.setSoTimeout(currentTimeout <= 0 ? remainingMillis : Math.min(currentTimeout, remainingMillis));
	}

	private VoteRequest fallbackToBufferedV1OrThrow(PushbackInputStream in, ByteArrayOutputStream voteData,
			VoteReceiver receiver, String address, Exception v2Failure, Socket socket, long deadlineNanos) throws Exception {
		if (receiver.isDisableV1() || voteData.size() > V1_BLOCK_BYTES) {
			throw v2Failure;
		}

		int remaining = V1_BLOCK_BYTES - voteData.size();
		if (remaining > 0) {
			if (socket == null) {
				if (in.available() < remaining || !readToSize(in, voteData, V1_BLOCK_BYTES)) {
					throw v2Failure;
				}
			} else if (!readV1CollisionRemainder(in, voteData, socket, v2Failure, deadlineNanos)) {
				throw v2Failure;
			}
		}

		try {
			return parseV1Candidate(voteData.toByteArray(), receiver, address);
		} catch (Exception v1Failure) {
			v2Failure.addSuppressed(v1Failure);
			throw v2Failure;
		}
	}

	private boolean readV1CollisionRemainder(PushbackInputStream in, ByteArrayOutputStream voteData, Socket socket,
			Exception v2Failure, long v2DeadlineNanos) throws Exception {
		int previousTimeout = socket.getSoTimeout();
		long deadlineNanos = System.nanoTime() + V1_COLLISION_GRACE_TIMEOUT_MS * 1_000_000L;
		if (v2DeadlineNanos > 0) {
			deadlineNanos = Math.min(deadlineNanos, v2DeadlineNanos);
		}
		byte[] buffer = new byte[V1_BLOCK_BYTES - voteData.size()];
		try {
			while (voteData.size() < V1_BLOCK_BYTES) {
				long remainingNanos = deadlineNanos - System.nanoTime();
				if (remainingNanos <= 0) {
					return false;
				}

				int remainingMillis = (int) Math.max(1, (remainingNanos + 999_999L) / 1_000_000L);
				int readTimeout = previousTimeout <= 0 ? remainingMillis : Math.min(previousTimeout, remainingMillis);
				socket.setSoTimeout(readTimeout);

				int read = in.read(buffer, 0, Math.min(buffer.length, V1_BLOCK_BYTES - voteData.size()));
				if (read == -1) {
					return false;
				}
				voteData.write(buffer, 0, read);
			}
			return true;
		} catch (SocketTimeoutException ex) {
			v2Failure.addSuppressed(ex);
			return false;
		} finally {
			socket.setSoTimeout(previousTimeout);
		}
	}

	private VoteRequest parseV1Candidate(byte[] candidate, VoteReceiver receiver, String address) throws Exception {
		return parseV1(new PushbackInputStream(new ByteArrayInputStream(candidate), V1_BLOCK_BYTES), receiver, address);
	}

	private static class JsonObjectBoundaryScanner {
		private int depth;
		private boolean escaped;
		private boolean inString;
		private boolean started;

		private int scan(byte[] data, int offset, int length) {
			for (int i = offset; i < offset + length; i++) {
				char current = (char) (data[i] & 0xFF);
				if (inString) {
					if (escaped) {
						escaped = false;
					} else if (current == '\\') {
						escaped = true;
					} else if (current == '"') {
						inString = false;
					}
					continue;
				}

				if (current == '"') {
					inString = true;
				} else if (current == '{') {
					started = true;
					depth++;
				} else if (current == '}' && started && --depth == 0) {
					return i - offset + 1;
				}
			}
			return -1;
		}
	}

	private VoteRequest parseV2(byte[] data, VoteReceiver receiver, String address, String challenge)
			throws Exception {
		String voteData = new String(data, StandardCharsets.UTF_8).trim();
		receiver.debug("Received raw V2 vote payload: [" + voteData + "]");

		int firstBrace = voteData.indexOf('{');
		if (firstBrace > 0) {
			voteData = voteData.substring(firstBrace);
		}

		int jsonStart = voteData.indexOf('{');
		int jsonEnd = voteData.lastIndexOf('}');
		if (jsonStart == -1 || jsonEnd == -1 || jsonStart > jsonEnd) {
			throw new InvalidVoteException("Expected JSON-formatted vote payload from " + address);
		}

		String jsonPayloadRaw = voteData.substring(jsonStart, jsonEnd + 1).trim();
		receiver.debug("Extracted raw JSON payload: [" + jsonPayloadRaw + "]");

		JsonObject voteMessage;
		if (jsonPayloadRaw.startsWith("[")) {
			JsonArray jsonArray = GSON.fromJson(jsonPayloadRaw, JsonArray.class);
			if (jsonArray.size() == 0) {
				throw new InvalidVoteException("Empty JSON array in vote payload from " + address);
			}
			voteMessage = jsonArray.get(0).getAsJsonObject();
		} else {
			voteMessage = GSON.fromJson(jsonPayloadRaw, JsonObject.class);
		}

		if (!voteMessage.has(FIELD_PAYLOAD) || !voteMessage.has(FIELD_SIGNATURE)) {
			throw new InvalidVoteException("Missing required fields in outer JSON from " + address);
		}

		String payload = requireString(voteMessage, FIELD_PAYLOAD, "Outer JSON from " + address + ": ");
		String signature = requireString(voteMessage, FIELD_SIGNATURE, "Outer JSON from " + address + ": ");

		byte[] providedSig;
		try {
			providedSig = Base64.getDecoder().decode(signature);
		} catch (IllegalArgumentException ex) {
			throw new InvalidVoteException("Signature is not valid Base64 from " + address + ": " + ex.getMessage(),
					ex);
		}

		JsonObject votePayload;
		try {
			votePayload = GSON.fromJson(payload, JsonObject.class);
		} catch (Exception ex) {
			throw new InvalidVoteException("Inner payload is not valid JSON from " + address + ": " + ex.getMessage(),
					ex);
		}

		if (!votePayload.has(FIELD_SERVICE_NAME) || !votePayload.has(FIELD_USERNAME) || !votePayload.has(FIELD_ADDRESS)
				|| !votePayload.has(FIELD_TIMESTAMP) || !votePayload.has(FIELD_CHALLENGE)) {
			throw new InvalidVoteException("Missing required fields in inner JSON from " + address);
		}

		String serviceName = requireString(votePayload, FIELD_SERVICE_NAME, "Inner JSON from " + address + ": ");
		String username = requireString(votePayload, FIELD_USERNAME, "Inner JSON from " + address + ": ");
		String voteAddress = requireString(votePayload, FIELD_ADDRESS, "Inner JSON from " + address + ": ");
		String timeStamp = requireString(votePayload, FIELD_TIMESTAMP, "Inner JSON from " + address + ": ");
		String receivedChallenge = requireString(votePayload, FIELD_CHALLENGE, "Inner JSON from " + address + ": ");

		Map<String, Key> tokens = receiver.getTokens();
		Key key = tokens.get(serviceName);
		if (key == null) {
			key = tokens.get("default");
			if (key == null) {
				throw new VoteAuthenticationException(
						"Unknown token for service '" + serviceName + "' from " + address);
			}
			receiver.debug("Using default token for service: " + serviceName);
		} else {
			receiver.debug("Using service-specific token for: " + serviceName);
		}

		if (!hmacEqual(providedSig, payload.getBytes(StandardCharsets.UTF_8), key)) {
			throw new VoteAuthenticationException(
					"Signature verification failed (invalid token?) for service '" + serviceName + "' from " + address);
		}

		if (!receivedChallenge.equals(challenge.trim())) {
			throw new VoteAuthenticationException("Invalid challenge from " + address);
		}

		VoteRequest request = new VoteRequest();
		request.setServiceName(serviceName);
		request.setUsername(username);
		request.setAddress(voteAddress);
		request.setTimeStamp(timeStamp);
		return request;
	}

	private String requireString(JsonObject obj, String field, String errorPrefix) throws InvalidVoteException {
		if (!obj.has(field)) {
			throw new InvalidVoteException(errorPrefix + "missing field '" + field + "'");
		}

		String value;
		try {
			value = obj.get(field).getAsString();
		} catch (Exception ex) {
			throw new InvalidVoteException(errorPrefix + "invalid field '" + field + "'", ex);
		}

		if (value == null || value.trim().isEmpty()) {
			throw new InvalidVoteException(errorPrefix + "empty field '" + field + "'");
		}

		return value;
	}

	private String readString(byte[] data, int offset) {
		StringBuilder builder = new StringBuilder();
		for (int i = offset; i < data.length; i++) {
			if (data[i] == '\n') {
				break;
			}
			builder.append((char) data[i]);
		}
		return builder.toString();
	}

	private boolean hmacEqual(byte[] providedSig, byte[] data, Key key) throws Exception {
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(key.getEncoded(), "HmacSHA256"));
		byte[] computed = mac.doFinal(data);

		if (providedSig.length != computed.length) {
			return false;
		}

		int diff = 0;
		for (int i = 0; i < providedSig.length; i++) {
			diff |= providedSig[i] ^ computed[i];
		}
		return diff == 0;
	}
}
