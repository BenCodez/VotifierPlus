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
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
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
		byte[] header = new byte[PROTOCOL_VERSION_PREFIX_BYTES];
		int bytesRead = 0;
		while (bytesRead < header.length) {
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
		if (version == VoteProtocolVersion.V1) {
			return parseV1(in, receiver, address);
		}

		ByteArrayOutputStream voteData = new ByteArrayOutputStream();
		readMoreVoteData(in, voteData);
		boolean v1FallbackAttempted = false;

		while (true) {
			byte[] candidate = voteData.toByteArray();
			Exception v2Failure;
			try {
				return parseV2(candidate, receiver, address, challenge);
			} catch (Exception ex) {
				v2Failure = ex;
			}

			if (!receiver.isDisableV1() && !v1FallbackAttempted && candidate.length == V1_BLOCK_BYTES) {
				v1FallbackAttempted = true;
				try {
					return parseV1(new PushbackInputStream(new ByteArrayInputStream(candidate), V1_BLOCK_BYTES), receiver,
							address);
				} catch (Exception v1Failure) {
					v2Failure.addSuppressed(v1Failure);
				}
			}

			if (candidate.length >= MAX_V2_PACKET_BYTES) {
				throw v2Failure;
			}

			try {
				if (!readMoreVoteData(in, voteData)) {
					throw v2Failure;
				}
			} catch (SocketTimeoutException ex) {
				v2Failure.addSuppressed(ex);
				throw v2Failure;
			}
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

	private boolean readMoreVoteData(PushbackInputStream in, ByteArrayOutputStream data) throws Exception {
		int next = in.read();
		if (next == -1) {
			return false;
		}
		data.write(next);

		while (data.size() < MAX_V2_PACKET_BYTES && in.available() > 0) {
			next = in.read();
			if (next == -1) {
				break;
			}
			data.write(next);
		}
		return true;
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
