package com.vexsoftware.votifier.net;

import java.io.ByteArrayOutputStream;
import java.io.PushbackInputStream;
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

public class VoteParser {

	private static final Gson GSON = new Gson();
	private static final short PROTOCOL_2_MAGIC = (short) 0x733A;

	public VoteProtocolVersion detectVersion(PushbackInputStream in) throws Exception {
		byte[] header = new byte[2];
		int bytesRead = in.read(header);
		if (bytesRead < 2) {
			throw new Exception("Not enough data available to determine vote protocol version.");
		}

		if ((char) header[0] == '{') {
			in.unread(header, 0, bytesRead);
			return VoteProtocolVersion.V2;
		}

		in.unread(header, 0, bytesRead);

		short magic = (short) (((header[0] & 0xFF) << 8) | (header[1] & 0xFF));
		if (magic == PROTOCOL_2_MAGIC) {
			return VoteProtocolVersion.V2;
		}

		return VoteProtocolVersion.V1;
	}

	public VoteRequest parse(PushbackInputStream in, VoteProtocolVersion version, VoteReceiver receiver, String address,
			String challenge) throws Exception {
		if (version == VoteProtocolVersion.V1) {
			return parseV1(in, receiver, address);
		}
		return parseV2(in, receiver, address, challenge);
	}

	private VoteRequest parseV1(PushbackInputStream in, VoteReceiver receiver, String address) throws Exception {
		byte[] block = new byte[256];
		int totalRead = 0;

		while (totalRead < block.length) {
			int read = in.read(block, totalRead, block.length - totalRead);
			if (read == -1) {
				break;
			}
			totalRead += read;
		}

		if (totalRead != 256) {
			throw new Exception(
					"Invalid vote format: Failed to read complete V1 vote block from " + address + " (expected 256 bytes, got "
							+ totalRead + ")");
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
		if (!"VOTE".equals(opcode)) {
			throw new Exception("Invalid vote format: Expected opcode 'VOTE' but got '" + opcode + "' from " + address);
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

	private VoteRequest parseV2(PushbackInputStream in, VoteReceiver receiver, String address, String challenge)
			throws Exception {
		ByteArrayOutputStream data = new ByteArrayOutputStream();
		int b;
		while ((b = in.read()) != -1) {
			data.write(b);
			if (in.available() == 0) {
				break;
			}
		}

		String voteData = data.toString("UTF-8").trim();
		receiver.debug("Received raw V2 vote payload: [" + voteData + "]");

		int firstBrace = voteData.indexOf('{');
		if (firstBrace > 0) {
			voteData = voteData.substring(firstBrace);
		}

		int jsonStart = voteData.indexOf('{');
		int jsonEnd = voteData.lastIndexOf('}');
		if (jsonStart == -1 || jsonEnd == -1 || jsonStart > jsonEnd) {
			throw new Exception("Invalid vote format: Expected JSON-formatted vote payload from " + address);
		}

		String jsonPayloadRaw = voteData.substring(jsonStart, jsonEnd + 1).trim();
		receiver.debug("Extracted raw JSON payload: [" + jsonPayloadRaw + "]");

		JsonObject voteMessage;
		if (jsonPayloadRaw.startsWith("[")) {
			JsonArray jsonArray = GSON.fromJson(jsonPayloadRaw, JsonArray.class);
			if (jsonArray.size() == 0) {
				throw new Exception("Invalid vote format: Empty JSON array in vote payload from " + address);
			}
			voteMessage = jsonArray.get(0).getAsJsonObject();
		} else {
			voteMessage = GSON.fromJson(jsonPayloadRaw, JsonObject.class);
		}

		if (!voteMessage.has("payload") || !voteMessage.has("signature")) {
			throw new Exception("Invalid vote format: Missing required fields in outer JSON from " + address);
		}

		String payload = voteMessage.get("payload").getAsString();
		String signature = voteMessage.get("signature").getAsString();

		byte[] providedSig;
		try {
			providedSig = Base64.getDecoder().decode(signature);
		} catch (IllegalArgumentException ex) {
			throw new Exception(
					"Invalid vote format: Signature is not valid Base64 from " + address + ": " + ex.getMessage());
		}

		JsonObject votePayload;
		try {
			votePayload = GSON.fromJson(payload, JsonObject.class);
		} catch (Exception ex) {
			throw new Exception(
					"Invalid vote format: Inner payload is not valid JSON from " + address + ": " + ex.getMessage());
		}

		if (!votePayload.has("serviceName") || !votePayload.has("username") || !votePayload.has("address")
				|| !votePayload.has("timestamp") || !votePayload.has("challenge")) {
			throw new Exception("Invalid vote format: Missing required fields in inner JSON from " + address);
		}

		String serviceName = votePayload.get("serviceName").getAsString();

		Map<String, Key> tokens = receiver.getTokens();
		Key key = tokens.get(serviceName);
		if (key == null) {
			key = tokens.get("default");
			if (key == null) {
				throw new Exception("Authentication failed: Unknown token for service '" + serviceName + "' from " + address);
			}
			receiver.debug("Using default token for service: " + serviceName);
		} else {
			receiver.debug("Using service-specific token for: " + serviceName);
		}

		if (!hmacEqual(providedSig, payload.getBytes(StandardCharsets.UTF_8), key)) {
			throw new Exception(
					"Authentication failed: Signature verification failed (invalid token?) for service '" + serviceName
							+ "' from " + address);
		}

		String receivedChallenge = votePayload.get("challenge").getAsString().trim();
		if (!receivedChallenge.equals(challenge.trim())) {
			throw new Exception("Authentication failed: Invalid challenge from " + address);
		}

		VoteRequest request = new VoteRequest();
		request.setServiceName(serviceName);
		request.setUsername(votePayload.get("username").getAsString());
		request.setAddress(votePayload.get("address").getAsString());
		request.setTimeStamp(votePayload.get("timestamp").getAsString());
		return request;
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