/*
 * Copyright (C) 2012 Vex Software LLC
 * This file is part of Votifier.
 * 
 * Votifier is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Votifier is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Votifier. If not, see <http://www.gnu.org/licenses/>.
 * 
 * Modified to support handling of extra proxy protocol data (e.g. from HAProxy).
 * This version supports multiple connection wrappers:
 *   1. Direct TCP (no extra header)
 *   2. PROXY protocol v1 (text-based): if the data begins with "PROXY", read and discard that header line,
 *      then drain any extra CR/LF characters.
 *   3. PROXY protocol v2 (binary): if the first 12 bytes match the v2 signature,
 *      read and discard the full binary header.
 *   4. HTTP CONNECT tunneling: if the connection begins with "CONNECT", read/discard the CONNECT request
 *      and send a "200 Connection Established" response.
 * 
 * After discarding any extra header, the normal vote protocol is performed.
 * 
 * Modified by: BenCodez / [Your Name]
 * 
 * This modified version supports both legacy V1 vote blocks (RSA encrypted fixed 256-byte blocks)
 * and V2 token-based vote blocks sent in cleartext.
 * In V1 mode, vote fields are separated by newline ("\n") and processed using a position pointer;
 * in V2 mode, the vote payload must be JSON-formatted.
 * The handshake is sent as: "VOTIFIER 2 <challenge>"
 */
package com.vexsoftware.votifier.net;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PushbackInputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.stream.MalformedJsonException;
import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.crypto.RSA;
import com.vexsoftware.votifier.crypto.TokenUtil;
import com.vexsoftware.votifier.model.Vote;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import lombok.Getter;

public abstract class VoteReceiver extends Thread {

	private final String host;
	private final int port;
	@Getter
	private ServerSocket server;
	private boolean running = true;

	// Expected 12-byte signature for PROXY protocol v2.
	private static final byte[] PROXY_V2_SIGNATURE = new byte[] { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55,
			0x49, 0x54, 0x0A };

	private static final Gson gson = new Gson();

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
		if (server == null)
			return;
		try {
			server.close();
		} catch (Exception ex) {
			logWarning("Unable to shut down vote receiver cleanly.");
		}
	}

	public abstract boolean isUseTokens();

	/**
	 * Enum representing the vote protocol version.
	 */
	private enum VoteProtocolVersion {
		V1, V2;
	}

	private static final short PROTOCOL_2_MAGIC = 0x733A;

	/**
	 * Checks if the incoming vote payload is in V2 (JSON) format (using a magic
	 * value) or legacy V1 format. It reads the first two bytes, wraps them in a
	 * ByteBuf to check the magic, and then pushes the bytes back into the stream.
	 *
	 * @param in the PushbackInputStream containing the vote payload.
	 * @return VoteProtocolVersion.V2 if the magic matches PROTOCOL_2_MAGIC,
	 *         otherwise V1.
	 * @throws IOException if there is an error reading from the stream.
	 */
	private VoteProtocolVersion checkVoteVersion(PushbackInputStream in) throws IOException {
		byte[] header = new byte[2];
		int bytesRead = in.read(header);
		if (bytesRead < 2) {
			throw new IOException("Not enough data available to determine vote protocol version.");
		}

		if ((char) header[0] == '{') {
			in.unread(header, 0, bytesRead);
			return VoteProtocolVersion.V2;
		}

		// Wrap the header bytes into a ByteBuf for magic value checking.
		ByteBuf buf = Unpooled.wrappedBuffer(header);
		short magic = buf.getShort(0);
		// Push the header bytes back into the stream.
		in.unread(header, 0, bytesRead);

		if (magic == PROTOCOL_2_MAGIC) {
			return VoteProtocolVersion.V2;
		}
		return VoteProtocolVersion.V1;
	}

	@Override
	public void run() {
		while (running) {
			String address = "";
			try (Socket socket = server.accept()) {
				address = socket.getRemoteSocketAddress().toString();
				debug("Accepted connection from: " + address);
				socket.setSoTimeout(5000);
				PushbackInputStream in = new PushbackInputStream(socket.getInputStream(), 512);
				BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

				// Send handshake greeting immediately.
				String message = "";
				if (isUseTokens()) {
					message = "VOTIFIER 2";
				} else {
					message = "VOTIFIER 1";
				}
				String challenge = getChallenge();
				if (isUseTokens()) {
					message += " " + challenge;
				}
				// Check for pre-existing V1 vote payload before sending handshake.
				// Some sites may send a vote payload immediately after connecting.
				int avail = in.available();

				if (avail >= 256) {
					// If there are at least 256 bytes available, assume this is a legacy V1 vote
					// payload.
					debug("Detected V1 vote payload before handshake (available bytes: " + avail
							+ "), skipping handshake.");
				} else {
					writer.write(message);
					writer.newLine();
					writer.flush();
					debug("Sent handshake: " + message);
				}

				// Process any proxy headers if available.
				if (in.available() > 0) {
					processProxyHeaders(in, writer);
				}

				// Wait for vote payload for up to 2000ms.
				long waitStart = System.currentTimeMillis();
				while (in.available() == 0 && System.currentTimeMillis() - waitStart < 2000) {
					try {
						Thread.sleep(50);
					} catch (InterruptedException ie) {
						Thread.currentThread().interrupt();
					}
				}
				if (in.available() == 0) {
					debug("No vote payload received after handshake; closing connection from " + address);
					writer.close();
					in.close();
					socket.close();
					continue;
				}

				// --- Determine protocol type and read vote payload ---
				VoteProtocolVersion voteProtocolVersion = checkVoteVersion(in);
				debug("Detected vote protocol version: " + voteProtocolVersion.toString());
				String voteData = null;
				if (voteProtocolVersion.equals(VoteProtocolVersion.V1)) {
					byte[] block = new byte[256];
					int totalRead = 0;
					long startTime = System.currentTimeMillis();
					debug("Reading V1 vote block (256 bytes expected) at " + startTime + " ms");

					if (in.available() < 256) {
						debug("Insufficient data available for V1 vote block; closing connection from " + address);
						writer.close();
						in.close();
						socket.close();
						continue;
					} else {

						while (totalRead < block.length) {
							int remaining = block.length - totalRead;
							int r = in.read(block, totalRead, remaining);
							if (r == -1) {
								debug("Reached end-of-stream unexpectedly after " + totalRead + " bytes from "
										+ address);
								break;
							}
							totalRead += r;
							debug("Read " + r + " bytes; total: " + totalRead);
						}
						if (totalRead == 256) {
							byte[] decrypted;
							try {
								decrypted = RSA.decrypt(block, getKeyPair().getPrivate());
							} catch (BadPaddingException e) {
								StringBuilder blockHex = new StringBuilder();
								for (byte b : block) {
									blockHex.append(String.format("%02X ", b));
								}
								logWarning(
										"Decryption failed. Either the vote block is invalid or the public key does not match the server list from "
												+ address);
								throw e;
							}
							int position = 0;
							String opcode = readString(decrypted, position);
							position += opcode.length() + 1;
							if (!opcode.equals("VOTE")) {
								throw new Exception("Unable to decode RSA: invalid opcode " + opcode);
							}
							String serviceName = readString(decrypted, position);
							position += serviceName.length() + 1;
							String username = readString(decrypted, position);
							position += username.length() + 1;
							String address1 = readString(decrypted, position);
							position += address1.length() + 1;
							String timeStamp = readString(decrypted, position);
							position += timeStamp.length() + 1;
							voteData = "VOTE\n" + serviceName + "\n" + username + "\n" + address1 + "\n" + timeStamp
									+ "\n";
							debug("Processed V1 vote block.");
						} else {
							debug("Failed to read V1 vote, random ping? expected 256 bytes, got " + totalRead);
							continue;
							// throw new Exception("Failed to read V1 vote block: expected 256 bytes, got "
							// + totalRead);
						}
					}
				}
				if (voteProtocolVersion.equals(VoteProtocolVersion.V2)) {
					// In V2 mode, always parse as JSON.
					ByteArrayOutputStream voteDataStream = new ByteArrayOutputStream();
					int b;
					while (in.available() > 0 && (b = in.read()) != -1) {
						voteDataStream.write(b);
					}
					voteData = voteDataStream.toString("UTF-8").trim();
					debug("Received raw V2 vote payload: [" + voteData + "]");
				}

				// --- Parse Vote Data (V2 JSON mode) ---
				String serviceName, username, address1, timeStamp = "";
				if (voteProtocolVersion.equals(VoteProtocolVersion.V2)) {
					// Remove any extraneous characters before the first '{'
					int firstBrace = voteData.indexOf('{');
					if (firstBrace > 0) {
						voteData = voteData.substring(firstBrace);
					}

					// Find the first '{' and the last '}' to extract JSON.
					int jsonStart = voteData.indexOf("{");
					int jsonEnd = voteData.lastIndexOf("}");
					if (jsonStart == -1 || jsonEnd == -1 || jsonStart > jsonEnd) {
						throw new Exception(
								"Expected JSON-formatted vote payload, got: " + voteData + " from " + address);
					}
					String jsonPayloadRaw = voteData.substring(jsonStart, jsonEnd + 1).trim();
					debug("Extracted raw JSON payload: [" + jsonPayloadRaw + "]");

					// Check if the JSON payload is an array and, if so, extract the first object.
					JsonObject voteMessage;
					if (jsonPayloadRaw.startsWith("[")) {
						JsonArray jsonArray = gson.fromJson(jsonPayloadRaw, JsonArray.class);
						if (jsonArray.size() == 0) {
							throw new Exception("Empty JSON array in vote payload from " + address);
						}
						voteMessage = jsonArray.get(0).getAsJsonObject();
					} else {
						voteMessage = gson.fromJson(jsonPayloadRaw, JsonObject.class);
					}

					// Extract the inner payload and signature.
					String payload = voteMessage.get("payload").getAsString();
					String sigHash = voteMessage.get("signature").getAsString();
					byte[] sigBytes = Base64.getDecoder().decode(sigHash);

					// Parse the inner payload JSON.
					JsonObject votePayload = gson.fromJson(payload, JsonObject.class);

					// Retrieve serviceName from the inner JSON.
					String serviceNameFromPayload = votePayload.get("serviceName").getAsString();

					// Lookup the token using the serviceName from the inner payload.
					Key key = getTokens().get(serviceNameFromPayload);
					if (key == null) {
						key = getTokens().get("default");
						if (key == null) {
							throw new Exception("Unknown service '" + serviceNameFromPayload + "'");
						}
					}

					// Debug: log the payload string and its computed HMAC for comparison.
					debug("Inner payload string: [" + payload + "]");

					// Verify HMAC signature using the payload bytes.
					if (!hmacEqual(sigBytes, payload.getBytes(StandardCharsets.UTF_8), key)) {
						throw new Exception("Signature is not valid (invalid token?) from " + address);
					}

					// Extract vote fields from the inner payload.
					serviceName = serviceNameFromPayload;
					username = votePayload.get("username").getAsString();
					address1 = votePayload.get("address").getAsString();
					timeStamp = votePayload.get("timestamp").getAsString();

					// Check the challenge.
					if (!votePayload.has("challenge")) {
						throw new Exception("Vote payload missing challenge field from " + address);
					}
					String receivedChallenge = votePayload.get("challenge").getAsString().trim();
					if (!receivedChallenge.equals(challenge.trim())) {
						throw new Exception(
								"Invalid challenge: expected " + challenge + " but got " + receivedChallenge);
					}
				} else {
					String[] fields = voteData.split("\n");
					serviceName = fields[1];
					username = fields[2];
					address1 = fields[3];
					timeStamp = fields[4];
				}

				// --- Create and Process Vote ---
				final Vote vote = new Vote();
				vote.setServiceName(serviceName);
				vote.setUsername(username);
				vote.setAddress(address1);
				vote.setTimeStamp(timeStamp);
				if (address != null) {
					vote.setSourceAddress(address);
				} else {
					vote.setSourceAddress("unknown");
				}
				if (timeStamp.equalsIgnoreCase("TestVote")) {
					log("Test vote received");
				}
				log("Received vote record -> " + vote);

				// Send OK response.
				if (!timeStamp.equalsIgnoreCase("TestVote")) {
					try {
						JsonObject okResponse = new JsonObject();
						okResponse.addProperty("status", "ok");
						String okMessage = gson.toJson(okResponse) + "\r\n";
						writer.write(okMessage);
						writer.flush();
						debug("Sent OK response: " + okMessage);
					} catch (Exception e) {
						debug("Failed to send OK response, but will continue to process vote: "
								+ e.getLocalizedMessage());
					}
				}

				// --- Forward Vote to Other Servers ---
				for (String server : getServers()) {
					ForwardServer forwardServer = getServerData(server);
					if (forwardServer.isEnabled()) {
						debug("Forwarding vote to: " + server);
						String voteString = "VOTE\n" + vote.getServiceName() + "\n" + vote.getUsername() + "\n"
								+ vote.getAddress() + "\n" + vote.getTimeStamp() + "\n";
						try {
							SocketAddress sockAddr = new InetSocketAddress(forwardServer.getHost(),
									forwardServer.getPort());
							try (Socket forwardSocket = new Socket()) {
								forwardSocket.connect(sockAddr, 1000);
								OutputStream outStream = forwardSocket.getOutputStream();

								byte[] encrypted = encrypt(voteString.getBytes(StandardCharsets.UTF_8),
										getPublicKey(forwardServer));
								outStream.write(encrypted);

								outStream.flush();
							}
						} catch (Exception e) {
							log("Failed to forward vote to " + server + " (" + forwardServer.getHost() + ":"
									+ forwardServer.getPort() + "): " + vote.toString());
							debug(e);
						}
					}
				}
				callEvent(vote);
				writer.close();
				in.close();
				socket.close();
			} catch (MalformedJsonException ex) {
				logWarning("Malformed JSON payload received from: " + address + " - " + ex.getMessage());
				debug(ex);
			} catch (SocketException ex) {
				if (running) {
					logWarning("Protocol error from: " + address + " - " + ex.getLocalizedMessage());
					debug(ex);
				} else {
					logWarning("Votifier socket closed.");
				}
			} catch (BadPaddingException ex) {
				logWarning("Unable to decrypt vote record from: " + address
						+ ". Make sure that your public key matches the one you gave the server list.");
				debug(ex);
			} catch (SocketTimeoutException ex) {
				logWarning("Socket timeout while waiting for vote payload from: " + address + " - " + ex.getMessage());
				debug(ex);
			} catch (Exception ex) {
				logWarning("Exception caught while receiving a vote notification from: " + address + " - "
						+ ex.getLocalizedMessage());
				debug(ex);
			}
		}
	}

	private String readString(byte[] data, int offset) {
		StringBuilder builder = new StringBuilder();
		for (int i = offset; i < data.length; i++) {
			if (data[i] == '\n')
				break;
			builder.append((char) data[i]);
		}
		return builder.toString();
	}

	private String readLine(PushbackInputStream in) throws Exception {
		ByteArrayOutputStream lineBuffer = new ByteArrayOutputStream();
		int b;
		boolean seenCR = false;
		while ((b = in.read()) != -1) {
			if (b == '\r') {
				seenCR = true;
				continue;
			}
			if (b == '\n') {
				break;
			}
			if (seenCR) {
				in.unread(b);
				break;
			}
			lineBuffer.write(b);
		}
		return lineBuffer.toString("ASCII").trim();
	}

	private boolean isProxyV2(byte[] header) {
		for (int i = 0; i < PROXY_V2_SIGNATURE.length; i++) {
			if (header[i] != PROXY_V2_SIGNATURE[i]) {
				return false;
			}
		}
		return true;
	}

	public abstract void logWarning(String warn);

	public abstract void logSevere(String msg);

	public abstract void log(String msg);

	public abstract void debug(String msg);

	public abstract String getVersion();

	public abstract Set<String> getServers();

	public abstract KeyPair getKeyPair();

	public abstract Map<String, Key> getTokens();

	public abstract ForwardServer getServerData(String s);

	public abstract void callEvent(Vote e);

	public abstract void debug(Exception e);

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

	// Generates a challenge string using TokenUtil.
	public String getChallenge() {
		return TokenUtil.newToken();
	}

	/**
	 * Processes and discards any proxy header data if present.
	 */
	private void processProxyHeaders(PushbackInputStream in, BufferedWriter writer) throws Exception {
		byte[] headerPeek = new byte[32];
		int bytesRead = in.read(headerPeek);
		if (bytesRead > 0) {
			String headerString = new String(headerPeek, 0, bytesRead, StandardCharsets.US_ASCII);
			if (headerString.startsWith("PROXY") && !headerString.contains("CONNECT")) {
				in.unread(headerPeek, 0, bytesRead);
				ByteArrayOutputStream headerLine = new ByteArrayOutputStream();
				byte[] buf = new byte[1];
				while (in.read(buf) != -1) {
					headerLine.write(buf[0]);
					if (buf[0] == '\n')
						break;
				}
				String proxyHeader = headerLine.toString("ASCII").trim();
				debug("Discarded PROXY (v1) header: " + proxyHeader);
			} else if (bytesRead >= 12 && isProxyV2(headerPeek)) {
				int addrLength = ((headerPeek[14] & 0xFF) << 8) | (headerPeek[15] & 0xFF);
				int totalV2HeaderLength = 16 + addrLength;
				int remaining = totalV2HeaderLength - bytesRead;
				byte[] discard = new byte[remaining];
				int readRemaining = 0;
				while (readRemaining < remaining) {
					int r = in.read(discard, readRemaining, remaining - readRemaining);
					if (r == -1)
						break;
					readRemaining += r;
				}
				if (readRemaining != remaining) {
					throw new Exception("Incomplete PROXY protocol v2 header");
				}
				debug("Discarded PROXY protocol v2 header (" + totalV2HeaderLength + " bytes)");
			} else if (headerString.startsWith("CONNECT")) {
				in.unread(headerPeek, 0, bytesRead);
				String connectLine = readLine(in);
				debug("Received CONNECT request: " + connectLine);
				String line;
				while (!(line = readLine(in)).isEmpty()) {
					debug("Discarding header: " + line);
				}
				writer.write("HTTP/1.1 200 Connection Established\r\n\r\n");
				writer.flush();
			} else {
				in.unread(headerPeek, 0, bytesRead);
			}
		}
	}

	/**
	 * Compares the provided HMAC signature with a computed HMAC of the data.
	 */
	private boolean hmacEqual(byte[] providedSig, byte[] data, Key key) throws Exception {
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(key.getEncoded(), "HmacSHA256"));
		byte[] computed = mac.doFinal(data);
		if (providedSig.length != computed.length) {
			return false;
		}
		for (int i = 0; i < providedSig.length; i++) {
			if (providedSig[i] != computed[i]) {
				return false;
			}
		}
		return true;
	}
}
