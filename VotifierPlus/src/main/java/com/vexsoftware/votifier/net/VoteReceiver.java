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
 * Modified by: BenCodez
 *
 * This modified version supports both legacy V1 vote blocks (RSA encrypted fixed 256-byte blocks)
 * and V2 token-based vote blocks sent in cleartext.
 * In V1 mode, vote fields are separated by newline ("\n") and processed using a position pointer;
 * in V2 mode, the vote payload must be JSON-formatted.
 * The handshake is sent as: "VOTIFIER 2 <challenge>"
 *
 * Additional modifications:
 * - Connection throttling + rate-limited logging to reduce spam (scanners, invalid payloads, key mismatch)
 * - Tunnel-aware throttling (e.g. playit.gg egress IP) with more aggressive thresholds
 * - Optional per-client bans only when a real client IP is known (e.g. PROXY v1)
 * - ParsedDuration used for all timing config strings
 */
package com.vexsoftware.votifier.net;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PushbackInputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.bencodez.simpleapi.time.ParsedDuration;
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

	/**
	 * Throttling config for connection spam reduction.
	 *
	 * Keep this small on purpose. Use ParsedDuration strings for time values.
	 */
	public static final class ThrottleConfig {
		public final boolean enabled;

		/** Remote socket IPs that should be treated as tunnel egress (e.g. playit). */
		public final Set<String> tunnelRemoteIps;

		/** Sliding window duration for failure counting. */
		public final long windowMs;

		/** Failures within window before hard throttle. */
		public final int failures;

		/** Hard throttle duration. */
		public final long throttleForMs;

		/** Tunnel-mode failures threshold. */
		public final int tunnelFailures;

		/** Tunnel-mode throttle duration. */
		public final long tunnelThrottleForMs;

		/** Per-client ban only when real client IP is known (e.g. PROXY v1). */
		public final boolean perClientBanEnabled;
		public final int perClientBanFailures;
		public final long perClientBanForMs;

		/** Rate-limit WARN logs per key. */
		public final long logWindowMs;

		public ThrottleConfig(boolean enabled, Set<String> tunnelRemoteIps, String window, int failures,
				String throttleFor, int tunnelFailures, String tunnelThrottleFor, boolean perClientBanEnabled,
				int perClientBanFailures, String perClientBanFor, String logWindow) {

			this.enabled = enabled;
			this.tunnelRemoteIps = tunnelRemoteIps == null ? new HashSet<String>() : tunnelRemoteIps;

			this.windowMs = safeDurationMs(window, 2 * 60_000L); // default 2m
			this.failures = failures;
			this.throttleForMs = safeDurationMs(throttleFor, 5 * 60_000L); // default 5m

			this.tunnelFailures = tunnelFailures;
			this.tunnelThrottleForMs = safeDurationMs(tunnelThrottleFor, 10 * 60_000L); // default 10m

			this.perClientBanEnabled = perClientBanEnabled;
			this.perClientBanFailures = perClientBanFailures;
			this.perClientBanForMs = safeDurationMs(perClientBanFor, 15 * 60_000L); // default 15m

			this.logWindowMs = safeDurationMs(logWindow, 60_000L); // default 60s
		}

		private static long safeDurationMs(String raw, long fallback) {
			try {
				if (raw == null || raw.isEmpty())
					return fallback;
				ParsedDuration d = ParsedDuration.parse(raw, TimeUnit.MINUTES);
				long ms = d.getMillis();
				return ms > 0 ? ms : fallback;
			} catch (Exception ignored) {
				return fallback;
			}
		}
	}

	/**
	 * Rate-limit repeated log lines. Allows at most one log per key per window, and
	 * appends "(suppressed N similar ...)" when it logs again.
	 */
	public static final class LogLimiter {
		private static final class State {
			volatile long lastLogMs;
			volatile int suppressed;
		}

		private final ConcurrentHashMap<String, State> states = new ConcurrentHashMap<>();
		private final long windowMs;

		public LogLimiter(long windowMs) {
			this.windowMs = Math.max(250L, windowMs);
		}

		public String allow(String key, String msg) {
			long now = System.currentTimeMillis();
			State st = states.computeIfAbsent(key, k -> new State());

			if (now - st.lastLogMs >= windowMs) {
				int suppressed = st.suppressed;
				st.suppressed = 0;
				st.lastLogMs = now;

				if (suppressed > 0) {
					return msg + " (suppressed " + suppressed + " similar in last " + windowMs + "ms)";
				}
				return msg;
			}

			st.suppressed++;
			return null;
		}
	}

	/**
	 * Connection throttle manager (failures in window -> throttle; optional ban
	 * when real IP known).
	 */
	public static final class ThrottleManager {
		private static final class State {
			volatile long windowStartMs;
			volatile int failures;
			volatile long throttledUntilMs;
			volatile long bannedUntilMs;
		}

		private final ConcurrentHashMap<String, State> map = new ConcurrentHashMap<>();
		private final ThrottleConfig cfg;

		public ThrottleManager(ThrottleConfig cfg) {
			this.cfg = cfg;
		}

		public boolean isBlocked(String key) {
			if (!cfg.enabled)
				return false;
			long now = System.currentTimeMillis();
			State s = map.get(key);
			if (s == null)
				return false;
			return (s.bannedUntilMs > now) || (s.throttledUntilMs > now);
		}

		public long retryAfterMs(String key) {
			State s = map.get(key);
			if (s == null)
				return 0L;
			long now = System.currentTimeMillis();
			return Math.max(s.bannedUntilMs, s.throttledUntilMs) - now;
		}

		public void fail(String key, boolean tunnelMode, boolean realIpKnown) {
			if (!cfg.enabled)
				return;

			long now = System.currentTimeMillis();
			State s = map.computeIfAbsent(key, k -> {
				State n = new State();
				n.windowStartMs = now;
				return n;
			});

			// reset window
			if (now - s.windowStartMs > cfg.windowMs) {
				s.windowStartMs = now;
				s.failures = 0;
			}

			s.failures++;

			// Optional per-client ban (ONLY if real IP known)
			if (cfg.perClientBanEnabled && realIpKnown && s.failures >= cfg.perClientBanFailures) {
				s.bannedUntilMs = now + cfg.perClientBanForMs;
				return;
			}

			// Hard throttle (tunnel profile vs normal)
			int threshold = tunnelMode ? cfg.tunnelFailures : cfg.failures;
			long durMs = tunnelMode ? cfg.tunnelThrottleForMs : cfg.throttleForMs;

			if (s.failures >= threshold) {
				s.throttledUntilMs = now + durMs;
			}
		}

		public void success(String key) {
			State s = map.get(key);
			if (s != null) {
				s.failures = 0;
				s.windowStartMs = System.currentTimeMillis();
			}
		}
	}

	/**
	 * Provide throttle config from your plugin config. Return null to disable
	 * throttling entirely.
	 */
	public abstract ThrottleConfig getThrottleConfig();

	// These are initialized lazily in run() once config exists.
	private volatile ThrottleManager throttle;
	private volatile LogLimiter warnLimiter;

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
	 * value) or legacy V1 format.
	 */
	private VoteProtocolVersion checkVoteVersion(PushbackInputStream in) throws IOException {
		byte[] header = new byte[2];
		int bytesRead = in.read(header);
		if (bytesRead < 2) {
			throw new IOException("Not enough data available to determine vote protocol version.");
		}

		// JSON check
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
		// Initialize throttle/warn limiter once (safe defaults if config missing)
		ThrottleConfig cfg = getThrottleConfig();
		if (cfg != null && cfg.enabled) {
			this.throttle = new ThrottleManager(cfg);
			this.warnLimiter = new LogLimiter(cfg.logWindowMs);
		} else {
			// Still create a small limiter so we can reduce spam even when throttling
			// disabled
			this.warnLimiter = new LogLimiter(60_000L);
		}

		while (running) {
			String address = "";
			String remoteIp = "unknown";
			try (Socket socket = server.accept()) {
				address = socket.getRemoteSocketAddress().toString();
				remoteIp = extractIp(address);

				debug("Accepted connection from: " + address);
				socket.setSoTimeout(5000);

				PushbackInputStream in = new PushbackInputStream(socket.getInputStream(), 512);
				BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

				// Send handshake greeting immediately unless we detect a pre-sent V1 payload.
				String message;
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
				int avail = in.available();
				if (avail >= 256) {
					debug("Detected V1 vote payload before handshake (available bytes: " + avail
							+ "), skipping handshake.");
				} else {
					writer.write(message);
					writer.newLine();
					writer.flush();
					debug("Sent handshake: " + message);
				}

				// Process any proxy headers if available (PROXY/CONNECT).
				// Returns a real client IP if PROXY v1 is provided; otherwise null.
				String realIp = null;
				if (in.available() > 0) {
					realIp = processProxyHeaders(in, writer);
				}
				boolean realIpKnown = realIp != null && !realIp.isEmpty();

				// Tunnel-aware throttling key choice:
				// - If we know real IP, key by that (safe per-client ban).
				// - Otherwise, key by remote egress IP (tunnel profile).
				boolean tunnelMode = false;
				if (cfg != null && cfg.enabled) {
					tunnelMode = (!realIpKnown && cfg.tunnelRemoteIps.contains(remoteIp));
				}
				String throttleKey = realIpKnown ? ("ip:" + realIp) : ("tunnel:" + remoteIp);

				// Early throttle gate: if blocked, drop quietly (rate-limited warning).
				if (throttle != null && throttle.isBlocked(throttleKey)) {
					long retry = throttle.retryAfterMs(throttleKey);
					String msg2 = "Votifier throttling " + throttleKey + " (tunnel=" + tunnelMode + "), retry in "
							+ Math.max(0, retry / 1000) + "s";
					String toLog = warnLimiter.allow("throttle|" + throttleKey, msg2);
					if (toLog != null)
						logWarning(toLog);

					try {
						writer.close();
					} catch (Exception ignored) {
					}
					try {
						in.close();
					} catch (Exception ignored) {
					}
					socket.close();
					continue;
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
					try {
						writer.close();
					} catch (Exception ignored) {
					}
					try {
						in.close();
					} catch (Exception ignored) {
					}
					socket.close();
					continue;
				}

				// --- Determine protocol type and read vote payload ---
				VoteProtocolVersion voteProtocolVersion = checkVoteVersion(in);
				debug("Detected vote protocol version: " + voteProtocolVersion);

				String voteData = null;

				if (voteProtocolVersion.equals(VoteProtocolVersion.V1)) {
					byte[] block = new byte[256];
					int totalRead = 0;

					if (in.available() < 256) {
						// This is extremely common for scanners/port probes; treat as throttled
						// warning.
						if (throttle != null)
							throttle.fail(throttleKey, tunnelMode, realIpKnown);

						String msg2 = "Invalid vote format: Insufficient data for V1 vote block from "
								+ (realIpKnown ? realIp : remoteIp) + " (expected 256 bytes)";
						String toLog = warnLimiter.allow("shortv1|" + throttleKey, msg2);
						if (toLog != null)
							logWarning(toLog);

						debug("Insufficient data available for V1 vote block; closing connection from " + address);
						try {
							writer.close();
						} catch (Exception ignored) {
						}
						try {
							in.close();
						} catch (Exception ignored) {
						}
						socket.close();
						continue;
					}

					while (totalRead < block.length) {
						int remaining = block.length - totalRead;
						int r = in.read(block, totalRead, remaining);
						if (r == -1) {
							debug("Reached end-of-stream unexpectedly after " + totalRead + " bytes from " + address);
							break;
						}
						totalRead += r;
					}

					if (totalRead == 256) {
						byte[] decrypted;
						try {
							decrypted = RSA.decrypt(block, getKeyPair().getPrivate());
						} catch (BadPaddingException e) {
							// Fail + throttle
							if (throttle != null)
								throttle.fail(throttleKey, tunnelMode, realIpKnown);

							String msg2 = "Decryption failed: Invalid V1 vote block / public key mismatch from "
									+ (realIpKnown ? realIp : remoteIp);
							String toLog = warnLimiter.allow("badpadding|" + throttleKey, msg2);
							if (toLog != null)
								logWarning(toLog);

							// Debug only: preview to avoid exposing full block
							StringBuilder blockHex = new StringBuilder();
							int bytesToLog = Math.min(32, block.length);
							for (int i = 0; i < bytesToLog; i++) {
								blockHex.append(String.format("%02X ", block[i]));
							}
							if (block.length > bytesToLog) {
								blockHex.append("... (truncated)");
							}
							debug("Vote block preview (first 32 bytes): " + blockHex.toString().trim());
							throw e;
						}

						int position = 0;
						String opcode = readString(decrypted, position);
						position += opcode.length() + 1;
						if (!opcode.equals("VOTE")) {
							if (throttle != null)
								throttle.fail(throttleKey, tunnelMode, realIpKnown);
							throw new Exception("Invalid vote format: Expected opcode 'VOTE' but got '" + opcode
									+ "' from " + address);
						}

						String serviceName = readString(decrypted, position);
						position += serviceName.length() + 1;
						String username = readString(decrypted, position);
						position += username.length() + 1;
						String address1 = readString(decrypted, position);
						position += address1.length() + 1;
						String timeStamp = readString(decrypted, position);
						position += timeStamp.length() + 1;

						voteData = "VOTE\n" + serviceName + "\n" + username + "\n" + address1 + "\n" + timeStamp + "\n";
						debug("Processed V1 vote block.");
					} else {
						if (throttle != null)
							throttle.fail(throttleKey, tunnelMode, realIpKnown);

						String msg2 = "Invalid vote format: Failed to read complete V1 vote block from "
								+ (realIpKnown ? realIp : remoteIp) + " (expected 256 bytes, got " + totalRead + ")";
						String toLog = warnLimiter.allow("shortv1read|" + throttleKey, msg2);
						if (toLog != null)
							logWarning(toLog);

						debug("Failed to read V1 vote, expected 256 bytes, got " + totalRead);
						try {
							writer.close();
						} catch (Exception ignored) {
						}
						try {
							in.close();
						} catch (Exception ignored) {
						}
						socket.close();
						continue;
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

				// --- Parse Vote Data ---
				String serviceName, username, address1, timeStamp = "";

				if (voteProtocolVersion.equals(VoteProtocolVersion.V2)) {
					// Remove any extraneous characters before the first '{'
					int firstBrace = voteData.indexOf('{');
					if (firstBrace > 0) {
						voteData = voteData.substring(firstBrace);
					}

					int jsonStart = voteData.indexOf("{");
					int jsonEnd = voteData.lastIndexOf("}");
					if (jsonStart == -1 || jsonEnd == -1 || jsonStart > jsonEnd) {
						if (throttle != null)
							throttle.fail(throttleKey, tunnelMode, realIpKnown);
						throw new Exception(
								"Invalid vote format: Expected JSON-formatted vote payload from " + address);
					}

					String jsonPayloadRaw = voteData.substring(jsonStart, jsonEnd + 1).trim();
					debug("Extracted raw JSON payload: [" + jsonPayloadRaw + "]");

					JsonObject voteMessage;
					if (jsonPayloadRaw.startsWith("[")) {
						JsonArray jsonArray = gson.fromJson(jsonPayloadRaw, JsonArray.class);
						if (jsonArray.size() == 0) {
							if (throttle != null)
								throttle.fail(throttleKey, tunnelMode, realIpKnown);
							throw new Exception(
									"Invalid vote format: Empty JSON array in vote payload from " + address);
						}
						voteMessage = jsonArray.get(0).getAsJsonObject();
					} else {
						voteMessage = gson.fromJson(jsonPayloadRaw, JsonObject.class);
					}

					if (!voteMessage.has("payload") || !voteMessage.has("signature")) {
						if (throttle != null)
							throttle.fail(throttleKey, tunnelMode, realIpKnown);
						throw new Exception(
								"Invalid vote format: Missing required fields in outer JSON from " + address);
					}

					String payload = voteMessage.get("payload").getAsString();
					String sigHash = voteMessage.get("signature").getAsString();

					byte[] sigBytes;
					try {
						sigBytes = Base64.getDecoder().decode(sigHash);
					} catch (IllegalArgumentException e) {
						if (throttle != null)
							throttle.fail(throttleKey, tunnelMode, realIpKnown);
						throw new Exception("Invalid vote format: Signature is not valid Base64 from " + address + ": "
								+ e.getMessage());
					}

					JsonObject votePayload;
					try {
						votePayload = gson.fromJson(payload, JsonObject.class);
					} catch (Exception e) {
						if (throttle != null)
							throttle.fail(throttleKey, tunnelMode, realIpKnown);
						throw new Exception("Invalid vote format: Inner payload is not valid JSON from " + address
								+ ": " + e.getMessage());
					}

					// Validate required fields in inner payload.
					if (!votePayload.has("serviceName") || !votePayload.has("username") || !votePayload.has("address")
							|| !votePayload.has("timestamp") || !votePayload.has("challenge")) {
						if (throttle != null)
							throttle.fail(throttleKey, tunnelMode, realIpKnown);
						throw new Exception(
								"Invalid vote format: Missing required fields in inner JSON from " + address);
					}

					String serviceNameFromPayload = votePayload.get("serviceName").getAsString();

					// Lookup the token using the serviceName from the inner payload.
					Key key = getTokens().get(serviceNameFromPayload);
					if (key == null) {
						key = getTokens().get("default");
						if (key == null) {
							if (throttle != null)
								throttle.fail(throttleKey, tunnelMode, realIpKnown);
							throw new Exception("Authentication failed: Unknown token for service '"
									+ serviceNameFromPayload + "' from " + address);
						}
						debug("Using default token for service: " + serviceNameFromPayload);
					} else {
						debug("Using service-specific token for: " + serviceNameFromPayload);
					}

					// Verify HMAC signature using the payload bytes.
					if (!hmacEqual(sigBytes, payload.getBytes(StandardCharsets.UTF_8), key)) {
						// invalid signature is a common scanner/noise case; throttle it
						if (throttle != null)
							throttle.fail(throttleKey, tunnelMode, realIpKnown);

						String msg2 = "Authentication failed: Signature verification failed from "
								+ (realIpKnown ? realIp : remoteIp) + " (service=" + serviceNameFromPayload + ")";
						String toLog = warnLimiter.allow("badsig|" + throttleKey, msg2);
						if (toLog != null)
							logWarning(toLog);

						throw new Exception(
								"Authentication failed: Signature verification failed (invalid token?) for service '"
										+ serviceNameFromPayload + "' from " + address);
					}

					serviceName = serviceNameFromPayload;
					username = votePayload.get("username").getAsString();
					address1 = votePayload.get("address").getAsString();
					timeStamp = votePayload.get("timestamp").getAsString();

					// Verify the challenge.
					String receivedChallenge = votePayload.get("challenge").getAsString().trim();
					if (!receivedChallenge.equals(challenge.trim())) {
						if (throttle != null)
							throttle.fail(throttleKey, tunnelMode, realIpKnown);
						throw new Exception("Authentication failed: Invalid challenge from " + address);
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

				// Source address: prefer real client IP if known (PROXY v1)
				if (realIpKnown) {
					vote.setSourceAddress(realIp);
				} else if (address != null) {
					vote.setSourceAddress(address);
				} else {
					vote.setSourceAddress("unknown");
				}

				if (timeStamp.equalsIgnoreCase("TestVote")) {
					log("Test vote received");
				}

				log("Received vote record -> " + vote);

				// Success: reset throttle state for this key so legit votes don't get punished
				if (throttle != null)
					throttle.success(throttleKey);

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

				forwardVote(vote);
				callEvent(vote);

				writer.close();
				in.close();
				socket.close();

			} catch (MalformedJsonException ex) {
				// Throttle + rate-limited warn
				ThrottleConfig cfg2 = getThrottleConfig();
				boolean tunnelMode = cfg2 != null && cfg2.enabled && cfg2.tunnelRemoteIps.contains(remoteIp);
				String throttleKey = "tunnel:" + remoteIp;

				if (throttle != null)
					throttle.fail(throttleKey, tunnelMode, false);
				String toLog = warnLimiter.allow("malformedjson|" + throttleKey,
						"Invalid vote format: Malformed JSON payload from " + remoteIp + " - " + ex.getMessage());
				if (toLog != null)
					logWarning(toLog);
				debug(ex);

			} catch (SocketException ex) {
				if (running) {
					String toLog = warnLimiter.allow("socket|" + remoteIp,
							"Connection error: Protocol error from " + remoteIp + " - " + ex.getLocalizedMessage());
					if (toLog != null)
						logWarning(toLog);
					debug(ex);
				} else {
					logWarning("Votifier socket closed.");
				}

			} catch (BadPaddingException ex) {
				// Keep this very quiet; the hot path already logs throttled warnings
				debug(ex);

			} catch (SocketTimeoutException ex) {
				// Typically port-probe noise; keep WARN throttled
				String toLog = warnLimiter.allow("timeout|" + remoteIp,
						"Connection timeout while waiting for vote payload from " + remoteIp + " - " + ex.getMessage());
				if (toLog != null)
					logWarning(toLog);
				debug(ex);

			} catch (Exception ex) {
				String errorMsg = ex.getMessage();
				if (errorMsg != null && (errorMsg.startsWith("Invalid vote format:")
						|| errorMsg.startsWith("Authentication failed:"))) {
					// Throttle these too
					ThrottleConfig cfg2 = getThrottleConfig();
					boolean tunnelMode = cfg2 != null && cfg2.enabled && cfg2.tunnelRemoteIps.contains(remoteIp);
					String throttleKey = "tunnel:" + remoteIp;
					if (throttle != null)
						throttle.fail(throttleKey, tunnelMode, false);

					String toLog = warnLimiter.allow("validation|" + throttleKey, errorMsg);
					if (toLog != null)
						logWarning(toLog);
				} else {
					String toLog = warnLimiter.allow("generic|" + remoteIp,
							"Error processing vote from " + remoteIp + ": " + ex.getLocalizedMessage());
					if (toLog != null)
						logWarning(toLog);
				}
				debug(ex);
			}
		}
	}

	private void forwardVote(Vote vote) {
		for (String name : getServers()) {
			ForwardServer fs = getServerData(name);

			if (!fs.isEnabled()) {
				debug("Skipping disabled forward server: " + name);
				continue;
			}

			debug("Preparing to forward vote to: " + name + ", tokens mode: " + fs.isUseTokens());

			try (Socket s = new Socket()) {
				s.connect(new InetSocketAddress(fs.getHost(), fs.getPort()), 1000);
				BufferedReader in = new BufferedReader(
						new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
				OutputStream outStream = s.getOutputStream();

				// --- Handshake: read server greeting (v2) ---
				String serverGreeting = in.readLine();
				debug("Received handshake from " + name + ": '" + serverGreeting + "'");

				byte[] payload;
				if (fs.isUseTokens()) {
					// Extract challenge
					String[] parts = serverGreeting.split(" ");
					if (parts.length < 3 || !"VOTIFIER".equals(parts[0]) || !"2".equals(parts[1])) {
						throw new IllegalStateException(
								"Invalid token-mode handshake from " + name + ": " + serverGreeting);
					}
					String chal = parts[2];

					// Build inner JSON
					JsonObject inner = new JsonObject();
					inner.addProperty("serviceName", vote.getServiceName());
					inner.addProperty("username", vote.getUsername());
					inner.addProperty("address", vote.getAddress());
					inner.addProperty("timestamp", vote.getTimeStamp());
					inner.addProperty("challenge", chal);
					String innerStr = inner.toString();

					// Compute HMAC signature
					Mac mac = Mac.getInstance("HmacSHA256");
					mac.init(fs.getToken());
					String sig = Base64.getEncoder()
							.encodeToString(mac.doFinal(innerStr.getBytes(StandardCharsets.UTF_8)));

					// Outer JSON with CRLF
					JsonObject outer = new JsonObject();
					outer.addProperty("payload", innerStr);
					outer.addProperty("signature", sig);
					String jsonVote = outer.toString() + "\r\n";
					payload = jsonVote.getBytes(StandardCharsets.UTF_8);

				} else {
					// Legacy V1 RSA-encrypted block
					String vs = String.join("\n", "VOTE", vote.getServiceName(), vote.getUsername(), vote.getAddress(),
							vote.getTimeStamp(), "") + "\n";
					payload = encrypt(vs.getBytes(StandardCharsets.UTF_8), getPublicKey(fs));
				}

				// Send the vote payload
				outStream.write(payload);
				outStream.flush();
				debug("Payload forwarded to " + name + " (" + payload.length + " bytes)");

			} catch (Exception e) {
				log("Failed to forward vote to " + name + ": " + e.getClass().getSimpleName() + " – " + e.getMessage());
				debug(e);
			}
		}
	}

	private static String extractIp(String remote) {
		if (remote == null)
			return "unknown";
		String s = remote.startsWith("/") ? remote.substring(1) : remote;
		int colon = s.lastIndexOf(':');
		return colon > 0 ? s.substring(0, colon) : s;
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
	 *
	 * @return real client IP if PROXY v1 is present and parseable, otherwise null.
	 */
	private String processProxyHeaders(PushbackInputStream in, BufferedWriter writer) throws Exception {
		byte[] headerPeek = new byte[32];
		int bytesRead = in.read(headerPeek);
		if (bytesRead <= 0)
			return null;

		String headerString = new String(headerPeek, 0, bytesRead, StandardCharsets.US_ASCII);

		// PROXY v1: "PROXY TCP4 <srcIP> <dstIP> <srcPort> <dstPort>"
		if (headerString.startsWith("PROXY") && !headerString.contains("CONNECT")) {
			in.unread(headerPeek, 0, bytesRead);

			String proxyHeader = readLine(in);
			debug("Discarded PROXY (v1) header: " + proxyHeader);

			String[] parts = proxyHeader.split("\\s+");
			if (parts.length >= 3) {
				String srcIp = parts[2].trim();
				return srcIp.isEmpty() ? null : srcIp;
			}
			return null;
		}

		// PROXY v2: discard (not parsing real IP here)
		if (bytesRead >= 12 && isProxyV2(headerPeek)) {
			// headerPeek already contains first bytes; v2 length is at [14..15]
			int addrLength = ((headerPeek[14] & 0xFF) << 8) | (headerPeek[15] & 0xFF);
			int totalV2HeaderLength = 16 + addrLength;

			int remaining = totalV2HeaderLength - bytesRead;
			if (remaining > 0) {
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
			}

			debug("Discarded PROXY protocol v2 header (" + totalV2HeaderLength + " bytes)");
			return null;
		}

		// HTTP CONNECT tunneling
		if (headerString.startsWith("CONNECT")) {
			in.unread(headerPeek, 0, bytesRead);
			String connectLine = readLine(in);
			debug("Received CONNECT request: " + connectLine);

			String line;
			while (!(line = readLine(in)).isEmpty()) {
				debug("Discarding header: " + line);
			}

			writer.write("HTTP/1.1 200 Connection Established\r\n\r\n");
			writer.flush();
			return null;
		}

		// No proxy header; push back bytes
		in.unread(headerPeek, 0, bytesRead);
		return null;
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

		// constant-time-ish compare
		int diff = 0;
		for (int i = 0; i < providedSig.length; i++) {
			diff |= (providedSig[i] ^ computed[i]);
		}
		return diff == 0;
	}
}
