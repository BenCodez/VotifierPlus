package com.bencodez.votifierplus.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PushbackInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.google.gson.JsonObject;
import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.model.Vote;
import com.vexsoftware.votifier.net.InvalidVoteException;
import com.vexsoftware.votifier.net.ProxyHeaderProcessor;
import com.vexsoftware.votifier.net.ThrottleConfig;
import com.vexsoftware.votifier.net.VoteConnectionHandler;
import com.vexsoftware.votifier.net.VoteForwarder;
import com.vexsoftware.votifier.net.VoteLogSafety;
import com.vexsoftware.votifier.net.VoteProtocolPolicy;
import com.vexsoftware.votifier.net.VoteReceiver;
import com.vexsoftware.votifier.net.VoteThrottleService;

public class VoteLoggingSecurityTest {
	private static KeyPair keyPair;
	private static Key token;
	private RecordingReceiver receiver;
	private ExecutorService executor;

	@BeforeAll
	public static void setupClass() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		keyPair = generator.generateKeyPair();
		token = new SecretKeySpec("logging-test-token".getBytes(StandardCharsets.US_ASCII), "HmacSHA256");
	}

	@BeforeEach
	public void setup() throws Exception {
		VoteProtocolPolicy.setDisableV1(false);
		receiver = new RecordingReceiver();
		executor = Executors.newCachedThreadPool();
	}

	@AfterEach
	public void tearDown() {
		VoteProtocolPolicy.setDisableV1(false);
		executor.shutdownNow();
		receiver.shutdown();
	}

	@Test
	public void testLogFieldsAreBoundedAndSingleLine() {
		assertEquals("a?b?c?d", VoteLogSafety.field("a\nb\rc\u001bd"));
		assertEquals("x?y", VoteLogSafety.field("x\u2028y"));
		assertTrue(VoteLogSafety.field("X".repeat(10000)).length() <= 96);
		assertTrue(VoteLogSafety.message("Y".repeat(10000)).length() <= 240);
		assertFalse(VoteLogSafety.field("A\u202eB").contains("\u202e"));
	}

	@Test
	public void testValidV2LogsUsefulSafeSummaryWithoutPayloadOrSignature() throws Exception {
		String service = "site\n" + "S".repeat(5000);
		String user = "bob\radmin";
		String address = "private-address-value";
		String timestamp = "private-time-value";
		String inner = innerPayload(service, user, address, timestamp);
		String signature = signature(inner);
		Vote vote = sendV2(outerPayload(inner, signature));
		assertNotNull(vote);
		assertEquals(user, vote.getUsername());
		String logs = allLogs();
		assertTrue(logs.contains("Received vote record: service=site?"));
		assertTrue(logs.contains("user=bob?admin"));
		assertTrue(logs.contains("source=127.0.0.1"));
		assertFalse(logs.contains(signature));
		assertFalse(logs.contains(inner));
		assertFalse(logs.contains(address));
		assertFalse(logs.contains(timestamp));
		assertSafeLines();
		assertTrue(receiver.info.stream().allMatch(line -> line.length() < 240));
	}

	@Test
	public void testInvalidSignatureAndOpcodeDoNotEchoAttackerText() throws Exception {
		String marker = "secret-signature-value";
		String inner = innerPayload("bad\nservice", "user", "address", "timestamp");
		assertNull(sendV2(outerPayload(inner, marker)));
		assertFalse(allLogs().contains(marker));
		assertFalse(allLogs().contains("bad\nservice"));
		assertTrue(receiver.warnings.stream().anyMatch(line -> line.contains("Signature is not valid Base64")));
		String opcode = "INJECT-MARKER\rCONTROL";
		assertNull(sendV1(opcode));
		assertFalse(allLogs().contains("INJECT-MARKER"));
		assertSafeLines();
	}

	@Test
	public void testProxyAndConnectDebugNeverIncludeHeaderValues() throws Exception {
		ProxyHeaderProcessor processor = new ProxyHeaderProcessor();
		String proxy = "PROXY TCP4 injected\u001b[31m 127.0.0.1 1 2\r\nVOTE";
		PushbackInputStream input = new PushbackInputStream(
				new ByteArrayInputStream(proxy.getBytes(StandardCharsets.US_ASCII)), 512);
		processor.process(input, writer(), receiver);
		String connect = "CONNECT vote.example:443 HTTP/1.1\r\nAuthorization: secret-value\u001b[31m\r\n\r\nVOTE";
		input = new PushbackInputStream(new ByteArrayInputStream(connect.getBytes(StandardCharsets.US_ASCII)), 512);
		processor.process(input, writer(), receiver);
		assertFalse(allLogs().contains("injected"));
		assertFalse(allLogs().contains("secret-value"));
		assertTrue(allLogs().contains("CONNECT headers"));
		assertSafeLines();

		String oversized = "CONNECT " + "X".repeat(9000) + "\r\n";
		PushbackInputStream tooLarge = new PushbackInputStream(
				new ByteArrayInputStream(oversized.getBytes(StandardCharsets.US_ASCII)), 512);
		assertThrows(InvalidVoteException.class, () -> processor.process(tooLarge, writer(), receiver));
		assertFalse(allLogs().contains("X".repeat(100)));
	}

	@Test
	public void testOversizedForwardHandshakeDoesNotEnterLogs() throws Exception {
		try (ServerSocket server = new ServerSocket(0)) {
			receiver.forwardServer = new ForwardServer(true, "127.0.0.1", server.getLocalPort(), "", token);
			Future<?> peer = executor.submit(() -> {
				try (Socket accepted = server.accept()) {
					accepted.getOutputStream().write(("A".repeat(600) + "\r\n").getBytes(StandardCharsets.US_ASCII));
					accepted.getOutputStream().flush();
				} catch (Exception ignored) {
				}
			});
			new VoteForwarder(receiver).forwardVote(new Vote("site", "user", "address", "timestamp"));
			peer.get(5, TimeUnit.SECONDS);
			assertTrue(receiver.info.stream().anyMatch(line -> line.contains("IllegalStateException")));
			assertFalse(allLogs().contains("A".repeat(100)));
			assertSafeLines();
		}
	}

	private Vote sendV2(String payload) throws Exception {
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, new VoteThrottleService(null));
		try (ServerSocket server = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", server.getLocalPort());
				Socket accepted = server.accept()) {
			Future<Vote> future = executor.submit(() -> handler.handle(accepted));
			BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
			assertEquals("VOTIFIER 2 challenge", reader.readLine());
			client.getOutputStream().write(payload.getBytes(StandardCharsets.UTF_8));
			client.getOutputStream().flush();
			client.shutdownOutput();
			return future.get(5, TimeUnit.SECONDS);
		}
	}

	private Vote sendV1(String opcode) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
		String payload = opcode + "\nsite\nuser\n127.0.0.1\nNormalTimestamp\n";
		byte[] encrypted = cipher.doFinal(payload.getBytes(StandardCharsets.US_ASCII));
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, new VoteThrottleService(null));
		try (ServerSocket server = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", server.getLocalPort());
				Socket accepted = server.accept()) {
			Future<Vote> future = executor.submit(() -> handler.handle(accepted));
			BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
			assertEquals("VOTIFIER 2 challenge", reader.readLine());
			client.getOutputStream().write(encrypted);
			client.getOutputStream().flush();
			client.shutdownOutput();
			return future.get(5, TimeUnit.SECONDS);
		}
	}

	private String innerPayload(String service, String user, String address, String timestamp) {
		JsonObject inner = new JsonObject();
		inner.addProperty("serviceName", service);
		inner.addProperty("username", user);
		inner.addProperty("address", address);
		inner.addProperty("timestamp", timestamp);
		inner.addProperty("challenge", "challenge");
		return inner.toString();
	}

	private String signature(String inner) throws Exception {
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(token);
		return Base64.getEncoder().encodeToString(mac.doFinal(inner.getBytes(StandardCharsets.UTF_8)));
	}

	private String outerPayload(String inner, String signature) {
		JsonObject outer = new JsonObject();
		outer.addProperty("payload", inner);
		outer.addProperty("signature", signature);
		return outer.toString() + "\r\n";
	}

	private BufferedWriter writer() {
		return new BufferedWriter(new OutputStreamWriter(new ByteArrayOutputStream(), StandardCharsets.US_ASCII));
	}

	private String allLogs() {
		return String.join("|", receiver.info) + "|" + String.join("|", receiver.warnings)
				+ "|" + String.join("|", receiver.debug);
	}

	private void assertSafeLines() {
		for (String line : receiver.info) assertSafe(line);
		for (String line : receiver.warnings) assertSafe(line);
		for (String line : receiver.debug) assertSafe(line);
	}

	private void assertSafe(String line) {
		assertFalse(line.contains("\n"), line);
		assertFalse(line.contains("\r"), line);
		assertFalse(line.contains("\u001b"), line);
	}

	private static final class RecordingReceiver extends VoteReceiver {
		private final List<String> info = new CopyOnWriteArrayList<>();
		private final List<String> warnings = new CopyOnWriteArrayList<>();
		private final List<String> debug = new CopyOnWriteArrayList<>();
		private ForwardServer forwardServer;

		RecordingReceiver() throws Exception {
			super("127.0.0.1", 0);
		}

		@Override public void logWarning(String message) { if (warnings != null) warnings.add(message); }
		@Override public void logSevere(String message) { }
		@Override public void log(String message) { if (info != null) info.add(message); }
		@Override public void debug(String message) { if (debug != null) debug.add(message); }
		@Override public void debug(Exception error) { }
		@Override public String getVersion() { return "test"; }
		@Override public String getChallenge() { return "challenge"; }
		@Override public boolean isUseTokens() { return true; }
		@Override public Set<String> getServers() { return forwardServer == null ? Collections.emptySet() : Collections.singleton("backend"); }
		@Override public ForwardServer getServerData(String server) { return forwardServer; }
		@Override public KeyPair getKeyPair() { return keyPair; }
		@Override public Map<String, Key> getTokens() { return Collections.singletonMap("default", token); }
		@Override public void callEvent(Vote vote) { }
		@Override public ThrottleConfig getThrottleConfig() { return null; }
	}
}
