package com.bencodez.votifierplus.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.io.PushbackInputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

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
import com.vexsoftware.votifier.net.ProxyHeaderProcessor;
import com.vexsoftware.votifier.net.ThrottleConfig;
import com.vexsoftware.votifier.net.VoteAuthenticationException;
import com.vexsoftware.votifier.net.InvalidVoteException;
import com.vexsoftware.votifier.net.VoteParser;
import com.vexsoftware.votifier.net.VoteProtocolVersion;
import com.vexsoftware.votifier.net.VoteReceiver;
import com.vexsoftware.votifier.net.VoteRequest;

/**
 * Unit tests for parser and proxy handling after splitting VoteReceiver into
 * separate classes.
 */
public class VoteReceiverTest {

	private static KeyPair testKeyPair;
	private static Key dummyTokenKey;

	private TestVoteReceiver receiver;
	private VoteParser parser;
	private ProxyHeaderProcessor proxyHeaderProcessor;

	@BeforeAll
	public static void setupClass() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		testKeyPair = kpg.generateKeyPair();
		dummyTokenKey = new SecretKeySpec("dummySecretKey1234".getBytes(StandardCharsets.UTF_8), "HmacSHA256");
	}

	@BeforeEach
	public void setup() throws Exception {
		receiver = new TestVoteReceiver("127.0.0.1", 0);
		parser = new VoteParser();
		proxyHeaderProcessor = new ProxyHeaderProcessor();
	}

	@AfterEach
	public void tearDown() {
		receiver.shutdown();
	}

	private static class TestVoteReceiver extends VoteReceiver {

		private final String testChallenge = "testChallenge";

		public TestVoteReceiver(String host, int port) throws Exception {
			super(host, port);
		}

		@Override
		public boolean isUseTokens() {
			return false;
		}

		@Override
		public void logWarning(String warn) {
		}

		@Override
		public void logSevere(String msg) {
		}

		@Override
		public void log(String msg) {
		}

		@Override
		public void debug(String msg) {
		}

		@Override
		public void debug(Exception e) {
		}

		@Override
		public String getVersion() {
			return "Test";
		}

		@Override
		public Set<String> getServers() {
			return Collections.emptySet();
		}

		@Override
		public KeyPair getKeyPair() {
			return testKeyPair;
		}

		@Override
		public Map<String, Key> getTokens() {
			return Collections.singletonMap("votifier.bencodez.com", dummyTokenKey);
		}

		@Override
		public ForwardServer getServerData(String s) {
			return null;
		}

		@Override
		public void callEvent(Vote e) {
		}

		@Override
		public String getChallenge() {
			return testChallenge;
		}

		@Override
		public ThrottleConfig getThrottleConfig() {
			return null;
		}
	}

	@Test
	public void testDetectV1VoteProtocol() throws Exception {
		String voteMsg = "VOTE\nvotifier.bencodez.com\ntestUser\n127.0.0.1\nTestTimestamp\n";
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, testKeyPair.getPublic());
		byte[] encrypted = cipher.doFinal(voteMsg.getBytes(StandardCharsets.UTF_8));

		PushbackInputStream in = new PushbackInputStream(new ByteArrayInputStream(encrypted), 512);
		VoteProtocolVersion version = parser.detectVersion(in);
		assertEquals(VoteProtocolVersion.V1, version);
	}

	@Test
	public void testParseV1Vote() throws Exception {
		String voteMsg = "VOTE\nvotifier.bencodez.com\ntestUser\n127.0.0.1\nTestTimestamp\n";
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, testKeyPair.getPublic());
		byte[] encrypted = cipher.doFinal(voteMsg.getBytes(StandardCharsets.UTF_8));
		assertEquals(256, encrypted.length);

		PushbackInputStream in = new PushbackInputStream(new ByteArrayInputStream(encrypted), 512);
		VoteRequest request = parser.parse(in, VoteProtocolVersion.V1, receiver, "test-address", receiver.getChallenge());

		assertNotNull(request);
		assertEquals("votifier.bencodez.com", request.getServiceName());
		assertEquals("testUser", request.getUsername());
		assertEquals("127.0.0.1", request.getAddress());
		assertEquals("TestTimestamp", request.getTimeStamp());
	}

	@Test
	public void testDetectV2VoteProtocol() throws Exception {
		String jsonPayload = "{\"payload\":\"{}\",\"signature\":\"dGVzdA==\"}";
		PushbackInputStream in = new PushbackInputStream(
				new ByteArrayInputStream(jsonPayload.getBytes(StandardCharsets.UTF_8)), 512);

		VoteProtocolVersion version = parser.detectVersion(in);
		assertEquals(VoteProtocolVersion.V2, version);
	}

	@Test
	public void testParseV2Vote() throws Exception {
		JsonObject inner = new JsonObject();
		inner.addProperty("serviceName", "votifier.bencodez.com");
		inner.addProperty("username", "testUserV2");
		inner.addProperty("address", "127.0.0.1");
		inner.addProperty("timestamp", "TestTimestampV2");
		inner.addProperty("challenge", "testChallenge");
		String payload = inner.toString();

		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(dummyTokenKey);
		byte[] signatureBytes = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
		String signature = Base64.getEncoder().encodeToString(signatureBytes);

		JsonObject outer = new JsonObject();
		outer.addProperty("payload", payload);
		outer.addProperty("signature", signature);

		PushbackInputStream in = new PushbackInputStream(
				new ByteArrayInputStream(outer.toString().getBytes(StandardCharsets.UTF_8)), 512);

		VoteRequest request = parser.parse(in, VoteProtocolVersion.V2, receiver, "test-address", receiver.getChallenge());

		assertNotNull(request);
		assertEquals("votifier.bencodez.com", request.getServiceName());
		assertEquals("testUserV2", request.getUsername());
		assertEquals("127.0.0.1", request.getAddress());
		assertEquals("TestTimestampV2", request.getTimeStamp());
	}

	@Test
	public void testProxyV1Header() throws Exception {
		String proxyHeader = "PROXY TCP4 192.168.1.1 192.168.1.2 1234 80\r\n";
		String remainingData = "VOTE\nvotifier.bencodez.com\ntestUser\n127.0.0.1\nTestTimestamp\n";
		String input = proxyHeader + remainingData;

		PushbackInputStream pis = new PushbackInputStream(
				new ByteArrayInputStream(input.getBytes(StandardCharsets.US_ASCII)), 512);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(baos, StandardCharsets.US_ASCII));

		ProxyHeaderProcessor.ProxyHeaderResult result = proxyHeaderProcessor.process(pis, writer, receiver);

		assertEquals("192.168.1.1", result.getRealIp());

		byte[] remaining = new byte[remainingData.length()];
		int read = pis.read(remaining);
		String output = new String(remaining, 0, read, StandardCharsets.US_ASCII);
		assertEquals(remainingData, output);
	}

	@Test
	public void testConnectHeader() throws Exception {
		String connectHeader = "CONNECT some.host:443 HTTP/1.1\r\nHost: some.host:443\r\n\r\n";
		String remainingData = "VOTE\nvotifier.bencodez.com\ntestUser\n127.0.0.1\nTestTimestamp\n";
		String input = connectHeader + remainingData;

		PushbackInputStream pis = new PushbackInputStream(
				new ByteArrayInputStream(input.getBytes(StandardCharsets.US_ASCII)), 512);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(baos, StandardCharsets.US_ASCII));

		ProxyHeaderProcessor.ProxyHeaderResult result = proxyHeaderProcessor.process(pis, writer, receiver);
		writer.flush();

		assertEquals(null, result.getRealIp());

		String response = baos.toString("ASCII");
		assertTrue(response.contains("200 Connection Established"));

		byte[] remaining = new byte[remainingData.length()];
		int read = pis.read(remaining);
		String output = new String(remaining, 0, read, StandardCharsets.US_ASCII);
		assertEquals(remainingData, output);
	}

	@Test
	public void testV2VoteMissingPayloadField() throws Exception {
		JsonObject outer = new JsonObject();
		outer.addProperty("signature", "dummySignature");

		PushbackInputStream in = new PushbackInputStream(
				new ByteArrayInputStream(outer.toString().getBytes(StandardCharsets.UTF_8)), 512);

		InvalidVoteException exception = assertThrows(InvalidVoteException.class,
				() -> parser.parse(in, VoteProtocolVersion.V2, receiver, "test", receiver.getChallenge()));

		assertTrue(exception.getMessage().contains("Missing required fields in outer JSON"));
	}

	@Test
	public void testV2VoteMissingSignatureField() throws Exception {
		JsonObject outer = new JsonObject();
		outer.addProperty("payload", "{}");

		PushbackInputStream in = new PushbackInputStream(
				new ByteArrayInputStream(outer.toString().getBytes(StandardCharsets.UTF_8)), 512);

		InvalidVoteException exception = assertThrows(InvalidVoteException.class,
				() -> parser.parse(in, VoteProtocolVersion.V2, receiver, "test", receiver.getChallenge()));

		assertTrue(exception.getMessage().contains("Missing required fields in outer JSON"));
	}

	@Test
	public void testV2VoteMissingUsernameField() throws Exception {
		JsonObject inner = new JsonObject();
		inner.addProperty("serviceName", "votifier.bencodez.com");
		inner.addProperty("address", "127.0.0.1");
		inner.addProperty("timestamp", "TestTimestamp");
		inner.addProperty("challenge", "testChallenge");
		String payload = inner.toString();

		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(dummyTokenKey);
		byte[] signatureBytes = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
		String signature = Base64.getEncoder().encodeToString(signatureBytes);

		JsonObject outer = new JsonObject();
		outer.addProperty("payload", payload);
		outer.addProperty("signature", signature);

		PushbackInputStream in = new PushbackInputStream(
				new ByteArrayInputStream(outer.toString().getBytes(StandardCharsets.UTF_8)), 512);

		InvalidVoteException exception = assertThrows(InvalidVoteException.class,
				() -> parser.parse(in, VoteProtocolVersion.V2, receiver, "test", receiver.getChallenge()));

		assertTrue(exception.getMessage().contains("Missing required fields in inner JSON"));
	}

	@Test
	public void testV2VoteInvalidChallenge() throws Exception {
		JsonObject inner = new JsonObject();
		inner.addProperty("serviceName", "votifier.bencodez.com");
		inner.addProperty("username", "testUser");
		inner.addProperty("address", "127.0.0.1");
		inner.addProperty("timestamp", "TestTimestamp");
		inner.addProperty("challenge", "wrongChallenge");
		String payload = inner.toString();

		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(dummyTokenKey);
		byte[] signatureBytes = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
		String signature = Base64.getEncoder().encodeToString(signatureBytes);

		JsonObject outer = new JsonObject();
		outer.addProperty("payload", payload);
		outer.addProperty("signature", signature);

		PushbackInputStream in = new PushbackInputStream(
				new ByteArrayInputStream(outer.toString().getBytes(StandardCharsets.UTF_8)), 512);

		VoteAuthenticationException exception = assertThrows(VoteAuthenticationException.class,
				() -> parser.parse(in, VoteProtocolVersion.V2, receiver, "test", receiver.getChallenge()));

		assertTrue(exception.getMessage().contains("Invalid challenge"));
	}

	@Test
	public void testV2VoteInvalidBase64Signature() throws Exception {
		JsonObject inner = new JsonObject();
		inner.addProperty("serviceName", "votifier.bencodez.com");
		inner.addProperty("username", "testUser");
		inner.addProperty("address", "127.0.0.1");
		inner.addProperty("timestamp", "TestTimestamp");
		inner.addProperty("challenge", "testChallenge");
		String payload = inner.toString();

		JsonObject outer = new JsonObject();
		outer.addProperty("payload", payload);
		outer.addProperty("signature", "not-valid-base64!!!");

		PushbackInputStream in = new PushbackInputStream(
				new ByteArrayInputStream(outer.toString().getBytes(StandardCharsets.UTF_8)), 512);

		InvalidVoteException exception = assertThrows(InvalidVoteException.class,
				() -> parser.parse(in, VoteProtocolVersion.V2, receiver, "test", receiver.getChallenge()));

		assertTrue(exception.getMessage().contains("Signature is not valid Base64"));
	}

	@Test
	public void testV2VoteEmptyUsernameField() throws Exception {
		JsonObject inner = new JsonObject();
		inner.addProperty("serviceName", "votifier.bencodez.com");
		inner.addProperty("username", "   ");
		inner.addProperty("address", "127.0.0.1");
		inner.addProperty("timestamp", "TestTimestamp");
		inner.addProperty("challenge", "testChallenge");
		String payload = inner.toString();

		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(dummyTokenKey);
		byte[] signatureBytes = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
		String signature = Base64.getEncoder().encodeToString(signatureBytes);

		JsonObject outer = new JsonObject();
		outer.addProperty("payload", payload);
		outer.addProperty("signature", signature);

		PushbackInputStream in = new PushbackInputStream(
				new ByteArrayInputStream(outer.toString().getBytes(StandardCharsets.UTF_8)), 512);

		InvalidVoteException exception = assertThrows(InvalidVoteException.class,
				() -> parser.parse(in, VoteProtocolVersion.V2, receiver, "test", receiver.getChallenge()));

		assertTrue(exception.getMessage().contains("empty field 'username'"));
	}

	@Test
	public void testBuildVoteFromParsedRequest() throws Exception {
		String voteMsg = "VOTE\nvotifier.bencodez.com\ntestUser\n127.0.0.1\nTestTimestamp\n";
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, testKeyPair.getPublic());
		byte[] encrypted = cipher.doFinal(voteMsg.getBytes(StandardCharsets.UTF_8));

		PushbackInputStream in = new PushbackInputStream(new ByteArrayInputStream(encrypted), 512);
		VoteRequest request = parser.parse(in, VoteProtocolVersion.V1, receiver, "test-address", receiver.getChallenge());

		Vote vote = new Vote();
		vote.setServiceName(request.getServiceName());
		vote.setUsername(request.getUsername());
		vote.setAddress(request.getAddress());
		vote.setTimeStamp(request.getTimeStamp());
		vote.setSourceAddress("192.168.1.1");

		assertEquals("votifier.bencodez.com", vote.getServiceName());
		assertEquals("testUser", vote.getUsername());
		assertEquals("127.0.0.1", vote.getAddress());
		assertEquals("TestTimestamp", vote.getTimeStamp());
		assertEquals("192.168.1.1", vote.getSourceAddress());
	}
}