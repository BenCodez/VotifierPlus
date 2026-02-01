package com.bencodez.votifierplus.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.io.PushbackInputStream;
import java.lang.reflect.Method;
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

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.crypto.RSA;
import com.vexsoftware.votifier.model.Vote;
import com.vexsoftware.votifier.net.VoteReceiver;

/**
 * Unit tests for processing V1 (RSA) and V2 (token/JSON) vote payloads,
 * including verification of the challenge and proxy header processing.
 */
public class VoteReceiverTest {

	// Test RSA key pair for v1 tests.
	private static KeyPair testKeyPair;
	// Dummy token key for v2 tests.
	private static Key dummyTokenKey;

	// Our test receiver instance; will bind to an ephemeral port (0).
	private TestVoteReceiver receiver;

	@BeforeAll
	public static void setupClass() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		testKeyPair = kpg.generateKeyPair();
		// Create a dummy HMAC key (for example purposes)
		dummyTokenKey = new SecretKeySpec("dummySecretKey1234".getBytes(StandardCharsets.UTF_8), "HmacSHA256");
	}

	@BeforeEach
	public void setup() throws Exception {
		// Bind to port 0 to let the OS assign an available port.
		receiver = new TestVoteReceiver("127.0.0.1", 0, testKeyPair);
	}

	@AfterEach
	public void tearDown() {
		receiver.shutdown();
	}

	/**
	 * A dummy subclass of VoteReceiver for testing. We override abstract methods
	 * and expose helper methods for processing votes.
	 */
	private static class TestVoteReceiver extends VoteReceiver {

		private final String testChallenge = "testChallenge";

		public TestVoteReceiver(String host, int port, KeyPair keyPair) throws Exception {
			super(host, port);
		}

		/**
		 * Process a V1 vote block. The block is assumed to be exactly the RSA-encrypted
		 * vote block.
		 */
		public Vote processV1Vote(byte[] encryptedBlock) throws Exception {
			byte[] decrypted = RSA.decrypt(encryptedBlock, getKeyPair().getPrivate());
			int position = 0;
			String opcode = readString(decrypted, position);
			position += opcode.length() + 1;
			if (!opcode.equals("VOTE")) {
				throw new Exception("Invalid opcode: " + opcode);
			}
			String serviceName = readString(decrypted, position);
			position += serviceName.length() + 1;
			String username = readString(decrypted, position);
			position += username.length() + 1;
			String address = readString(decrypted, position);
			position += address.length() + 1;
			String timeStamp = readString(decrypted, position);
			position += timeStamp.length() + 1;
			Vote vote = new Vote();
			vote.setServiceName(serviceName);
			vote.setUsername(username);
			vote.setAddress(address);
			vote.setTimeStamp(timeStamp);
			return vote;
		}

		/**
		 * Process a V2 vote payload in JSON format.
		 */
		public Vote processV2Vote(String jsonPayload) throws Exception {
			Gson gson = new Gson();
			JsonObject outer = gson.fromJson(jsonPayload, JsonObject.class);
			String payload = outer.get("payload").getAsString();
			JsonObject inner = gson.fromJson(payload, JsonObject.class);
			// Verify challenge.
			if (!inner.has("challenge")) {
				throw new Exception("Vote payload missing challenge field.");
			}
			String receivedChallenge = inner.get("challenge").getAsString();
			if (!receivedChallenge.equals(getChallenge())) {
				throw new Exception("Invalid challenge: expected " + getChallenge() + " but got " + receivedChallenge);
			}
			Vote vote = new Vote();
			vote.setServiceName(inner.get("serviceName").getAsString());
			vote.setUsername(inner.get("username").getAsString());
			vote.setAddress(inner.get("address").getAsString());
			vote.setTimeStamp(inner.get("timestamp").getAsString());

			return vote;
		}

		// Dummy implementations for abstract methods:
		@Override
		public boolean isUseTokens() {
			// For testing, we decide based on our mode.
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
		public void debug(Exception e) {
		}

		// Expose readString method (reimplementation)
		public String readString(byte[] data, int offset) {
			StringBuilder builder = new StringBuilder();
			for (int i = offset; i < data.length; i++) {
				if (data[i] == '\n')
					break;
				builder.append((char) data[i]);
			}
			return builder.toString();
		}

		// For V2, challenge is always testChallenge.
		@Override
		public String getChallenge() {
			return testChallenge;
		}
	}

	@Test
	public void testV1Vote() throws Exception {
		// Construct a vote message for V1.
		String voteMsg = "VOTE\nvotifier.bencodez.com\ntestUser\n127.0.0.1\nTestTimestamp\n";
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, testKeyPair.getPublic());
		byte[] encrypted = cipher.doFinal(voteMsg.getBytes(StandardCharsets.UTF_8));
		assertEquals(256, encrypted.length);

		Vote vote = receiver.processV1Vote(encrypted);
		assertNotNull(vote);
		assertEquals("votifier.bencodez.com", vote.getServiceName());
		assertEquals("testUser", vote.getUsername());
		assertEquals("127.0.0.1", vote.getAddress());
		assertEquals("TestTimestamp", vote.getTimeStamp());
		vote.setSourceAddress("192.168.1.1"); // Add sourceAddress
		assertEquals("192.168.1.1", vote.getSourceAddress());
	}

	@Test
	public void testV2Vote() throws Exception {
	    // Construct a JSON payload for V2.
	    String challenge = "testChallenge";
	    JsonObject inner = new JsonObject();
	    inner.addProperty("serviceName", "votifier.bencodez.com");
	    inner.addProperty("username", "testUserV2");
	    inner.addProperty("address", "127.0.0.1");
	    inner.addProperty("timestamp", "TestTimestampV2");
	    inner.addProperty("challenge", challenge);
	    String payload = inner.toString();

	    // Compute HMAC signature using dummyTokenKey.
	    Mac mac = Mac.getInstance("HmacSHA256"); // Declare and initialize mac
	    mac.init(dummyTokenKey);
	    byte[] signatureBytes = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
	    String signature = Base64.getEncoder().encodeToString(signatureBytes);

	    JsonObject outer = new JsonObject();
	    outer.addProperty("payload", payload);
	    outer.addProperty("signature", signature);
	    String jsonPayload = outer.toString();

	    // Create a new TestVoteReceiver in token mode.
	    TestVoteReceiver tokenReceiver = new TestVoteReceiver("127.0.0.1", 0, testKeyPair) {
	        @Override
	        public boolean isUseTokens() {
	            return true;
	        }
	    };
	    Vote vote = tokenReceiver.processV2Vote(jsonPayload);
	    assertNotNull(vote);
	    assertEquals("votifier.bencodez.com", vote.getServiceName());
	    assertEquals("testUserV2", vote.getUsername());
	    assertEquals("127.0.0.1", vote.getAddress());
	    assertEquals("TestTimestampV2", vote.getTimeStamp());
	    vote.setSourceAddress("192.168.1.2"); // Add sourceAddress
	    assertEquals("192.168.1.2", vote.getSourceAddress());
	    tokenReceiver.shutdown();
	}

	@Test
	public void testProxyV1Header() throws Exception {
		// Test processing of a PROXY protocol v1 header.
		String proxyHeader = "PROXY TCP4 192.168.1.1 192.168.1.2 1234 80\r\n";
		String remainingData = "VOTE\nvotifier.bencodez.com\ntestUser\n127.0.0.1\nTestTimestamp\n";
		String input = proxyHeader + remainingData;
		PushbackInputStream pis = new PushbackInputStream(
				new ByteArrayInputStream(input.getBytes(StandardCharsets.US_ASCII)), 512);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(baos, StandardCharsets.US_ASCII));

		// Use reflection to call the private processProxyHeaders method.
		Method method = VoteReceiver.class.getDeclaredMethod("processProxyHeaders", PushbackInputStream.class,
				BufferedWriter.class);
		method.setAccessible(true);
		method.invoke(receiver, pis, writer);

		// After processing, the remaining data should be the vote payload.
		byte[] remaining = new byte[remainingData.length()];
		int read = pis.read(remaining);
		String output = new String(remaining, 0, read, StandardCharsets.US_ASCII);
		assertEquals(remainingData, output);
	}

	@Test
	public void testConnectHeader() throws Exception {
		// Test processing of an HTTP CONNECT header.
		String connectHeader = "CONNECT some.host:443 HTTP/1.1\r\nHost: some.host:443\r\n\r\n";
		String remainingData = "VOTE\nvotifier.bencodez.com\ntestUser\n127.0.0.1\nTestTimestamp\n";
		String input = connectHeader + remainingData;
		PushbackInputStream pis = new PushbackInputStream(
				new ByteArrayInputStream(input.getBytes(StandardCharsets.US_ASCII)), 512);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(baos, StandardCharsets.US_ASCII));

		Method method = VoteReceiver.class.getDeclaredMethod("processProxyHeaders", PushbackInputStream.class,
				BufferedWriter.class);
		method.setAccessible(true);
		method.invoke(receiver, pis, writer);
		writer.flush();

		// The writer should contain the HTTP CONNECT response.
		String response = baos.toString("ASCII");
		assertTrue(response.contains("200 Connection Established"));

		// The remaining data in the stream should be the vote payload.
		byte[] remaining = new byte[remainingData.length()];
		int read = pis.read(remaining);
		String output = new String(remaining, 0, read, StandardCharsets.US_ASCII);
		assertEquals(remainingData, output);
	}

	@Test
	public void testV2VoteMissingPayloadField() throws Exception {
		// Test V2 vote with missing "payload" field - should throw exception
		// Note: Payload field validation occurs before signature validation,
		// so we expect the payload error to be thrown first.
		TestVoteReceiver tokenReceiver = new TestVoteReceiver("127.0.0.1", 0, testKeyPair) {
			@Override
			public boolean isUseTokens() {
				return true;
			}
		};

		JsonObject outer = new JsonObject();
		outer.addProperty("signature", "dummySignature");
		// Missing "payload" field
		String jsonPayload = outer.toString();

		Exception exception = null;
		try {
			tokenReceiver.processV2Vote(jsonPayload);
		} catch (Exception e) {
			exception = e;
		}

		assertNotNull(exception, "Expected exception for missing payload field");
		assertTrue(exception.getMessage().contains("Missing required 'payload' field"),
				"Expected error message about missing payload field, got: " + exception.getMessage());
		tokenReceiver.shutdown();
	}

	@Test
	public void testV2VoteMissingSignatureField() throws Exception {
		// Test V2 vote with missing "signature" field - should throw exception
		TestVoteReceiver tokenReceiver = new TestVoteReceiver("127.0.0.1", 0, testKeyPair) {
			@Override
			public boolean isUseTokens() {
				return true;
			}
		};

		JsonObject outer = new JsonObject();
		outer.addProperty("payload", "{}");
		// Missing "signature" field
		String jsonPayload = outer.toString();

		Exception exception = null;
		try {
			tokenReceiver.processV2Vote(jsonPayload);
		} catch (Exception e) {
			exception = e;
		}

		assertNotNull(exception, "Expected exception for missing signature field");
		assertTrue(exception.getMessage().contains("Missing required 'signature' field"),
				"Expected error message about missing signature field, got: " + exception.getMessage());
		tokenReceiver.shutdown();
	}

	@Test
	public void testV2VoteMissingUsernameField() throws Exception {
		// Test V2 vote with missing "username" field in inner payload
		TestVoteReceiver tokenReceiver = new TestVoteReceiver("127.0.0.1", 0, testKeyPair) {
			@Override
			public boolean isUseTokens() {
				return true;
			}
		};

		String challenge = "testChallenge";
		JsonObject inner = new JsonObject();
		inner.addProperty("serviceName", "votifier.bencodez.com");
		// Missing "username" field
		inner.addProperty("address", "127.0.0.1");
		inner.addProperty("timestamp", "TestTimestamp");
		inner.addProperty("challenge", challenge);
		String payload = inner.toString();

		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(dummyTokenKey);
		byte[] signatureBytes = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
		String signature = Base64.getEncoder().encodeToString(signatureBytes);

		JsonObject outer = new JsonObject();
		outer.addProperty("payload", payload);
		outer.addProperty("signature", signature);
		String jsonPayload = outer.toString();

		Exception exception = null;
		try {
			tokenReceiver.processV2Vote(jsonPayload);
		} catch (Exception e) {
			exception = e;
		}

		assertNotNull(exception, "Expected exception for missing username field");
		assertTrue(exception.getMessage().contains("Missing required 'username' field"),
				"Expected error message about missing username field, got: " + exception.getMessage());
		tokenReceiver.shutdown();
	}

	@Test
	public void testV2VoteInvalidChallenge() throws Exception {
		// Test V2 vote with incorrect challenge value
		TestVoteReceiver tokenReceiver = new TestVoteReceiver("127.0.0.1", 0, testKeyPair) {
			@Override
			public boolean isUseTokens() {
				return true;
			}
		};

		JsonObject inner = new JsonObject();
		inner.addProperty("serviceName", "votifier.bencodez.com");
		inner.addProperty("username", "testUser");
		inner.addProperty("address", "127.0.0.1");
		inner.addProperty("timestamp", "TestTimestamp");
		inner.addProperty("challenge", "wrongChallenge"); // Wrong challenge
		String payload = inner.toString();

		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(dummyTokenKey);
		byte[] signatureBytes = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
		String signature = Base64.getEncoder().encodeToString(signatureBytes);

		JsonObject outer = new JsonObject();
		outer.addProperty("payload", payload);
		outer.addProperty("signature", signature);
		String jsonPayload = outer.toString();

		Exception exception = null;
		try {
			tokenReceiver.processV2Vote(jsonPayload);
		} catch (Exception e) {
			exception = e;
		}

		assertNotNull(exception, "Expected exception for invalid challenge");
		assertTrue(exception.getMessage().contains("Invalid challenge"),
				"Expected error message about invalid challenge, got: " + exception.getMessage());
		tokenReceiver.shutdown();
	}

	@Test
	public void testV2VoteInvalidBase64Signature() throws Exception {
		// Test V2 vote with invalid base64 signature
		TestVoteReceiver tokenReceiver = new TestVoteReceiver("127.0.0.1", 0, testKeyPair) {
			@Override
			public boolean isUseTokens() {
				return true;
			}
		};

		JsonObject inner = new JsonObject();
		inner.addProperty("serviceName", "votifier.bencodez.com");
		inner.addProperty("username", "testUser");
		inner.addProperty("address", "127.0.0.1");
		inner.addProperty("timestamp", "TestTimestamp");
		inner.addProperty("challenge", "testChallenge");
		String payload = inner.toString();

		JsonObject outer = new JsonObject();
		outer.addProperty("payload", payload);
		outer.addProperty("signature", "not-valid-base64!!!"); // Invalid base64
		String jsonPayload = outer.toString();

		Exception exception = null;
		try {
			tokenReceiver.processV2Vote(jsonPayload);
		} catch (Exception e) {
			exception = e;
		}

		assertNotNull(exception, "Expected exception for invalid base64 signature");
		assertTrue(exception.getMessage().contains("Signature is not valid Base64"),
				"Expected error message about invalid base64, got: " + exception.getMessage());
		tokenReceiver.shutdown();
	}
}
