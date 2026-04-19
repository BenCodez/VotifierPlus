package com.bencodez.votifierplus.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

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
import com.vexsoftware.votifier.net.ThrottleConfig;
import com.vexsoftware.votifier.net.VoteConnectionHandler;
import com.vexsoftware.votifier.net.VoteReceiver;
import com.vexsoftware.votifier.net.VoteThrottleService;

/**
 * Socket-level tests for VoteConnectionHandler.
 */
public class VoteConnectionHandlerTest {

	private static KeyPair testKeyPair;
	private static KeyPair otherKeyPair;
	private static Key dummyTokenKey;
	private static Key wrongDummyTokenKey;

	private TestVoteReceiver receiver;
	private ExecutorService executor;

	@BeforeAll
	public static void setupClass() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		testKeyPair = kpg.generateKeyPair();
		otherKeyPair = kpg.generateKeyPair();

		dummyTokenKey = new SecretKeySpec("dummySecretKey1234".getBytes(StandardCharsets.UTF_8), "HmacSHA256");
		wrongDummyTokenKey = new SecretKeySpec("wrongDummySecret12".getBytes(StandardCharsets.UTF_8), "HmacSHA256");
	}

	@BeforeEach
	public void setup() throws Exception {
		receiver = new TestVoteReceiver("127.0.0.1", 0);
		executor = Executors.newCachedThreadPool();
	}

	@AfterEach
	public void tearDown() {
		if (executor != null) {
			executor.shutdownNow();
		}
		if (receiver != null) {
			receiver.shutdown();
		}
	}

	private static class TestVoteReceiver extends VoteReceiver {

		private final String testChallenge = "testChallenge";
		private volatile boolean useTokens = false;

		public TestVoteReceiver(String host, int port) throws Exception {
			super(host, port);
		}

		public void setUseTokens(boolean useTokens) {
			this.useTokens = useTokens;
		}

		@Override
		public boolean isUseTokens() {
			return useTokens;
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
	public void testHandleV1ConnectionReturnsVoteAndSendsOk() throws Exception {
		receiver.setUseTokens(false);
		VoteThrottleService throttleService = new VoteThrottleService(null);
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, throttleService);

		try (ServerSocket serverSocket = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", serverSocket.getLocalPort());
				Socket accepted = serverSocket.accept()) {

			Future<Vote> future = executor.submit(new Callable<Vote>() {
				@Override
				public Vote call() {
					return handler.handle(accepted);
				}
			});

			BufferedReader clientReader = new BufferedReader(
					new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
			OutputStream clientOut = client.getOutputStream();

			String handshake = clientReader.readLine();
			assertEquals("VOTIFIER 1", handshake);

			String voteMsg = "VOTE\nvotifier.bencodez.com\ntestUser\n127.0.0.1\nNormalTimestamp\n";
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, testKeyPair.getPublic());
			byte[] encrypted = cipher.doFinal(voteMsg.getBytes(StandardCharsets.UTF_8));
			clientOut.write(encrypted);
			clientOut.flush();

			String okResponse = clientReader.readLine();
			assertTrue(okResponse.contains("\"status\":\"ok\""));

			Vote vote = future.get();
			assertNotNull(vote);
			assertEquals("votifier.bencodez.com", vote.getServiceName());
			assertEquals("testUser", vote.getUsername());
			assertEquals("127.0.0.1", vote.getAddress());
			assertEquals("NormalTimestamp", vote.getTimeStamp());
			assertEquals("127.0.0.1", vote.getSourceAddress());
		}
	}

	@Test
	public void testHandleV2ConnectionReturnsVoteAndSendsOk() throws Exception {
		receiver.setUseTokens(true);
		VoteThrottleService throttleService = new VoteThrottleService(null);
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, throttleService);

		try (ServerSocket serverSocket = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", serverSocket.getLocalPort());
				Socket accepted = serverSocket.accept()) {

			Future<Vote> future = executor.submit(new Callable<Vote>() {
				@Override
				public Vote call() {
					return handler.handle(accepted);
				}
			});

			BufferedReader clientReader = new BufferedReader(
					new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
			OutputStream clientOut = client.getOutputStream();

			String handshake = clientReader.readLine();
			assertEquals("VOTIFIER 2 testChallenge", handshake);

			JsonObject inner = new JsonObject();
			inner.addProperty("serviceName", "votifier.bencodez.com");
			inner.addProperty("username", "testUserV2");
			inner.addProperty("address", "127.0.0.1");
			inner.addProperty("timestamp", "NormalTimestampV2");
			inner.addProperty("challenge", "testChallenge");
			String payload = inner.toString();

			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(dummyTokenKey);
			String signature = Base64.getEncoder()
					.encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));

			JsonObject outer = new JsonObject();
			outer.addProperty("payload", payload);
			outer.addProperty("signature", signature);

			clientOut.write((outer.toString() + "\r\n").getBytes(StandardCharsets.UTF_8));
			clientOut.flush();

			String okResponse = clientReader.readLine();
			assertTrue(okResponse.contains("\"status\":\"ok\""));

			Vote vote = future.get();
			assertNotNull(vote);
			assertEquals("votifier.bencodez.com", vote.getServiceName());
			assertEquals("testUserV2", vote.getUsername());
			assertEquals("127.0.0.1", vote.getAddress());
			assertEquals("NormalTimestampV2", vote.getTimeStamp());
			assertEquals("127.0.0.1", vote.getSourceAddress());
		}
	}

	@Test
	public void testHandleBlockedConnectionReturnsNull() throws Exception {
		receiver.setUseTokens(false);
		ThrottleConfig config = new ThrottleConfig(true, Collections.<String>emptySet(), "10s", 1, "30s", 1, "30s",
				false, 999, "1s", "60s");
		VoteThrottleService throttleService = new VoteThrottleService(config);
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, throttleService);

		throttleService.fail("tunnel:127.0.0.1", false, false);
		assertTrue(throttleService.isBlocked("tunnel:127.0.0.1"));

		try (ServerSocket serverSocket = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", serverSocket.getLocalPort());
				Socket accepted = serverSocket.accept()) {

			Future<Vote> future = executor.submit(new Callable<Vote>() {
				@Override
				public Vote call() {
					return handler.handle(accepted);
				}
			});

			BufferedReader clientReader = new BufferedReader(
					new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));

			String handshake = clientReader.readLine();
			assertEquals("VOTIFIER 1", handshake);

			Vote vote = future.get();
			assertNull(vote);
		}
	}

	@Test
	public void testHandlePresentV1PayloadSkipsHandshake() throws Exception {
		receiver.setUseTokens(false);
		VoteThrottleService throttleService = new VoteThrottleService(null);
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, throttleService);

		try (ServerSocket serverSocket = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", serverSocket.getLocalPort());
				Socket accepted = serverSocket.accept()) {

			String voteMsg = "VOTE\nvotifier.bencodez.com\ntestUser\n127.0.0.1\nNormalTimestamp\n";
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, testKeyPair.getPublic());
			byte[] encrypted = cipher.doFinal(voteMsg.getBytes(StandardCharsets.UTF_8));
			client.getOutputStream().write(encrypted);
			client.getOutputStream().flush();

			Future<Vote> future = executor.submit(new Callable<Vote>() {
				@Override
				public Vote call() {
					return handler.handle(accepted);
				}
			});

			Vote vote = future.get();
			assertNotNull(vote);
			assertEquals("votifier.bencodez.com", vote.getServiceName());
			assertEquals("testUser", vote.getUsername());
		}
	}

	@Test
	public void testHandleV2InvalidSignatureReturnsNull() throws Exception {
		receiver.setUseTokens(true);
		VoteThrottleService throttleService = new VoteThrottleService(null);
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, throttleService);

		try (ServerSocket serverSocket = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", serverSocket.getLocalPort());
				Socket accepted = serverSocket.accept()) {

			Future<Vote> future = executor.submit(new Callable<Vote>() {
				@Override
				public Vote call() {
					return handler.handle(accepted);
				}
			});

			BufferedReader clientReader = new BufferedReader(
					new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
			OutputStream clientOut = client.getOutputStream();

			String handshake = clientReader.readLine();
			assertEquals("VOTIFIER 2 testChallenge", handshake);

			JsonObject inner = new JsonObject();
			inner.addProperty("serviceName", "votifier.bencodez.com");
			inner.addProperty("username", "testUserV2");
			inner.addProperty("address", "127.0.0.1");
			inner.addProperty("timestamp", "NormalTimestampV2");
			inner.addProperty("challenge", "testChallenge");
			String payload = inner.toString();

			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(wrongDummyTokenKey);
			String signature = Base64.getEncoder()
					.encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));

			JsonObject outer = new JsonObject();
			outer.addProperty("payload", payload);
			outer.addProperty("signature", signature);

			clientOut.write((outer.toString() + "\r\n").getBytes(StandardCharsets.UTF_8));
			clientOut.flush();
			client.shutdownOutput();

			Vote vote = future.get();
			assertNull(vote);
		}
	}

	@Test
	public void testHandleV1BadPaddingReturnsNull() throws Exception {
		receiver.setUseTokens(false);
		VoteThrottleService throttleService = new VoteThrottleService(null);
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, throttleService);

		try (ServerSocket serverSocket = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", serverSocket.getLocalPort());
				Socket accepted = serverSocket.accept()) {

			Future<Vote> future = executor.submit(new Callable<Vote>() {
				@Override
				public Vote call() {
					return handler.handle(accepted);
				}
			});

			BufferedReader clientReader = new BufferedReader(
					new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
			OutputStream clientOut = client.getOutputStream();

			String handshake = clientReader.readLine();
			assertEquals("VOTIFIER 1", handshake);

			String voteMsg = "VOTE\nvotifier.bencodez.com\ntestUser\n127.0.0.1\nNormalTimestamp\n";
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, otherKeyPair.getPublic());
			byte[] encrypted = cipher.doFinal(voteMsg.getBytes(StandardCharsets.UTF_8));
			clientOut.write(encrypted);
			clientOut.flush();
			client.shutdownOutput();

			Vote vote = future.get();
			assertNull(vote);
		}
	}

	@Test
	public void testHandleProxyV1UsesRealIpAsSourceAddress() throws Exception {
		receiver.setUseTokens(false);
		VoteThrottleService throttleService = new VoteThrottleService(null);
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, throttleService);

		try (ServerSocket serverSocket = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", serverSocket.getLocalPort());
				Socket accepted = serverSocket.accept()) {

			Future<Vote> future = executor.submit(new Callable<Vote>() {
				@Override
				public Vote call() {
					return handler.handle(accepted);
				}
			});

			BufferedReader clientReader = new BufferedReader(
					new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
			OutputStream clientOut = client.getOutputStream();

			String handshake = clientReader.readLine();
			assertEquals("VOTIFIER 1", handshake);

			String proxyHeader = "PROXY TCP4 203.0.113.10 127.0.0.1 1234 8192\r\n";
			clientOut.write(proxyHeader.getBytes(StandardCharsets.US_ASCII));

			String voteMsg = "VOTE\nvotifier.bencodez.com\ntestUser\n127.0.0.1\nNormalTimestamp\n";
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, testKeyPair.getPublic());
			byte[] encrypted = cipher.doFinal(voteMsg.getBytes(StandardCharsets.UTF_8));
			clientOut.write(encrypted);
			clientOut.flush();

			Vote vote = future.get();
			assertNotNull(vote);
			assertEquals("203.0.113.10", vote.getSourceAddress());

			String okResponse = clientReader.readLine();
			assertNotNull(okResponse);
			assertTrue(okResponse.contains("\"status\":\"ok\""));
		}
	}

	@Test
	public void testHandleTestVoteDoesNotSendOkResponse() throws Exception {
		receiver.setUseTokens(false);
		VoteThrottleService throttleService = new VoteThrottleService(null);
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, throttleService);

		try (ServerSocket serverSocket = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", serverSocket.getLocalPort());
				Socket accepted = serverSocket.accept()) {

			Future<Vote> future = executor.submit(new Callable<Vote>() {
				@Override
				public Vote call() {
					return handler.handle(accepted);
				}
			});

			BufferedReader clientReader = new BufferedReader(
					new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
			OutputStream clientOut = client.getOutputStream();

			String handshake = clientReader.readLine();
			assertEquals("VOTIFIER 1", handshake);

			String voteMsg = "VOTE\nvotifier.bencodez.com\ntestUser\n127.0.0.1\nTestVote\n";
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, testKeyPair.getPublic());
			byte[] encrypted = cipher.doFinal(voteMsg.getBytes(StandardCharsets.UTF_8));
			clientOut.write(encrypted);
			clientOut.flush();
			client.shutdownOutput();

			Vote vote = future.get();
			assertNotNull(vote);
			assertEquals("TestVote", vote.getTimeStamp());

			assertTrue(!clientReader.ready(), "Did not expect an OK response for TestVote");
		}
	}
}