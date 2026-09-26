package com.bencodez.votifierplus.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
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
		private Set<String> trustedProxyIps = Collections.emptySet();

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
		public Set<String> getTrustedProxyIps() {
			return trustedProxyIps;
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
	public void testProxyCanProvideClientIdentityBeforeThrottleDecision() throws Exception {
		receiver.setUseTokens(false);
		ThrottleConfig config = new ThrottleConfig(true, Collections.<String>emptySet(), "10s", 1, "30s", 1,
				"30s", false, 999, "1s", "60s");
		VoteThrottleService throttleService = new VoteThrottleService(config);
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, throttleService);
		throttleService.fail("tunnel:127.0.0.1", true, false);

		try (ServerSocket serverSocket = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", serverSocket.getLocalPort());
				Socket accepted = serverSocket.accept()) {
			Future<Vote> future = executor.submit(() -> handler.handle(accepted));
			BufferedReader reader = new BufferedReader(
					new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
			assertEquals("VOTIFIER 1", reader.readLine(), "Shared tunnels must reach proxy-header detection");
			client.close();
			assertNull(future.get());
		}
	}

	@Test
	public void testAggregateBlockRejectsBeforeHandshakeAndPayloadWait() throws Exception {
		receiver.setUseTokens(false);
		ThrottleConfig config = new ThrottleConfig(true, Collections.singleton("127.0.0.1"), "5s", 1, "10s", 1,
				"10s", false, 999, "1s", "60s");
		VoteThrottleService throttleService = new VoteThrottleService(config);
		for (int i = 0; i < 4096; i++) {
			throttleService.fail("ip:filler:" + i, false, true);
		}
		throttleService.fail("ip:blocked", "tunnel:127.0.0.1", false, true);
		assertTrue(throttleService.isAggregateBlocked("tunnel:127.0.0.1"));

		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, throttleService);
		try (ServerSocket serverSocket = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", serverSocket.getLocalPort());
				Socket accepted = serverSocket.accept()) {
			client.setSoTimeout(500);
			Future<Vote> future = executor.submit(() -> handler.handle(accepted));
			BufferedReader clientReader = new BufferedReader(
					new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));

			try {
				assertNull(clientReader.readLine(), "an aggregate-blocked remote must not receive a handshake");
			} catch (SocketTimeoutException ex) {
				throw new AssertionError("aggregate rejection must happen before waiting for payload", ex);
			}
			assertNull(future.get(1, java.util.concurrent.TimeUnit.SECONDS));
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
		receiver.trustedProxyIps = Collections.singleton("127.0.0.1");
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
	public void testNonTunnelProxyOverflowUsesRemoteAggregate() throws Exception {
		receiver.setUseTokens(false);
		receiver.trustedProxyIps = Collections.singleton("127.0.0.1");
		ThrottleConfig config = new ThrottleConfig(true, Collections.<String>emptySet(), "5s", 1, "10s", 1,
				"10s", false, 999, "1s", "60s");
		VoteThrottleService throttleService = new VoteThrottleService(config);
		for (int i = 0; i < 4096; i++) {
			throttleService.fail("ip:" + i, false, true);
		}
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
			assertEquals("VOTIFIER 1", clientReader.readLine());

			clientOut.write("PROXY TCP4 203.0.113.10 127.0.0.1 1234 8192\r\n"
					.getBytes(StandardCharsets.US_ASCII));
			clientOut.write(new byte[256]);
			clientOut.flush();
			client.shutdownOutput();

			assertNull(future.get());
			assertTrue(throttleService.isBlocked("ip:203.0.113.10", "tunnel:127.0.0.1"));
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

	@Test
	public void testProxyHeadersRequireTrustedSocketPeer() throws Exception {
		byte[] v1 = "PROXY TCP4 203.0.113.10 127.0.0.1 1234 8192\r\n"
				.getBytes(StandardCharsets.US_ASCII);
		byte[] v2 = proxyV2(4, "203.0.113.10", "127.0.0.1", 1234, 8192);
		assertNull(sendV1Vote(v1));
		assertNull(sendV1Vote(v2));
		receiver.trustedProxyIps = Collections.singleton("127.0.0.1");
		assertEquals("203.0.113.10", sendV1Vote(v1).getSourceAddress());
		assertEquals("203.0.113.10", sendV1Vote(v2).getSourceAddress());
	}

	@Test
	public void testTrustedProxyIpv6AndConnectAttribution() throws Exception {
		receiver.trustedProxyIps = Collections.singleton("127.0.0.1");
		assertEquals("2001:db8:0:0:0:0:0:10", sendV1Vote(
				"PROXY TCP6 2001:db8::10 2001:db8::20 1234 8192\r\n".getBytes(StandardCharsets.US_ASCII))
				.getSourceAddress());
		assertEquals("2001:db8:0:0:0:0:0:10", sendV1Vote(
				proxyV2(6, "2001:db8::10", "2001:db8::20", 1234, 8192)).getSourceAddress());
		receiver.trustedProxyIps = Collections.emptySet();
		assertEquals("127.0.0.1", sendV1Vote(
				"CONNECT vote.example:443 HTTP/1.1\r\nHost: vote.example:443\r\n\r\n"
						.getBytes(StandardCharsets.US_ASCII)).getSourceAddress());
	}

	@Test
	public void testTrustedProxyHeadersWithoutSourceKeepSocketAttribution() throws Exception {
		receiver.trustedProxyIps = Collections.singleton("127.0.0.1");
		assertEquals("127.0.0.1", sendV1Vote("PROXY UNKNOWN\r\n".getBytes(StandardCharsets.US_ASCII))
				.getSourceAddress());
		byte[] local = proxyV2(4, "203.0.113.10", "127.0.0.1", 1234, 8192);
		local[12] = 0x20;
		assertEquals("127.0.0.1", sendV1Vote(local).getSourceAddress());
		byte[] withTlv = proxyV2(4, "203.0.113.10", "127.0.0.1", 1234, 8192);
		withTlv[15] += 4;
		ByteArrayOutputStream packet = new ByteArrayOutputStream();
		packet.write(withTlv);
		packet.write(new byte[] { 0x01, 0, 0x01, 0x01 });
		assertEquals("203.0.113.10", sendV1Vote(packet.toByteArray()).getSourceAddress());
	}

	@Test
	public void testMalformedProxyAddressesFamiliesAndPortsAreRejected() throws Exception {
		receiver.trustedProxyIps = Collections.singleton("127.0.0.1");
		String[] invalid = {
				"PROXY TCP4 example.com 127.0.0.1 1234 8192\r\n",
				"PROXY TCP4 256.0.0.1 127.0.0.1 1234 8192\r\n",
				"PROXY TCP4 ::1 127.0.0.1 1234 8192\r\n",
				"PROXY TCP6 203.0.113.10 ::1 1234 8192\r\n",
				"PROXY TCP4 203.0.113.10 ::1 1234 8192\r\n",
				"PROXY TCP4 203.0.113.10 127.0.0.1 -1 8192\r\n",
				"PROXY TCP4 203.0.113.10 127.0.0.1 65536 8192\r\n",
				"PROXY TCP4 203.0.113.10 127.0.0.1 1234 99999\r\n",
				"PROXY TCP4 203.0.113.10 127.0.0.1 1234 8192\n",
				"PROXY UDP4 203.0.113.10 127.0.0.1 1234 8192\r\n" };
		for (String header : invalid) {
			assertNull(sendV1Vote(header.getBytes(StandardCharsets.US_ASCII)), header);
		}
		byte[] wrongVersion = proxyV2(4, "203.0.113.10", "127.0.0.1", 1234, 8192);
		wrongVersion[12] = 0x11;
		assertNull(sendV1Vote(wrongVersion));
		byte[] wrongFamily = proxyV2(4, "203.0.113.10", "127.0.0.1", 1234, 8192);
		wrongFamily[13] = 0x21;
		assertNull(sendV1Vote(wrongFamily));
		byte[] datagram = proxyV2(4, "203.0.113.10", "127.0.0.1", 1234, 8192);
		datagram[13] = 0x12;
		assertNull(sendV1Vote(datagram));
	}

	private Vote sendV1Vote(byte[] prefix) throws Exception {
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, new VoteThrottleService(null));
		try (ServerSocket server = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", server.getLocalPort());
				Socket accepted = server.accept()) {
			Future<Vote> future = executor.submit(() -> handler.handle(accepted));
			BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream(), StandardCharsets.US_ASCII));
			assertEquals("VOTIFIER 1", reader.readLine());
			String message = "VOTE\nsite\nuser\n127.0.0.1\nNormalTimestamp\n";
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, testKeyPair.getPublic());
			OutputStream out = client.getOutputStream();
			ByteArrayOutputStream request = new ByteArrayOutputStream();
			request.write(prefix);
			request.write(cipher.doFinal(message.getBytes(StandardCharsets.US_ASCII)));
			try {
				out.write(request.toByteArray());
				out.flush();
				client.shutdownOutput();
			} catch (SocketException ignored) {
				// Rejected headers may close the connection while the client is writing.
			}
			return future.get(5, TimeUnit.SECONDS);
		}
	}

	private byte[] proxyV2(int family, String source, String destination, int sourcePort, int destinationPort)
			throws Exception {
		byte[] sourceBytes = InetAddress.getByName(source).getAddress();
		byte[] destinationBytes = InetAddress.getByName(destination).getAddress();
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(new byte[] { 0x0D, 0x0A, 0x0D, 0x0A, 0, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A });
		out.write(0x21);
		out.write(family == 4 ? 0x11 : 0x21);
		int length = sourceBytes.length + destinationBytes.length + 4;
		out.write(length >>> 8);
		out.write(length);
		out.write(sourceBytes);
		out.write(destinationBytes);
		out.write(sourcePort >>> 8);
		out.write(sourcePort);
		out.write(destinationPort >>> 8);
		out.write(destinationPort);
		return out.toByteArray();
	}
}
