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
import java.net.SocketException;
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
import java.util.concurrent.CountDownLatch;
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
import com.vexsoftware.votifier.net.VoteProtocolPolicy;
import com.vexsoftware.votifier.net.VoteReceiver;
import com.vexsoftware.votifier.net.VoteThrottleService;

/**
 * Regression tests for the optional V1 security boundary and bounded listener
 * queue.
 */
public class VoteProtocolSecurityTest {

	private static KeyPair testKeyPair;
	private static Key tokenKey;

	private TestVoteReceiver receiver;
	private ExecutorService executor;

	@BeforeAll
	public static void setupClass() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		testKeyPair = keyPairGenerator.generateKeyPair();
		tokenKey = new SecretKeySpec("securityTestToken123".getBytes(StandardCharsets.UTF_8), "HmacSHA256");
	}

	@BeforeEach
	public void setup() throws Exception {
		VoteProtocolPolicy.setDisableV1(false);
		receiver = new TestVoteReceiver("127.0.0.1", 0);
		executor = Executors.newCachedThreadPool();
	}

	@AfterEach
	public void tearDown() {
		VoteProtocolPolicy.setDisableV1(false);
		if (executor != null) {
			executor.shutdownNow();
		}
		if (receiver != null) {
			receiver.shutdown();
		}
	}

	@Test
	public void testTokenCompatibilityModeStillAcceptsPresentV1Packet() throws Exception {
		receiver.setUseTokens(true);
		VoteProtocolPolicy.setDisableV1(false);
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, new VoteThrottleService(null));

		try (ServerSocket serverSocket = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", serverSocket.getLocalPort());
				Socket accepted = serverSocket.accept()) {
			client.getOutputStream().write(createV1Packet("compatibilityUsr"));
			client.getOutputStream().flush();

			Future<Vote> future = executor.submit(() -> handler.handle(accepted));
			Vote vote = future.get(2, TimeUnit.SECONDS);

			assertNotNull(vote);
			assertEquals("compatibilityUsr", vote.getUsername());
		}
	}

	@Test
	public void testFragmentedV1PacketIsReadCompletely() throws Exception {
		receiver.setUseTokens(false);
		VoteProtocolPolicy.setDisableV1(false);
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, new VoteThrottleService(null));

		try (ServerSocket serverSocket = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", serverSocket.getLocalPort());
				Socket accepted = serverSocket.accept()) {
			Future<Vote> future = executor.submit(() -> handler.handle(accepted));
			BufferedReader reader = new BufferedReader(
					new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
			OutputStream output = client.getOutputStream();

			assertEquals("VOTIFIER 1", reader.readLine());
			byte[] packet = createV1Packet("fragmentedUser");
			output.write(packet, 0, 32);
			output.flush();
			Thread.sleep(50);
			output.write(packet, 32, packet.length - 32);
			output.flush();

			assertTrue(reader.readLine().contains("\"status\":\"ok\""));
			Vote vote = future.get(2, TimeUnit.SECONDS);
			assertNotNull(vote);
			assertEquals("fragmentedUser", vote.getUsername());
		}
	}

	@Test
	public void testDisableV1RejectsDelayedV1PacketInTokenMode() throws Exception {
		receiver.setUseTokens(true);
		VoteProtocolPolicy.setDisableV1(true);
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, new VoteThrottleService(null));

		try (ServerSocket serverSocket = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", serverSocket.getLocalPort());
				Socket accepted = serverSocket.accept()) {
			Future<Vote> future = executor.submit(() -> handler.handle(accepted));
			BufferedReader reader = new BufferedReader(
					new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));

			assertEquals("VOTIFIER 2 testChallenge", reader.readLine());
			client.getOutputStream().write(createV1Packet("rejectedDelayedUser"));
			client.getOutputStream().flush();

			assertNull(future.get(2, TimeUnit.SECONDS));
			assertTrue(receiver.getWarnings().stream()
					.anyMatch(message -> message.contains("Votifier V1 votes are disabled by configuration")));
		}
	}

	@Test
	public void testDisableV1RejectsPresentV1PacketAndStillSendsV2Handshake() throws Exception {
		receiver.setUseTokens(true);
		VoteProtocolPolicy.setDisableV1(true);
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, new VoteThrottleService(null));

		try (ServerSocket serverSocket = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", serverSocket.getLocalPort());
				Socket accepted = serverSocket.accept()) {
			client.getOutputStream().write(createV1Packet("rejectedPresentUser"));
			client.getOutputStream().flush();

			Future<Vote> future = executor.submit(() -> handler.handle(accepted));
			BufferedReader reader = new BufferedReader(
					new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));

			assertEquals("VOTIFIER 2 testChallenge", reader.readLine());
			assertNull(future.get(2, TimeUnit.SECONDS));
		}
	}

	@Test
	public void testDisableV1ForcesV2HandshakeAndAcceptsValidV2() throws Exception {
		receiver.setUseTokens(false);
		VoteProtocolPolicy.setDisableV1(true);
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, new VoteThrottleService(null));

		try (ServerSocket serverSocket = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", serverSocket.getLocalPort());
				Socket accepted = serverSocket.accept()) {
			Future<Vote> future = executor.submit(() -> handler.handle(accepted));
			BufferedReader reader = new BufferedReader(
					new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
			OutputStream output = client.getOutputStream();

			assertEquals("VOTIFIER 2 testChallenge", reader.readLine());
			output.write(createV2Packet("secureV2User"));
			output.flush();

			assertTrue(reader.readLine().contains("\"status\":\"ok\""));
			Vote vote = future.get(2, TimeUnit.SECONDS);
			assertNotNull(vote);
			assertEquals("secureV2User", vote.getUsername());
		}
	}

	@Test
	public void testFullConnectionQueueRejectsAndClosesNewSocket() throws Exception {
		receiver.shutdown();
		SaturatedVoteReceiver saturated = new SaturatedVoteReceiver("127.0.0.1", 0);
		receiver = saturated;
		receiver.start();

		try (Socket active = new Socket("127.0.0.1", receiver.getServer().getLocalPort())) {
			BufferedReader activeReader = new BufferedReader(
					new InputStreamReader(active.getInputStream(), StandardCharsets.UTF_8));
			assertEquals("VOTIFIER 1", activeReader.readLine());

			try (Socket queued = new Socket("127.0.0.1", receiver.getServer().getLocalPort());
					Socket rejected = new Socket("127.0.0.1", receiver.getServer().getLocalPort())) {
				assertTrue(saturated.awaitRejection());
				rejected.setSoTimeout(1000);
				try {
					assertEquals(-1, rejected.getInputStream().read());
				} catch (SocketException expectedReset) {
					assertTrue(expectedReset.getMessage() != null || rejected.isClosed() || rejected.isConnected());
				}
			}
		}
	}

	private byte[] createV1Packet(String username) throws Exception {
		String voteMessage = "VOTE\nvotifier.bencodez.com\n" + username + "\n127.0.0.1\nNormalTimestamp\n";
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, testKeyPair.getPublic());
		return cipher.doFinal(voteMessage.getBytes(StandardCharsets.UTF_8));
	}

	private byte[] createV2Packet(String username) throws Exception {
		JsonObject inner = new JsonObject();
		inner.addProperty("serviceName", "votifier.bencodez.com");
		inner.addProperty("username", username);
		inner.addProperty("address", "127.0.0.1");
		inner.addProperty("timestamp", "NormalTimestampV2");
		inner.addProperty("challenge", "testChallenge");
		String payload = inner.toString();

		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(tokenKey);
		String signature = Base64.getEncoder()
				.encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));

		JsonObject outer = new JsonObject();
		outer.addProperty("payload", payload);
		outer.addProperty("signature", signature);
		return (outer.toString() + "\r\n").getBytes(StandardCharsets.UTF_8);
	}

	private static class TestVoteReceiver extends VoteReceiver {

		private final List<String> warnings = new CopyOnWriteArrayList<>();
		private volatile boolean useTokens;

		TestVoteReceiver(String host, int port) throws Exception {
			super(host, port);
		}

		void setUseTokens(boolean useTokens) {
			this.useTokens = useTokens;
		}

		List<String> getWarnings() {
			return warnings;
		}

		@Override
		public boolean isUseTokens() {
			return useTokens;
		}

		@Override
		public void logWarning(String warning) {
			if (warnings != null) {
				warnings.add(warning);
			}
		}

		@Override
		public void logSevere(String message) {
		}

		@Override
		public void log(String message) {
		}

		@Override
		public void debug(String message) {
		}

		@Override
		public void debug(Exception exception) {
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
			return Collections.singletonMap("votifier.bencodez.com", tokenKey);
		}

		@Override
		public ForwardServer getServerData(String server) {
			return null;
		}

		@Override
		public void callEvent(Vote vote) {
		}

		@Override
		public String getChallenge() {
			return "testChallenge";
		}

		@Override
		public ThrottleConfig getThrottleConfig() {
			return null;
		}
	}

	private static class SaturatedVoteReceiver extends TestVoteReceiver {

		private final CountDownLatch rejection = new CountDownLatch(1);

		SaturatedVoteReceiver(String host, int port) throws Exception {
			super(host, port);
		}

		@Override
		public int getConnectionWorkerCount() {
			return 1;
		}

		@Override
		public int getConnectionQueueCapacity() {
			return 1;
		}

		@Override
		public long getConnectionQueueTimeoutMillis() {
			return 10000L;
		}

		@Override
		public void debug(String message) {
			if (rejection != null && message.startsWith("Rejected vote connection")) {
				rejection.countDown();
			}
		}

		boolean awaitRejection() throws InterruptedException {
			return rejection.await(2, TimeUnit.SECONDS);
		}
	}
}
