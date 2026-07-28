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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.model.Vote;
import com.vexsoftware.votifier.net.ThrottleConfig;
import com.vexsoftware.votifier.net.VoteConnectionHandler;
import com.vexsoftware.votifier.net.VoteReceiver;
import com.vexsoftware.votifier.net.VoteThrottleService;

/**
 * Regression tests for empty and delayed companion connections.
 */
public class EmptyConnectionHandlingTest {

	private static KeyPair testKeyPair;

	private CapturingVoteReceiver receiver;
	private ExecutorService executor;

	@BeforeAll
	public static void setupClass() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		testKeyPair = keyPairGenerator.generateKeyPair();
	}

	@BeforeEach
	public void setup() throws Exception {
		receiver = new CapturingVoteReceiver("127.0.0.1", 0);
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

	@Test
	public void testCleanCloseWithoutPayloadIsDebugOnly() throws Exception {
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, new VoteThrottleService(null));

		try (ServerSocket serverSocket = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", serverSocket.getLocalPort());
				Socket accepted = serverSocket.accept()) {
			Future<Vote> future = executor.submit(() -> handler.handle(accepted));
			BufferedReader reader = new BufferedReader(
					new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));

			assertEquals("VOTIFIER 1", reader.readLine());
			client.shutdownOutput();

			assertNull(future.get(1, TimeUnit.SECONDS));
			assertTrue(receiver.getWarnings().isEmpty());
			assertTrue(receiver.getDebugMessages().stream()
					.anyMatch(message -> message.contains("Connection closed without payload")));
		}
	}

	@Test
	public void testSilentOpenConnectionStillWarnsAfterTimeout() throws Exception {
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, new VoteThrottleService(null));

		try (ServerSocket serverSocket = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", serverSocket.getLocalPort());
				Socket accepted = serverSocket.accept()) {
			Future<Vote> future = executor.submit(() -> handler.handle(accepted));
			BufferedReader reader = new BufferedReader(
					new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));

			assertEquals("VOTIFIER 1", reader.readLine());
			assertNull(future.get(4, TimeUnit.SECONDS));
			assertTrue(receiver.getWarnings().stream()
					.anyMatch(message -> message.contains("Connection timeout while waiting for vote payload")));
		}
	}

	@Test
	public void testDelayedPayloadPreservesFirstByteAndParsesVote() throws Exception {
		VoteConnectionHandler handler = new VoteConnectionHandler(receiver, new VoteThrottleService(null));

		try (ServerSocket serverSocket = new ServerSocket(0);
				Socket client = new Socket("127.0.0.1", serverSocket.getLocalPort());
				Socket accepted = serverSocket.accept()) {
			Future<Vote> future = executor.submit(() -> handler.handle(accepted));
			BufferedReader reader = new BufferedReader(
					new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
			OutputStream output = client.getOutputStream();

			assertEquals("VOTIFIER 1", reader.readLine());
			Thread.sleep(150);

			String voteMessage = "VOTE\nvotifier.bencodez.com\ndelayedUser\n127.0.0.1\nNormalTimestamp\n";
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, testKeyPair.getPublic());
			output.write(cipher.doFinal(voteMessage.getBytes(StandardCharsets.UTF_8)));
			output.flush();

			Vote vote = future.get(2, TimeUnit.SECONDS);
			assertNotNull(vote);
			assertEquals("delayedUser", vote.getUsername());
		}
	}

	private static class CapturingVoteReceiver extends VoteReceiver {

		private final List<String> warnings = new CopyOnWriteArrayList<>();
		private final List<String> debugMessages = new CopyOnWriteArrayList<>();

		CapturingVoteReceiver(String host, int port) throws Exception {
			super(host, port);
		}

		List<String> getWarnings() {
			return warnings;
		}

		List<String> getDebugMessages() {
			return debugMessages;
		}

		@Override
		public boolean isUseTokens() {
			return false;
		}

		@Override
		public void logWarning(String warning) {
			warnings.add(warning);
		}

		@Override
		public void logSevere(String message) {
		}

		@Override
		public void log(String message) {
		}

		@Override
		public void debug(String message) {
			debugMessages.add(message);
		}

		@Override
		public void debug(Exception exception) {
			debugMessages.add(exception.toString());
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
			return Collections.emptyMap();
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
}
