package com.bencodez.votifierplus.tests;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.Socket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.lang.reflect.Method;
import java.lang.reflect.Field;
import java.util.concurrent.LinkedBlockingQueue;
import java.security.Key;
import java.security.KeyPair;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.model.Vote;
import com.vexsoftware.votifier.net.ThrottleConfig;
import com.vexsoftware.votifier.net.VoteReceiver;

/** Regression tests for receiver thread lifecycle logging. */
public class VoteReceiverLifecycleTest {

	private CapturingVoteReceiver receiver;

	@AfterEach
	public void tearDown() throws Exception {
		if (receiver != null) {
			receiver.shutdown();
			receiver.join(3000);
		}
	}

	@Test
	public void intentionalShutdownDoesNotWarn() throws Exception {
		receiver = new CapturingVoteReceiver();
		receiver.start();
		waitForAccept();

		receiver.shutdown();
		receiver.join(3000);

		assertFalse(receiver.isAlive());
		assertTrue(receiver.getWarnings().isEmpty(), () -> "Unexpected shutdown warnings: " + receiver.getWarnings());
	}

	@Test
	public void unexpectedAcceptSocketExceptionWarnsWhileRunning() throws Exception {
		receiver = new CapturingVoteReceiver();
		receiver.start();
		waitForAccept();

		receiver.getServer().close();
		receiver.join(3000);

		assertFalse(receiver.isAlive(), "Receiver should stop after its listener is closed");
		assertTrue(receiver.getWarnings().stream()
				.anyMatch(message -> message.contains("Connection error while accepting vote socket")),
				() -> "Expected accept warning, got: " + receiver.getWarnings());
		assertTrue(receiver.getWarnings().size() == 1, () -> "Expected one accept warning, got: " + receiver.getWarnings());
	}

	@Test
	public void forcedShutdownClosesActiveAndQueuedSockets() throws Exception {
		receiver = new CapturingVoteReceiver();
		receiver.pauseProcessing = true;
		receiver.start();
		int port = receiver.getServer().getLocalPort();
		try (Socket active = new Socket("127.0.0.1", port);
				Socket queued = new Socket("127.0.0.1", port)) {
			assertTrue(receiver.processing.await(2, TimeUnit.SECONDS));
			Socket first = receiver.accepted.poll(2, TimeUnit.SECONDS);
			Socket second = receiver.accepted.poll(2, TimeUnit.SECONDS);
			assertNotNull(first);
			assertNotNull(second);
			assertTrue(receiver.thirdAccept.await(2, TimeUnit.SECONDS), "second socket was not submitted");
			var retiring = new Thread(() -> {
				Thread.currentThread().interrupt();
				receiver.shutdown();
			});
			retiring.start();
			retiring.join(5000);
			assertFalse(retiring.isAlive());
			assertTrue(first.isClosed());
			assertTrue(second.isClosed());
			assertTrue(retiring.isInterrupted());
		}
	}

	@Test
	public void socketAcceptedDuringRetirementIsClosed() throws Exception {
		receiver = new CapturingVoteReceiver();
		receiver.pauseAccept = true;
		receiver.start();
		try (Socket client = new Socket("127.0.0.1", receiver.getServer().getLocalPort())) {
			Socket accepted = receiver.accepted.poll(2, TimeUnit.SECONDS);
			assertNotNull(accepted);
			try {
				receiver.shutdown();
			} finally {
				receiver.resumeAccept.countDown();
			}
			receiver.join(3000);
			assertFalse(receiver.isAlive());
			assertTrue(accepted.isClosed());
			assertEquals(1L, receiver.processing.getCount());
		}
	}

	@Test
	public void fullForwardingQueueNeverRunsTheOutboundJobOnTheSubmittingThread() throws Exception {
		receiver = new CapturingVoteReceiver();
		try (ServerSocket backend = new ServerSocket(0, 3, InetAddress.getLoopbackAddress())) {
			backend.setSoTimeout(2000);
			receiver.servers = Set.of("test");
			receiver.target = new ForwardServer(true, backend.getInetAddress().getHostAddress(),
					backend.getLocalPort(), "", null);
			receiver.start();
			waitForAccept();
			Method submit = VoteReceiver.class.getDeclaredMethod("submitForward", Vote.class);
			submit.setAccessible(true);
			Vote vote = new Vote("example.test", "TestVoter", "", "TestTimestamp");
			submit.invoke(receiver, vote);
			try (Socket stalled = backend.accept()) {
				submit.invoke(receiver, vote);
				submit.invoke(receiver, vote);
				assertTrue(receiver.getWarnings().stream().anyMatch(warning -> warning.contains("Unable to queue")));
				var retire = new Thread(() -> {
					Thread.currentThread().interrupt();
					receiver.shutdown();
				});
				retire.start();
				retire.join(5000);
				assertFalse(retire.isAlive());
				assertTrue(receiver.getWarnings().stream().anyMatch(warning ->
						warning.contains("discarded queued jobs=1, closed active sockets=1")));
				stalled.setSoTimeout(2000);
				assertEquals(-1, stalled.getInputStream().read());
			}
		}
	}

	@Test
	public void concurrentShutdownWaitsForTheRetirementOwner() throws Exception {
		receiver = new CapturingVoteReceiver();
		CountDownLatch closing = new CountDownLatch(1);
		CountDownLatch canClose = new CountDownLatch(1);
		CountDownLatch secondReturned = new CountDownLatch(1);
		receiver.getServer().close();
		Field server = VoteReceiver.class.getDeclaredField("server");
		server.setAccessible(true);
		server.set(receiver, new ServerSocket() {
			@Override
			public void close() throws IOException {
				closing.countDown();
				try {
					canClose.await(3, TimeUnit.SECONDS);
				} catch (InterruptedException ex) {
					Thread.currentThread().interrupt();
				}
				super.close();
			}
		});
		Thread first = new Thread(receiver::shutdown);
		Thread second = new Thread(() -> {
			receiver.shutdown();
			secondReturned.countDown();
		});
		first.start();
		try {
			assertTrue(closing.await(2, TimeUnit.SECONDS));
			second.start();
			assertFalse(secondReturned.await(200, TimeUnit.MILLISECONDS));
		} finally {
			canClose.countDown();
			first.join(5000);
			second.join(5000);
		}
		assertFalse(first.isAlive());
		assertFalse(second.isAlive());
		assertTrue(receiver.getServer().isClosed());
	}

	private void waitForAccept() throws InterruptedException {
		assertTrue(receiver.awaitingAccept(2, TimeUnit.SECONDS), "Receiver did not reach accept()");
	}

	private static final class CapturingVoteReceiver extends VoteReceiver {

		private final List<String> warnings = new CopyOnWriteArrayList<>();
		private final CountDownLatch accepting = new CountDownLatch(1);
		private final CountDownLatch processing = new CountDownLatch(1);
		private final CountDownLatch thirdAccept = new CountDownLatch(3);
		private final CountDownLatch resumeAccept = new CountDownLatch(1);
		private final LinkedBlockingQueue<Socket> accepted = new LinkedBlockingQueue<>();
		private boolean pauseAccept;
		private boolean pauseProcessing;
		private Set<String> servers = Set.of();
		private ForwardServer target;

		private CapturingVoteReceiver() throws Exception {
			super("127.0.0.1", 0);
		}

		private List<String> getWarnings() {
			return warnings;
		}

		private boolean awaitingAccept(long timeout, TimeUnit unit) throws InterruptedException {
			return accepting.await(timeout, unit);
		}

		@Override
		protected Socket acceptSocket() throws IOException {
			accepting.countDown();
			thirdAccept.countDown();
			Socket socket = super.acceptSocket();
			accepted.add(socket);
			if (pauseAccept) {
				try {
					resumeAccept.await(3, TimeUnit.SECONDS);
				} catch (InterruptedException ex) {
					Thread.currentThread().interrupt();
				}
			}
			return socket;
		}

		@Override
		public int getConnectionWorkerCount() {
			return 1;
		}

		@Override
		public int getForwardQueueCapacity() {
			return 1;
		}

		@Override
		public boolean isUseTokens() {
			return false;
		}

		@Override
		public ThrottleConfig getThrottleConfig() {
			return null;
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
			if (message.startsWith("Accepted connection")) {
				processing.countDown();
				if (pauseProcessing) {
					try {
						new CountDownLatch(1).await(4, TimeUnit.SECONDS);
					} catch (InterruptedException ex) {
						Thread.currentThread().interrupt();
					}
				}
			}
		}

		@Override
		public void debug(Exception exception) {
		}

		@Override
		public String getVersion() {
			return "test";
		}

		@Override
		public Set<String> getServers() {
			return servers;
		}

		@Override
		public KeyPair getKeyPair() {
			return null;
		}

		@Override
		public Map<String, Key> getTokens() {
			return Collections.emptyMap();
		}

		@Override
		public ForwardServer getServerData(String server) {
			return target;
		}

		@Override
		public void callEvent(Vote vote) {
		}
	}
}
