package com.bencodez.votifierplus.tests;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.Socket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.function.BiFunction;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.FutureTask;
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
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.KeyGenerator;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.model.Vote;
import com.vexsoftware.votifier.net.ThrottleConfig;
import com.vexsoftware.votifier.net.VoteReceiver;
import com.vexsoftware.votifier.net.VoteForwarder;

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
	public void fullForwardingQueueStillAcknowledgesAndDeliversVotesLocally() throws Exception {
		receiver = new CapturingVoteReceiver();
		try (ServerSocket backend = new ServerSocket(0, 3, InetAddress.getLoopbackAddress())) {
			backend.setSoTimeout(2000);
			receiver.servers = Set.of("test");
			receiver.target = new ForwardServer(true, backend.getInetAddress().getHostAddress(),
					backend.getLocalPort(), "", null);
			receiver.signingKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
			receiver.start();
			int port = receiver.getServer().getLocalPort();
			VoteReceiverBindingTest.assertVoteAccepted(port, receiver.signingKey);
			try (Socket stalled = backend.accept()) {
				for (int i = 0; i < 3; i++) {
					VoteReceiverBindingTest.assertVoteAccepted(port, receiver.signingKey);
				}
				for (int i = 0; i < 4; i++) {
					assertNotNull(receiver.votes.poll(2, TimeUnit.SECONDS));
				}
				assertTrue(receiver.forwardingRejected.await(2, TimeUnit.SECONDS));
				var retire = new Thread(() -> {
					Thread.currentThread().interrupt();
					receiver.shutdown();
				});
				retire.start();
				retire.join(5000);
				assertFalse(retire.isAlive());
				assertTrue(receiver.getWarnings().stream().anyMatch(warning ->
						warning.contains("discarded queued jobs=1, active socket close attempts=1")));
				assertTrue(receiver.getWarnings().contains("Forwarding queue rejections at receiver retirement: 2"));
				assertEquals(1L, receiver.getWarnings().stream().filter(warning -> warning.contains("Unable to queue")).count());
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
		AtomicInteger listenerCloseCalls = new AtomicInteger();
		receiver.getServer().close();
		Field server = VoteReceiver.class.getDeclaredField("server");
		server.setAccessible(true);
		server.set(receiver, new ServerSocket() {
			@Override
			public void close() throws IOException {
				listenerCloseCalls.incrementAndGet();
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
		assertEquals(1, listenerCloseCalls.get());
		assertTrue(receiver.getServer().isClosed());
	}

	@Test
	public void listenerExitCannotConfirmRetirementOfANonCooperativeWorker() throws Exception {
		receiver = new CapturingVoteReceiver();
		receiver.signingKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
		var callbackThread = new LinkedBlockingQueue<Thread>();
		var release = new CountDownLatch(1);
		receiver.onVote = () -> {
			callbackThread.add(Thread.currentThread());
			boolean interrupted = false;
			try {
				while (release.getCount() != 0) {
					try {
						if (!release.await(10, TimeUnit.SECONDS)) {
							return;
						}
					} catch (InterruptedException ex) {
						interrupted = true;
					}
				}
			} finally {
				if (interrupted) {
					Thread.currentThread().interrupt();
				}
			}
		};
		receiver.start();
		Thread shutdown = new Thread(() -> {
			Thread.currentThread().interrupt();
			receiver.shutdown();
		});
		Thread worker = null;
		try {
			VoteReceiverBindingTest.assertVoteAccepted(receiver.getServer().getLocalPort(), receiver.signingKey);
			worker = callbackThread.poll(2, TimeUnit.SECONDS);
			assertNotNull(worker);
			shutdown.start();
			shutdown.join(6000);
			receiver.join(2000);
			assertFalse(shutdown.isAlive());
			assertFalse(receiver.isAlive());
			assertFalse(receiver.isRetired());
			assertTrue(worker.isAlive(), "Listener exit does not terminate a callback that ignores interruption");
			assertTrue(receiver.getWarnings().contains("Unable to fully shut down connection executor."));
		} finally {
			release.countDown();
			if (worker != null) {
				worker.join(2000);
				assertFalse(worker.isAlive(), "Cooperating after release lets the same worker retire");
				assertTrue(receiver.isRetired());
			}
		}
	}

	@Test
	public void repeatedFailuresAgainstOneTargetShareOneDiagnostic() throws Exception {
		receiver = new CapturingVoteReceiver();
		try (ServerSocket backend = new ServerSocket(0, 2, InetAddress.getLoopbackAddress())) {
			backend.setSoTimeout(3000);
			receiver.servers = Set.of("test");
			receiver.target = new ForwardServer(true, backend.getInetAddress().getHostAddress(),
					backend.getLocalPort(), "", null);
			var replies = new FutureTask<Void>(() -> {
				for (int i = 0; i < 2; i++) {
					try (Socket peer = backend.accept()) {
						peer.getOutputStream().write(("A".repeat(600) + "\n").getBytes(StandardCharsets.UTF_8));
					}
				}
				return null;
			});
			Thread.ofVirtual().start(replies);
			var forwarder = new VoteForwarder(receiver);
			var vote = new Vote("example.test", "TestVoter", "", "TestTimestamp");
			forwarder.forwardVote(vote);
			forwarder.forwardVote(vote);
			replies.get(5, TimeUnit.SECONDS);
			assertEquals(1L, receiver.info.stream().filter(message -> message.contains("Failed to forward vote")).count());
			assertFalse(receiver.info.getFirst().contains("A".repeat(100)));
		}
	}

	@Test
	public void shutdownBeforeStartSealsTheInstance() throws Exception {
		receiver = new CapturingVoteReceiver();
		assertFalse(receiver.isRetired());
		receiver.shutdown();
		assertTrue(receiver.isRetired());
		assertThrows(IllegalThreadStateException.class, receiver::start);
		assertThrows(IllegalStateException.class, receiver::initialize);
		assertTrue(receiver.isRetired());
	}

	@Test
	public void partialStartupRetiresTheListenerAndOwnedExecutors() throws Exception {
		receiver = new CapturingVoteReceiver();
		receiver.invalidForwardQueue = true;
		var failure = new LinkedBlockingQueue<Throwable>();
		receiver.setUncaughtExceptionHandler((thread, error) -> failure.add(error));
		receiver.start();
		receiver.join(3000);
		assertFalse(receiver.isAlive());
		assertTrue(failure.poll(2, TimeUnit.SECONDS) instanceof IllegalArgumentException);
		assertTrue(receiver.isRetired());
	}

	@Test
	public void failedCloseIsNotSuccessfulRetirement() throws Exception {
		receiver = new CapturingVoteReceiver();
		receiver.getServer().close();
		Field server = VoteReceiver.class.getDeclaredField("server");
		server.setAccessible(true);
		server.set(receiver, new ServerSocket() {
			@Override
			public void close() throws IOException {
				super.close();
				throw new IOException("synthetic cleanup failure");
			}
		});
		receiver.shutdown();
		assertTrue(receiver.getServer().isClosed());
		assertFalse(receiver.isRetired());
	}

	@Test
	public void repeatedLegacyInitializePreservesTheOriginalListener() throws Exception {
		receiver = new CapturingVoteReceiver();
		ServerSocket original = receiver.getServer();
		assertThrows(IllegalStateException.class, receiver::initialize);
		assertTrue(original == receiver.getServer());
		assertFalse(original.isClosed());
		receiver.shutdown();
		assertTrue(original.isClosed());
		assertTrue(receiver.isRetired());
	}

	@Test
	public void admittedSocketCloseFailurePreventsRetirementConfirmation() throws Exception {
		receiver = new CapturingVoteReceiver();
		receiver.pauseProcessing = true;
		var admitted = org.mockito.Mockito.mock(Socket.class);
		org.mockito.Mockito.doThrow(new IOException("synthetic socket close failure")).when(admitted).close();
		receiver.syntheticSocket = admitted;
		receiver.start();
		assertTrue(receiver.thirdAccept.await(2, TimeUnit.SECONDS));
		receiver.shutdown();
		receiver.join(2000);
		assertFalse(receiver.isAlive());
		assertFalse(receiver.isRetired());
		org.mockito.Mockito.verify(admitted, org.mockito.Mockito.atLeastOnce()).close();
	}

	@Test
	public void receiverRetainsStuckResolverAfterNormalAndForcedForwardingDrain() throws Exception {
		for (boolean force : new boolean[] {false, true}) {
			receiver = new CapturingVoteReceiver();
			receiver.signingKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
			receiver.servers = Set.of("test");
			receiver.target = new ForwardServer(true, "example.test", 1234, "", null);
			receiver.start();
			waitForAccept();
			var resolverThread = new LinkedBlockingQueue<Thread>();
			var release = new CountDownLatch(1);
			BiFunction<String, Integer, InetSocketAddress> resolve = (host, port) -> {
				resolverThread.add(Thread.currentThread());
				while (release.getCount() != 0) {
					try {
						if (!release.await(12, TimeUnit.SECONDS)) {
							break;
						}
					} catch (InterruptedException ignored) {
						// Model a resolver that keeps running after cancellation.
					}
				}
				return new InetSocketAddress(InetAddress.getLoopbackAddress(), port);
			};
			var constructor = VoteForwarder.class.getDeclaredConstructor(VoteReceiver.class, int.class, BiFunction.class);
			constructor.setAccessible(true);
			var forwarderField = VoteReceiver.class.getDeclaredField("voteForwarder");
			forwarderField.setAccessible(true);
			var stopForwarder = VoteForwarder.class.getDeclaredMethod("stop");
			stopForwarder.setAccessible(true);
			stopForwarder.invoke(receiver.getVoteForwarder());
			forwarderField.set(receiver, constructor.newInstance(receiver, 1, resolve));
			Thread worker = null;
			try {
				VoteReceiverBindingTest.assertVoteAccepted(receiver.getServer().getLocalPort(), receiver.signingKey);
				worker = resolverThread.poll(2, TimeUnit.SECONDS);
				assertNotNull(worker);
				if (!force) {
					assertTrue(receiver.forwardFailure.await(7, TimeUnit.SECONDS));
				}
				var shutdown = new Thread(() -> {
					if (force) {
						Thread.currentThread().interrupt();
					}
					receiver.shutdown();
				});
				shutdown.start();
				shutdown.join(5000);
				receiver.join(2000);
				assertFalse(shutdown.isAlive());
				assertFalse(receiver.isAlive());
				assertFalse(receiver.isRetired());
				assertTrue(worker.isAlive());
			} finally {
				release.countDown();
				if (worker != null) {
					worker.join(2000);
				}
				receiver.shutdown();
			}
			assertTrue(receiver.isRetired());
		}
	}

	private void waitForAccept() throws InterruptedException {
		assertTrue(receiver.awaitingAccept(2, TimeUnit.SECONDS), "Receiver did not reach accept()");
	}

	private static final class CapturingVoteReceiver extends VoteReceiver {

		private final List<String> warnings = new CopyOnWriteArrayList<>();
		private final List<String> info = new CopyOnWriteArrayList<>();
		private final CountDownLatch accepting = new CountDownLatch(1);
		private final CountDownLatch processing = new CountDownLatch(1);
		private final CountDownLatch thirdAccept = new CountDownLatch(3);
		private final CountDownLatch resumeAccept = new CountDownLatch(1);
		private final LinkedBlockingQueue<Socket> accepted = new LinkedBlockingQueue<>();
		private boolean pauseAccept;
		private Socket syntheticSocket;
		private final CountDownLatch forwardFailure = new CountDownLatch(1);
		private boolean invalidForwardQueue;
		private boolean pauseProcessing;
		private Set<String> servers = Set.of();
		private ForwardServer target;
		private Key signingKey;
		private Runnable onVote = () -> {};
		private final LinkedBlockingQueue<Vote> votes = new LinkedBlockingQueue<>();
		private final CountDownLatch forwardingRejected = new CountDownLatch(1);

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
			Socket socket = syntheticSocket;
			if (socket == null) {
				socket = super.acceptSocket();
			} else {
				syntheticSocket = null;
				thirdAccept.countDown();
			}
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
			return invalidForwardQueue ? 0 : 1;
		}

		@Override
		public boolean isUseTokens() {
			return signingKey != null;
		}

		@Override
		public ThrottleConfig getThrottleConfig() {
			return null;
		}

		@Override
		public void logWarning(String warning) {
			warnings.add(warning);
			if (warning.contains("Unable to queue")) {
				forwardingRejected.countDown();
			}
		}

		@Override
		public void logSevere(String message) {
		}

		@Override
		public void log(String message) {
			info.add(message);
			if (message.contains("Failed to forward vote")) {
				forwardFailure.countDown();
			}
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
			return signingKey == null ? Collections.emptyMap() : Map.of("example.test", signingKey);
		}

		@Override
		public ForwardServer getServerData(String server) {
			return target;
		}

		@Override
		public void callEvent(Vote vote) {
			votes.add(vote);
			onVote.run();
		}
	}
}
