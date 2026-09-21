package com.bencodez.votifierplus.tests;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.Socket;
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

	private void waitForAccept() throws InterruptedException {
		assertTrue(receiver.awaitingAccept(2, TimeUnit.SECONDS), "Receiver did not reach accept()");
	}

	private static final class CapturingVoteReceiver extends VoteReceiver {

		private final List<String> warnings = new CopyOnWriteArrayList<>();
		private final CountDownLatch accepting = new CountDownLatch(1);

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
			return super.acceptSocket();
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
			return Collections.emptySet();
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
			return null;
		}

		@Override
		public void callEvent(Vote vote) {
		}
	}
}
