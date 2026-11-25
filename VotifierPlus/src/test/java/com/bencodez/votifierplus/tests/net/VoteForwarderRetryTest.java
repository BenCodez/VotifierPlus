package com.bencodez.votifierplus.tests.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import com.google.gson.JsonParser;
import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.model.Vote;
import com.vexsoftware.votifier.net.ForwardRetryConfig;
import com.vexsoftware.votifier.net.VoteForwarder;
import com.vexsoftware.votifier.net.VoteReceiver;

class VoteForwarderRetryTest {
	@Test
	void retriesOnlyFailedTargetWithOriginalVoteAndConfiguredToken() throws Exception {
		try (var run = new Forwarding(2)) {
			run.addTarget("healthy", 2001);
			run.addTarget("recovering", 2002);
			run.unavailablePort = 2002;
			Vote vote = new Vote("example.test", "OriginalVoter", "192.0.2.10", "original-time");
			run.forward(vote);
			vote.setUsername("ChangedVoter");
			vote.setAddress("192.0.2.20");

			for (int i = 0; i < 7; i++) {
				run.scheduler.runNext();
			}
			assertEquals(List.of(60L, 300L, 300L, 300L, 300L, 300L, 300L, 300L), run.scheduler.delays);
			assertEquals(1, Collections.frequency(run.connects, 2001));
			assertEquals(8, Collections.frequency(run.connects, 2002));
			assertEquals(1, run.payloads.size());

			run.unavailablePort = -1;
			run.scheduler.runNext();
			assertTrue(run.scheduler.getQueue().isEmpty());
			assertEquals(2, run.payloads.size());
			var packet = JsonParser.parseString(run.payloads.getLast().toString(StandardCharsets.UTF_8)).getAsJsonObject();
			String payload = packet.get("payload").getAsString();
			var voteJson = JsonParser.parseString(payload).getAsJsonObject();
			assertEquals("example.test", voteJson.get("serviceName").getAsString());
			assertEquals("OriginalVoter", voteJson.get("username").getAsString());
			assertEquals("192.0.2.10", voteJson.get("address").getAsString());
			assertEquals("original-time", voteJson.get("timestamp").getAsString());
			assertEquals("test-challenge", voteJson.get("challenge").getAsString());
			Mac signer = Mac.getInstance("HmacSHA256");
			signer.init(run.targets.get("recovering").getToken());
			assertEquals(Base64.getEncoder().encodeToString(signer.doFinal(payload.getBytes(StandardCharsets.UTF_8))),
					packet.get("signature").getAsString());
		}
	}

	@Test
	void doesNotRetryAmbiguousWriteOrIncompatibleGreeting() throws Exception {
		try (var run = new Forwarding(4)) {
			run.addTarget("backend", 2001);
			run.failWrite = true;
			run.forward(testVote());
			assertEquals(1, run.writeCalls);
			run.greeting = "VOTIFIER 1";
			run.forward(testVote());
			assertEquals(1, run.writeCalls);
			assertEquals(List.of(2001, 2001), run.connects);
			assertTrue(run.scheduler.delays.isEmpty());
		}
	}

	@Test
	void boundsBacklogAndDropsRemovedDisabledOrRepurposedTargets() throws Exception {
		try (var run = new Forwarding(4)) {
			run.addTarget("backend", 2001);
			run.unavailablePort = 2001;
			for (int i = 0; i < 10; i++) {
				run.forward(testVote());
			}
			assertEquals(4, run.scheduler.getQueue().size());
			run.targets.put("backend", new ForwardServer(false, "localhost", 2001, "", run.token()));
			run.scheduler.runNext();
			run.targets.remove("backend");
			run.scheduler.runNext();
			run.addTarget("backend", 2002);
			run.scheduler.runNext();
			run.targets.put("backend", new ForwardServer(true, "localhost", 2001, "", null));
			run.scheduler.runNext();
			assertEquals(10, run.connects.size());
			assertTrue(run.scheduler.getQueue().isEmpty());

			run.addTarget("backend", 2001);
			run.forward(testVote());
			assertEquals(1, run.scheduler.getQueue().size());
			run.retire();
			run.forward(testVote()); // Initial forwarding still drains during retirement.
			assertEquals(12, run.connects.size());
			assertTrue(run.scheduler.getQueue().isEmpty());
		}
	}

	@Test
	void independentlyAcceptedIdenticalVotesKeepSeparateRetrySlots() throws Exception {
		try (var run = new Forwarding(2)) {
			run.addTarget("backend", 2001);
			run.unavailablePort = 2001;
			try (var senders = Executors.newFixedThreadPool(2)) {
				var first = senders.submit(() -> { run.forward(testVote()); return null; });
				var second = senders.submit(() -> { run.forward(testVote()); return null; });
				first.get(5, TimeUnit.SECONDS);
				second.get(5, TimeUnit.SECONDS);
			}
			assertEquals(2, run.scheduler.getQueue().size());
			run.unavailablePort = -1;
			run.scheduler.runNext();
			run.scheduler.runNext();
			assertEquals(2, run.writeCalls);
			assertEquals(4, run.connects.size());
			assertTrue(run.scheduler.getQueue().isEmpty());
		}
	}

	@Test
	void retriesInitialAndRepeatedAddressResolutionTimeout() throws Exception {
		try (var run = new Forwarding(1)) {
			run.addTarget("backend", 2001);
			run.slowResolution = true;
			run.forward(testVote());
			run.scheduler.runNext();
			assertEquals(List.of(60L, 300L), run.scheduler.delays);
			assertTrue(run.connects.isEmpty());

			run.slowResolution = false;
			run.scheduler.runNext();
			assertEquals(List.of(2001), run.connects);
			assertEquals(1, run.writeCalls);
			assertTrue(run.scheduler.getQueue().isEmpty());
		}
	}

	@Test
	void retirementClosesActiveRetrySocketDuringDrain() throws Exception {
		try (var run = new Forwarding(1); var worker = Executors.newSingleThreadExecutor()) {
			run.addTarget("backend", 2001);
			run.unavailablePort = 2001;
			run.forward(testVote());

			run.unavailablePort = -1;
			run.blockWrite = true;
			var retry = worker.submit(run.scheduler::runNext);
			assertTrue(run.writeStarted.await(3, TimeUnit.SECONDS));
			run.retire();
			assertTrue(run.retrySocketClosed.await(3, TimeUnit.SECONDS));
			retry.get(3, TimeUnit.SECONDS);
			assertTrue(run.scheduler.getQueue().isEmpty());
			assertTrue(run.payloads.isEmpty());
		}
	}

	@Test
	void fixedFirstRetryThenConfiguredIntervalAndCount() throws Exception {
		for (int interval : new int[] {1, 300, 3600}) {
			for (int count : new int[] {0, 1, 2, 3600}) {
				try (var run = new Forwarding(1, new ForwardRetryConfig(interval, count, false))) {
					run.addTarget("backend", 2001);
					run.unavailablePort = 2001;
					run.forward(testVote());
					run.scheduler.runIfDue(TimeUnit.SECONDS.toNanos(60) - 1);
					assertEquals(1, run.connects.size());
					run.scheduler.runIfDue(TimeUnit.SECONDS.toNanos(60));
					assertEquals(count == 0 ? 1 : 2, run.connects.size());
					if (count >= 2 && interval < 3540) {
						assertEquals(List.of(60L, (long) interval), run.scheduler.delays);
						run.scheduler.runIfDue(TimeUnit.SECONDS.toNanos(60 + interval) - 1);
						assertEquals(2, run.connects.size());
						run.scheduler.runNext();
						assertEquals(3, run.connects.size());
					}
					if (count <= 2 || interval == 3600) {
						assertTrue(run.scheduler.getQueue().isEmpty());
					}
				}
			}
		}
	}

	@Test
	void defaultCountFitsAndLateSchedulerCannotStartAtOrBeyondExpiry() throws Exception {
		try (var run = new Forwarding(1)) {
			run.addTarget("backend", 2001);
			run.unavailablePort = 2001;
			run.forward(testVote());
			for (int i = 0; i < 12; i++) {
				run.scheduler.runNext();
			}
			assertEquals(13, run.connects.size());
			assertTrue(run.scheduler.getQueue().isEmpty());
		}
		for (long elapsed : new long[] {3599, 3600, 3601}) {
			try (var run = new Forwarding(1, new ForwardRetryConfig(1, 3600, false))) {
				run.addTarget("backend", 2001);
				run.unavailablePort = 2001;
				run.forward(testVote());
				run.scheduler.runIfDue(TimeUnit.SECONDS.toNanos(elapsed));
				assertEquals(elapsed < 3600 ? 2 : 1, run.connects.size());
				assertTrue(run.scheduler.getQueue().isEmpty());
			}
		}
	}

	@Test
	void previousTransportSuccessIsPerTargetAndClearedOnChangeAndRetirement() throws Exception {
		try (var run = new Forwarding(2, ForwardRetryConfig.DEFAULT)) {
			run.addTarget("cold", 2001);
			run.addTarget("healthy", 2002);
			run.unavailablePort = 2001;
			run.forward(testVote());
			assertTrue(run.scheduler.getQueue().isEmpty());
			run.failWrite = true;
			run.unavailablePort = -1;
			run.forward(testVote()); // Greeting and failed write cannot establish success.
			run.failWrite = false;
			run.unavailablePort = 2001;
			run.forward(testVote());
			assertTrue(run.scheduler.getQueue().isEmpty());
			run.targets.remove("cold");
			run.unavailablePort = 2002;
			run.forward(testVote());
			assertEquals(1, run.scheduler.getQueue().size());
			run.addTarget("healthy", 2002); // Change only the token.
			int sends = run.connects.size();
			run.scheduler.runNext();
			assertEquals(sends, run.connects.size());
			run.forward(testVote());
			assertTrue(run.scheduler.getQueue().isEmpty());
			run.unavailablePort = 2001;
			run.forward(testVote()); // A completed send establishes the new token's success.
			run.unavailablePort = 2002;
			run.forward(testVote());
			assertEquals(1, run.scheduler.getQueue().size());
			run.retire();
			assertTrue(run.scheduler.getQueue().isEmpty());
		}
		try (var replacement = new Forwarding(1, ForwardRetryConfig.DEFAULT)) {
			replacement.addTarget("healthy", 2002);
			replacement.unavailablePort = 2002;
			replacement.forward(testVote());
			assertTrue(replacement.scheduler.getQueue().isEmpty());
		}
	}

	@Test
	void invalidSettingsUseSafeDefaultsAndZeroCountDisables() {
		assertEquals(ForwardRetryConfig.DEFAULT, ForwardRetryConfig.parse(null, null, null));
		assertEquals(ForwardRetryConfig.DEFAULT, ForwardRetryConfig.parse(-1, -1, "invalid"));
		assertEquals(ForwardRetryConfig.DEFAULT, ForwardRetryConfig.parse(0, Long.MAX_VALUE, 0));
		assertEquals(ForwardRetryConfig.DEFAULT, ForwardRetryConfig.parse(1.5, "2147483648", List.of(false)));
		assertEquals(new ForwardRetryConfig(17, 0, false), ForwardRetryConfig.parse("17", 0, false));
	}

	@Test
	void destinationPoliciesInheritAndOverrideIndependently() throws Exception {
		var global = new ForwardRetryConfig(300, 4, true);
		assertEquals(global, global.withOverrides(null, null, null));
		assertEquals(global, global.withOverrides(-1, "2147483648", "invalid"));
		try (var run = new Forwarding(4, global)) {
			run.addTarget("quick", 2001, global.withOverrides(1, 2, false));
			run.addTarget("slow", 2001, global.withOverrides(3539, 4, "false"));
			run.addTarget("inherited", 2001, global.withOverrides(null, -1, null));
			run.addTarget("disabled", 2001, global.withOverrides(3, 0, false));
			run.unavailablePort = 2001;
			run.forward(testVote());
			assertEquals(4, run.connects.size());
			assertEquals(List.of(60L, 60L), run.scheduler.delays);
			run.scheduler.runIfDue(TimeUnit.SECONDS.toNanos(60) - 1);
			assertEquals(4, run.connects.size());
			run.scheduler.runNext();
			run.scheduler.runNext();
			assertEquals(6, run.connects.size());
			assertEquals(List.of(60L, 60L, 1L, 3539L), run.scheduler.delays);
			run.scheduler.runNext();
			assertEquals(7, run.connects.size());
			run.scheduler.runIfDue(TimeUnit.HOURS.toNanos(1));
			assertEquals(7, run.connects.size());
			assertTrue(run.scheduler.getQueue().isEmpty());
		}
	}

	@Test
	void policyChangeInvalidatesPreviousSuccessAndQueuedVotes() throws Exception {
		try (var run = new Forwarding(2, ForwardRetryConfig.DEFAULT)) {
			run.addTarget("backend", 2001, ForwardRetryConfig.DEFAULT);
			run.forward(testVote());
			run.unavailablePort = 2001;
			run.forward(testVote());
			assertEquals(1, run.scheduler.getQueue().size());
			var previous = run.targets.get("backend");
			run.targets.put("backend", new ForwardServer(true, "localhost", 2001, "", previous.getToken(),
					ForwardRetryConfig.DEFAULT.withOverrides(10, null, null)));
			run.scheduler.runNext();
			assertEquals(2, run.connects.size());
			run.forward(testVote());
			assertTrue(run.scheduler.getQueue().isEmpty());
		}
	}

	@Test
	void opaqueKeyDoesNotPreventLaterTargetsFromReceivingVote() throws Exception {
		try (var run = new Forwarding(2, ForwardRetryConfig.DEFAULT)) {
			Key opaque = mock(Key.class);
			when(opaque.getEncoded()).thenThrow(new UnsupportedOperationException());
			run.targets.put("opaque", new ForwardServer(true, "localhost", 2001, "", opaque));
			run.addTarget("healthy", 2002);
			run.unavailablePort = 2001;

			run.forward(testVote());
			assertEquals(List.of(2001, 2002), run.connects);
			assertEquals(1, run.payloads.size());
			assertTrue(run.scheduler.getQueue().isEmpty());

			run.forwarder.forwardVote(testVote());
			assertEquals(List.of(2001, 2002, 2001, 2002), run.connects);
			assertEquals(2, run.payloads.size());
		}
	}

	@Test
	void tokenReplacementDuringIdentityReadCannotChangeInFlightCredential() throws Exception {
		try (var run = new Forwarding(1, ForwardRetryConfig.DEFAULT)) {
			run.addTarget("backend", 2001);
			ForwardServer target = run.targets.get("backend");
			Key original = target.getToken();
			Key replacement = run.token();
			target.setToken(new SecretKeySpec(original.getEncoded(), "HmacSHA256") {
				@Override
				public byte[] getEncoded() {
					target.setToken(replacement);
					return super.getEncoded();
				}
			});

			run.forward(testVote());
			var packet = JsonParser.parseString(run.payloads.getLast().toString(StandardCharsets.UTF_8)).getAsJsonObject();
			byte[] payload = packet.get("payload").getAsString().getBytes(StandardCharsets.UTF_8);
			Mac signer = Mac.getInstance("HmacSHA256");
			signer.init(original);
			assertEquals(Base64.getEncoder().encodeToString(signer.doFinal(payload)), packet.get("signature").getAsString());

			run.unavailablePort = 2001;
			run.forward(testVote());
			assertTrue(run.scheduler.getQueue().isEmpty());
		}
	}

	private static Vote testVote() {
		return new Vote("example.test", "TestVoter", "192.0.2.10", "test-time");
	}

	private static final class ManualScheduler extends ScheduledThreadPoolExecutor {
		final List<Long> delays = new ArrayList<>();
		final Map<Runnable, Long> due = new LinkedHashMap<>();
		volatile long now;

		ManualScheduler() {
			super(1);
		}

		@Override
		public ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
			delays.add(unit.toSeconds(delay));
			ScheduledFuture<?> scheduled = super.schedule(command, 1, TimeUnit.DAYS);
			due.put((Runnable) scheduled, now + unit.toNanos(delay));
			return scheduled;
		}

		void runNext() {
			Runnable next = next();
			assertNotNull(next);
			runIfDue(Math.max(now, due.get(next)));
		}

		void runIfDue(long time) {
			now = time;
			Runnable next = next();
			if (next != null && doneWaiting(next)) {
				assertTrue(remove(next));
				due.remove(next);
				next.run();
			}
		}

		private Runnable next() {
			return getQueue().stream().min(Comparator.comparingLong(due::get)).orElse(null);
		}

		private boolean doneWaiting(Runnable next) {
			return due.get(next) <= now;
		}
	}

	private static final class Forwarding implements AutoCloseable {
		final Map<String, ForwardServer> targets = new LinkedHashMap<>();
		final List<Integer> connects = Collections.synchronizedList(new ArrayList<>());
		final List<ByteArrayOutputStream> payloads = new ArrayList<>();
		final ManualScheduler scheduler = new ManualScheduler();
		final VoteForwarder forwarder;
		int unavailablePort = -1;
		int writeCalls;
		boolean failWrite;
		boolean blockWrite;
		volatile boolean slowResolution;
		final CountDownLatch writeStarted = new CountDownLatch(1);
		final CountDownLatch retrySocketClosed = new CountDownLatch(1);
		String greeting = "VOTIFIER 2 test-challenge";

		Forwarding(int capacity) throws Exception {
			this(capacity, new ForwardRetryConfig(300, 12, false));
		}

		Forwarding(int capacity, ForwardRetryConfig retryConfig) throws Exception {
			var receiver = mock(VoteReceiver.class);
			when(receiver.getServers()).thenReturn(targets.keySet());
			when(receiver.getServerData(org.mockito.ArgumentMatchers.anyString()))
					.thenAnswer(call -> targets.get(call.getArgument(0)));
			when(receiver.getForwardQueueCapacity()).thenReturn(capacity);
			var constructor = VoteForwarder.class.getDeclaredConstructor(VoteReceiver.class, int.class,
					BiFunction.class, Supplier.class, ScheduledThreadPoolExecutor.class, ForwardRetryConfig.class, LongSupplier.class);
			constructor.setAccessible(true);
			BiFunction<String, Integer, InetSocketAddress> resolver = (host, port) -> {
				if (slowResolution) {
					try {
						TimeUnit.SECONDS.sleep(20);
					} catch (InterruptedException ex) {
						Thread.currentThread().interrupt();
					}
				}
				return new InetSocketAddress(java.net.InetAddress.getLoopbackAddress(), port);
			};
			forwarder = constructor.newInstance(receiver, 2, resolver, (Supplier<Socket>) this::socket,
					scheduler, retryConfig, (LongSupplier) () -> scheduler.now);
		}

		void addTarget(String name, int port) throws Exception {
			addTarget(name, port, null);
		}

		void addTarget(String name, int port, ForwardRetryConfig retryConfig) throws Exception {
			targets.put(name, new ForwardServer(true, "localhost", port, "", token(), retryConfig));
		}

		Key token() throws Exception {
			return KeyGenerator.getInstance("HmacSHA256").generateKey();
		}

		void forward(Vote vote) throws Exception {
			invoke("forwardQueuedVote", vote);
		}

		void retire() throws Exception {
			invoke("sealDirectCalls", null);
		}

		@Override
		public void close() throws Exception {
			invoke("stop", null);
		}

		private void invoke(String name, Vote vote) throws Exception {
			var method = vote == null ? VoteForwarder.class.getDeclaredMethod(name)
					: VoteForwarder.class.getDeclaredMethod(name, Vote.class);
			method.setAccessible(true);
			if (vote == null) {
				method.invoke(forwarder);
			} else {
				method.invoke(forwarder, vote);
			}
		}

		private Socket socket() {
			return new Socket() {
				@Override
				public void connect(SocketAddress address, int timeout) throws IOException {
					int port = ((InetSocketAddress) address).getPort();
					connects.add(port);
					if (port == unavailablePort) {
						throw new ConnectException();
					}
				}

				@Override
				public ByteArrayInputStream getInputStream() {
					return new ByteArrayInputStream((greeting + "\n").getBytes(StandardCharsets.UTF_8));
				}

				@Override
				public synchronized void close() throws IOException {
					super.close();
					if (blockWrite) {
						retrySocketClosed.countDown();
					}
				}

				@Override
				public OutputStream getOutputStream() {
					return new OutputStream() {
						@Override
						public void write(byte[] bytes) throws IOException {
							writeCalls++;
							if (blockWrite) {
								writeStarted.countDown();
								try {
									if (!retrySocketClosed.await(4, TimeUnit.SECONDS)) {
										throw new AssertionError("Retry socket was not closed during retirement");
									}
								} catch (InterruptedException ex) {
									Thread.currentThread().interrupt();
									throw new AssertionError(ex);
								}
								throw new IOException("Socket closed");
							}
							if (failWrite) {
								throw new IOException();
							}
							var payload = new ByteArrayOutputStream();
							payload.write(bytes);
							payloads.add(payload);
						}

						@Override
						public void write(int value) {
							throw new AssertionError("Expected a whole payload");
						}
					};
				}
			};
		}
	}
}
