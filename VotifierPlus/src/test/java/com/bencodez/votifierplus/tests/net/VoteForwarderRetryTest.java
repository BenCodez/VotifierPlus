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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;
import java.util.function.Supplier;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

import org.junit.jupiter.api.Test;

import com.google.gson.JsonParser;
import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.model.Vote;
import com.vexsoftware.votifier.net.VoteForwarder;
import com.vexsoftware.votifier.net.VoteReceiver;

class VoteForwarderRetryTest {
	@Test
	void retriesOnlyFailedTargetWithOriginalVoteAndCurrentToken() throws Exception {
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
			assertEquals(List.of(15L, 15L, 15L, 15L, 15L, 30L, 30L, 30L), run.scheduler.delays);
			assertEquals(1, Collections.frequency(run.connects, 2001));
			assertEquals(8, Collections.frequency(run.connects, 2002));
			assertEquals(1, run.payloads.size());

			run.addTarget("recovering", 2002);
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
			try (var senders = java.util.concurrent.Executors.newFixedThreadPool(2)) {
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

	private static Vote testVote() {
		return new Vote("example.test", "TestVoter", "192.0.2.10", "test-time");
	}

	private static final class ManualScheduler extends ScheduledThreadPoolExecutor {
		final List<Long> delays = new ArrayList<>();

		ManualScheduler() {
			super(1);
		}

		@Override
		public ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
			delays.add(unit.toMinutes(delay));
			return super.schedule(command, delay, unit);
		}

		void runNext() {
			Runnable next = getQueue().peek();
			assertNotNull(next);
			assertTrue(remove(next));
			next.run();
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
		String greeting = "VOTIFIER 2 test-challenge";

		Forwarding(int capacity) throws Exception {
			var receiver = mock(VoteReceiver.class);
			when(receiver.getServers()).thenReturn(targets.keySet());
			when(receiver.getServerData(org.mockito.ArgumentMatchers.anyString()))
					.thenAnswer(call -> targets.get(call.getArgument(0)));
			when(receiver.getForwardQueueCapacity()).thenReturn(capacity);
			var constructor = VoteForwarder.class.getDeclaredConstructor(VoteReceiver.class, int.class,
					BiFunction.class, Supplier.class, ScheduledThreadPoolExecutor.class);
			constructor.setAccessible(true);
			BiFunction<String, Integer, InetSocketAddress> resolver =
					(host, port) -> new InetSocketAddress(java.net.InetAddress.getLoopbackAddress(), port);
			forwarder = constructor.newInstance(receiver, 2, resolver, (Supplier<Socket>) this::socket, scheduler);
		}

		void addTarget(String name, int port) throws Exception {
			targets.put(name, new ForwardServer(true, "localhost", port, "", token()));
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
				public OutputStream getOutputStream() {
					return new OutputStream() {
						@Override
						public void write(byte[] bytes) throws IOException {
							writeCalls++;
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
