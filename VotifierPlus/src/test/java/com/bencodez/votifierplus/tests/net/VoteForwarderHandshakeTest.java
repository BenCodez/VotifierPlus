package com.bencodez.votifierplus.tests.net;

import com.vexsoftware.votifier.net.VoteForwarder;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.FilterOutputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.io.StringReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.FutureTask;
import java.util.function.BiFunction;
import java.util.function.Supplier;
import java.util.concurrent.atomic.AtomicInteger;
import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.net.VoteReceiver;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.vexsoftware.votifier.model.Vote;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

public class VoteForwarderHandshakeTest {
	// Keep the production parser package-private while exercising the same method.
	private static String readHandshakeLine(BufferedReader input) throws Exception {
		Method parser = VoteForwarder.class.getDeclaredMethod("readHandshakeLine", BufferedReader.class);
		parser.setAccessible(true);
		try {
			return (String) parser.invoke(null, input);
		} catch (InvocationTargetException failure) {
			if (failure.getCause() instanceof Exception cause) throw cause;
			if (failure.getCause() instanceof Error cause) throw cause;
			throw new AssertionError(failure.getCause());
		}
	}

	@Test
	public void crlfConsumesBothTerminatorBytesAndPreservesFollowingData() throws Exception {
		BufferedReader input = new BufferedReader(new StringReader("VOTIFIER 2 challenge\r\nPAYLOAD\n"));
		assertEquals("VOTIFIER 2 challenge", readHandshakeLine(input));
		assertEquals("PAYLOAD", input.readLine());
	}

	@Test
	public void lfAndBareCrPreserveFollowingData() throws Exception {
		BufferedReader lf = new BufferedReader(new StringReader("VOTIFIER 2 challenge\nPAYLOAD\n"));
		assertEquals("VOTIFIER 2 challenge", readHandshakeLine(lf));
		assertEquals("PAYLOAD", lf.readLine());

		BufferedReader cr = new BufferedReader(new StringReader("VOTIFIER 2 challenge\rPAYLOAD\n"));
		assertEquals("VOTIFIER 2 challenge", readHandshakeLine(cr));
		assertEquals("PAYLOAD", cr.readLine());
	}

	@Test
	public void oversizedHandshakeIsStillRejected() {
		BufferedReader input = new BufferedReader(new StringReader("X".repeat(513) + "\r\n"));
		assertThrows(IllegalStateException.class, () -> readHandshakeLine(input));
	}

	@Test
	public void quietPeerAndCrLookaheadUseTheTotalDeadline() throws Exception {
		for (String greeting : new String[] {"", "VOTIFIER 2 challenge\r"}) {
			try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
					Socket client = new Socket(server.getInetAddress(), server.getLocalPort());
					Socket peer = server.accept()) {
				peer.getOutputStream().write(greeting.getBytes(StandardCharsets.UTF_8));
				assertThrows(SocketTimeoutException.class, () -> readSocketHandshake(client, 250));
			}
		}
	}

	@Test
	public void trickleTrafficCannotRenewTheHandshakeBudget() throws Exception {
		try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
				Socket client = new Socket(server.getInetAddress(), server.getLocalPort());
				Socket peer = server.accept()) {
			Thread sender = Thread.ofVirtual().start(() -> {
				try {
					for (int i = 0; i < 100; i++) {
						peer.getOutputStream().write('a');
						Thread.sleep(30);
					}
				} catch (InterruptedException ex) {
					Thread.currentThread().interrupt();
				} catch (IOException ignored) {
					// The peer may close when the read budget expires.
				}
			});
			try {
				long start = System.nanoTime();
				assertThrows(SocketTimeoutException.class, () -> readSocketHandshake(client, 300));
				assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(2));
			} finally {
				sender.interrupt();
				sender.join(2000);
			}
		}
	}


	@Test
	public void queuedResolutionExpiresWithoutFreeingTheRunningResolverSlot() throws Throwable {
		CountDownLatch entered = new CountDownLatch(1);
		CountDownLatch release = new CountDownLatch(1);
		BiFunction<String, Integer, InetSocketAddress> stubbornResolver = (host, port) -> {
			entered.countDown();
			for (;;) {
				try {
					release.await();
					return new InetSocketAddress(InetAddress.getLoopbackAddress(), port);
				} catch (InterruptedException ignored) {
					// Model a native resolver that ignores interruption.
				}
			}
		};
		var constructor = VoteForwarder.class.getDeclaredConstructor(VoteReceiver.class, int.class, BiFunction.class);
		constructor.setAccessible(true);
		VoteForwarder forwarder = constructor.newInstance(null, 1, stubbornResolver);
		var resolverField = VoteForwarder.class.getDeclaredField("resolver");
		resolverField.setAccessible(true);
		var resolver = (ThreadPoolExecutor) resolverField.get(forwarder);
		Method resolve = VoteForwarder.class.getDeclaredMethod("resolve", ForwardServer.class, long.class);
		resolve.setAccessible(true);
		Method stop = VoteForwarder.class.getDeclaredMethod("stop");
		stop.setAccessible(true);
		var target = new ForwardServer(true, "example.test", 1234, "", null);
		try {
			assertThrows(TimeoutException.class, () -> call(resolve, forwarder, target,
					System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(300)));
			assertTrue(entered.await(1, TimeUnit.SECONDS));
			assertEquals(1, resolver.getActiveCount());
			var queued = new FutureTask<Void>(() -> {
				assertThrows(TimeoutException.class, () -> call(resolve, forwarder, target,
						System.nanoTime() + TimeUnit.SECONDS.toNanos(1)));
				return null;
			});
			Thread.ofVirtual().start(queued);
			long waitUntil = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(500);
			while (resolver.getQueue().isEmpty() && System.nanoTime() < waitUntil) {
				Thread.sleep(1);
			}
			assertEquals(1, resolver.getQueue().size());
			assertThrows(RejectedExecutionException.class, () -> call(resolve, forwarder, target,
					System.nanoTime() + TimeUnit.SECONDS.toNanos(1)));
			queued.get(2, TimeUnit.SECONDS);
			assertEquals(0, resolver.getQueue().size());
			var forced = new FutureTask<Void>(() -> {
				assertThrows(CancellationException.class, () -> call(resolve, forwarder, target,
						System.nanoTime() + TimeUnit.SECONDS.toNanos(4)));
				return null;
			});
			Thread.ofVirtual().start(forced);
			waitUntil = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(500);
			while (resolver.getQueue().isEmpty() && System.nanoTime() < waitUntil) {
				Thread.sleep(1);
			}
			assertEquals(1, resolver.getQueue().size());
			call(stop, forwarder);
			forced.get(2, TimeUnit.SECONDS);
			assertEquals(0, resolver.getQueue().size());
			assertTrue(resolver.isShutdown());
			assertTrue(!resolver.isTerminated());
		} finally {
			release.countDown();
			call(stop, forwarder);
			assertTrue(resolver.awaitTermination(2, TimeUnit.SECONDS));
		}
	}

	@Test
	public void forwardingPreservesAuthenticatedAndLegacyWirePayloads() throws Exception {
		var signingKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
		var rsa = KeyPairGenerator.getInstance("RSA");
		rsa.initialize(2048);
		var pair = rsa.generateKeyPair();
		var vote = new Vote("example.test", "TestVoter", "127.0.0.1", "TestTimestamp");
		for (boolean authenticated : new boolean[] {false, true}) {
			try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
				server.setSoTimeout(2000);
				var target = new ForwardServer(true, server.getInetAddress().getHostAddress(), server.getLocalPort(),
						Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()), authenticated ? signingKey : null);
				var settings = new VoteReceiver.Settings("127.0.0.1", 0, "test", true, true, null,
						Map.of(), Set.of(), null, Map.of("test", target));
				var receiver = VoteReceiver.bind(settings, Logger.getAnonymousLogger(), accepted -> {});
				var peerResult = new FutureTask<byte[]>(() -> {
					try (Socket peer = server.accept()) {
						peer.setSoTimeout(3000);
						var greeting = authenticated ? "VOTIFIER 2 challenge-é\r\n" : "VOTIFIER 1\r\n";
						peer.getOutputStream().write(greeting.getBytes(StandardCharsets.UTF_8));
						return peer.getInputStream().readAllBytes();
					}
				});
				Thread.ofVirtual().start(peerResult);
				try {
					new VoteForwarder(receiver).forwardVote(vote);
					byte[] received = peerResult.get(4, TimeUnit.SECONDS);
					if (authenticated) {
						var body = new String(received, StandardCharsets.UTF_8);
						assertTrue(body.endsWith("\r\n"));
						JsonObject envelope = JsonParser.parseString(body).getAsJsonObject();
						String payload = envelope.get("payload").getAsString();
						assertEquals("{\"serviceName\":\"example.test\",\"username\":\"TestVoter\","
								+ "\"address\":\"127.0.0.1\",\"timestamp\":\"TestTimestamp\",\"challenge\":\"challenge-é\"}", payload);
						Mac mac = Mac.getInstance("HmacSHA256");
						mac.init(signingKey);
						assertEquals(Base64.getEncoder().encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8))),
								envelope.get("signature").getAsString());
					} else {
						Cipher cipher = Cipher.getInstance("RSA");
						cipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());
						assertEquals("VOTE\nexample.test\nTestVoter\n127.0.0.1\nTestTimestamp\n\n",
								new String(cipher.doFinal(received), StandardCharsets.UTF_8));
					}
				} finally {
					receiver.shutdown();
				}
			}
		}
	}

	@Test
	public void separateJvmUsesSocksWithoutConnectingToTheTargetDirectly() throws Exception {
		checkSocks(false);
	}

	@Test
	public void delayedResolutionAndStalledSocksGreetingShareOneBudget() throws Exception {
		checkSocks(true);
	}

	private static void checkSocks(boolean stallGreeting) throws Exception {
		InetAddress loopback = InetAddress.getByName("127.0.0.1");
		try (ServerSocket proxy = new ServerSocket(0, 1, loopback);
				ServerSocket directSentinel = new ServerSocket(0, 1, loopback)) {
			proxy.setSoTimeout(7000);
			directSentinel.setSoTimeout(200);
			String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
			String classpath = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
			Process child = new ProcessBuilder(java, "-DsocksProxyHost=127.0.0.1",
					"-DsocksProxyPort=" + proxy.getLocalPort(), "-DsocksNonProxyHosts=", "-cp", classpath,
					SocksClient.class.getName(), Integer.toString(directSentinel.getLocalPort()), Boolean.toString(stallGreeting))
					.redirectErrorStream(true).start();
			try (Socket peer = proxy.accept()) {
				peer.setSoTimeout(3000);
				var in = new DataInputStream(peer.getInputStream());
				var out = peer.getOutputStream();
				assertEquals(5, in.readUnsignedByte());
				int methods = in.readUnsignedByte();
				in.readNBytes(methods);
				out.write(new byte[] {5, 0});
				assertEquals(5, in.readUnsignedByte());
				assertEquals(1, in.readUnsignedByte());
				assertEquals(0, in.readUnsignedByte());
				assertEquals(1, in.readUnsignedByte());
				assertEquals("127.0.0.1", InetAddress.getByAddress(in.readNBytes(4)).getHostAddress());
				assertEquals(directSentinel.getLocalPort(), in.readUnsignedShort());
				out.write(new byte[] {5, 0, 0, 1, 127, 0, 0, 1, 0, 0});
				if (stallGreeting) {
					peer.setSoTimeout(2600);
					out.write("VOTIFIER 2 ".getBytes(StandardCharsets.UTF_8));
					assertEquals(-1, in.read(), "The resolver delay must consume the greeting budget");
				} else {
					out.write("VOTIFIER 2 challenge\r\n".getBytes(StandardCharsets.UTF_8));
					String received = new String(in.readAllBytes(), StandardCharsets.UTF_8);
					assertTrue(received.contains("TestVoter"));
					assertTrue(received.endsWith("\r\n"));
				}
				assertThrows(SocketTimeoutException.class, directSentinel::accept);
				assertTrue(child.waitFor(5, TimeUnit.SECONDS));
				assertEquals(0, child.exitValue(), () -> {
					try {
						return new String(child.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
					} catch (IOException ex) {
						return ex.toString();
					}
				});
			} finally {
				if (child.isAlive()) {
					child.destroyForcibly();
					child.waitFor(2, TimeUnit.SECONDS);
				}
			}
		}
	}

	@Test
	public void writeBackpressureExpiresAndClosesTheRealSocket() throws Exception {
		InetAddress loopback = InetAddress.getByName("127.0.0.1");
		try (ServerSocket backend = new ServerSocket(0, 1, loopback)) {
			backend.setReceiveBufferSize(4096);
			backend.setSoTimeout(3000);
			var signingKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
			var target = new ForwardServer(true, "127.0.0.1", backend.getLocalPort(), "", signingKey);
			var settings = new VoteReceiver.Settings("127.0.0.1", 0, "test", true, true, null,
					Map.of(), Set.of(), null, Map.of("test", target));
			var receiver = VoteReceiver.bind(settings, Logger.getAnonymousLogger(), ignored -> {});
			var writing = new CountDownLatch(1);
			Socket smallBuffer = new Socket() {
				@Override
				public OutputStream getOutputStream() throws IOException {
					return new FilterOutputStream(super.getOutputStream()) {
						@Override
						public void write(byte[] payload) throws IOException {
							writing.countDown();
							out.write(payload);
						}
					};
				}
			};
			smallBuffer.setSendBufferSize(4096);
			VoteForwarder forwarder = forwarderWithSockets(receiver, () -> smallBuffer);
			int submittedBytes = 4 * 1024 * 1024;
			Thread sender = Thread.ofVirtual().start(() -> forwarder.forwardVote(
					new Vote("example.test", "TestVoter", "A".repeat(submittedBytes), "TestTimestamp")));
			try (Socket peer = backend.accept()) {
				peer.getOutputStream().write("VOTIFIER 2 challenge\n".getBytes(StandardCharsets.UTF_8));
				assertTrue(writing.await(3, TimeUnit.SECONDS));
				sender.join(7000);
				assertFalse(sender.isAlive());
				assertTrue(smallBuffer.isClosed());
				peer.setSoTimeout(2000);
				byte[] partial = peer.getInputStream().readAllBytes();
				assertTrue(partial.length > 0 && partial.length < submittedBytes,
						"Peer observed an incomplete write after backpressure");
			} finally {
				stopForTest(forwarder);
				receiver.shutdown();
				sender.join(2000);
			}
		}
	}

	@Test
	public void aBlockedCloseRetainsCapacityWithoutBlockingOtherExpirations() throws Throwable {
		var blocked = new CountDownLatch(1);
		var release = new CountDownLatch(1);
		var fastClosed = new CountDownLatch(1);
		var slowCloses = new AtomicInteger();
		var quickCloses = new AtomicInteger();
		var socketCounter = new AtomicInteger();
		VoteForwarder forwarder = forwarderWithSockets(null, () -> {
			boolean slow = socketCounter.getAndIncrement() == 0;
			return new Socket() {
				@Override
				public void close() throws IOException {
					if (slow) {
						slowCloses.incrementAndGet();
						blocked.countDown();
						try {
							release.await(4, TimeUnit.SECONDS);
						} catch (InterruptedException ex) {
							Thread.currentThread().interrupt();
						}
					} else {
						quickCloses.incrementAndGet();
					}
					super.close();
					if (!slow) {
						fastClosed.countDown();
					}
				}
			};
		});
		Method register = attemptRegistration();
		Method terminated = VoteForwarder.class.getDeclaredMethod("isTerminated");
		terminated.setAccessible(true);
		try {
			call(register, forwarder, origin(register, "DIRECT"), "direct", System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(200));
			assertTrue(blocked.await(2, TimeUnit.SECONDS));
			assertThrows(RejectedExecutionException.class, () -> call(register, forwarder, origin(register, "DIRECT"), "direct",
					System.nanoTime() + TimeUnit.SECONDS.toNanos(1)));
			call(register, forwarder, origin(register, "INITIAL"), "runtime", System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(200));
			assertTrue(fastClosed.await(2, TimeUnit.SECONDS));
			stopForTest(forwarder);
			assertFalse((boolean) call(terminated, forwarder));
			assertEquals(1, slowCloses.get());
			assertEquals(1, quickCloses.get());
		} finally {
			release.countDown();
			stopForTest(forwarder);
		}
		long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
		while (!(boolean) call(terminated, forwarder) && System.nanoTime() < deadline) {
			Thread.sleep(1);
		}
		assertTrue((boolean) call(terminated, forwarder));
	}

	@Test
	public void queuedRuntimeCallCanDrainWhileDirectConnectHookSurvivesStop() throws Throwable {
		var stalled = new CountDownLatch(1);
		var release = new CountDownLatch(1);
		var writes = new ByteArrayOutputStream();
		var socketCount = new AtomicInteger();
		var target = new ForwardServer(true, "127.0.0.1", 1234, "",
				KeyGenerator.getInstance("HmacSHA256").generateKey());
		var settings = new VoteReceiver.Settings("127.0.0.1", 0, "test", true, true, null,
				Map.of(), Set.of(), null, Map.of("test", target));
		var receiver = VoteReceiver.bind(settings, Logger.getAnonymousLogger(), ignored -> {});
		var forwarder = forwarderWithSockets(receiver, () -> {
			boolean direct = socketCount.getAndIncrement() == 0;
			return new Socket() {
				@Override
				public void connect(SocketAddress destination, int timeout) throws IOException {
					if (direct) {
						stalled.countDown();
						try {
							release.await(10, TimeUnit.SECONDS);
						} catch (InterruptedException ex) {
							Thread.currentThread().interrupt();
						}
						throw new IOException("synthetic non-cooperative connect hook");
					}
				}

				@Override
				public InputStream getInputStream() {
					return new ByteArrayInputStream("VOTIFIER 2 challenge\r\n".getBytes(StandardCharsets.UTF_8));
				}

				@Override
				public OutputStream getOutputStream() {
					return writes;
				}
			};
		});
		Method seal = VoteForwarder.class.getDeclaredMethod("sealDirectCalls");
		seal.setAccessible(true);
		Method queued = VoteForwarder.class.getDeclaredMethod("forwardQueuedVote", Vote.class);
		queued.setAccessible(true);
		Method terminated = VoteForwarder.class.getDeclaredMethod("isTerminated");
		terminated.setAccessible(true);
		var vote = new Vote("example.test", "TestVoter", "", "TestTimestamp");
		Thread direct = Thread.ofVirtual().start(() -> forwarder.forwardVote(vote));
		try {
			assertTrue(stalled.await(2, TimeUnit.SECONDS));
			call(seal, forwarder);
			forwarder.forwardVote(vote);
			assertEquals(1, socketCount.get());
			call(queued, forwarder, vote);
			assertEquals(2, socketCount.get());
			assertTrue(writes.toString(StandardCharsets.UTF_8).contains("TestVoter"));
			stopForTest(forwarder);
			assertTrue(direct.isAlive());
			assertFalse((boolean) call(terminated, forwarder));
		} finally {
			release.countDown();
			direct.join(2000);
			stopForTest(forwarder);
			receiver.shutdown();
		}
		assertFalse(direct.isAlive());
		long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
		while (!(boolean) call(terminated, forwarder) && System.nanoTime() < deadline) {
			Thread.sleep(1);
		}
		assertTrue((boolean) call(terminated, forwarder));
	}

	@Test
	public void failedCloseFencesRetirementAndKeepsOneCloseOwner() throws Throwable {
		var closeCalled = new CountDownLatch(1);
		var closeCalls = new AtomicInteger();
		var settings = new VoteReceiver.Settings("127.0.0.1", 0, "test", true, true, null,
				Map.of(), Set.of(), null, Map.of());
		var receiver = VoteReceiver.bind(settings, Logger.getAnonymousLogger(), ignored -> {});
		var forwarder = forwarderWithSockets(receiver, () -> new Socket() {
			@Override
			public void close() throws IOException {
				closeCalls.incrementAndGet();
				closeCalled.countDown();
				throw new IOException("synthetic close failure");
			}
		});
		Method register = attemptRegistration();
		Method terminated = VoteForwarder.class.getDeclaredMethod("isTerminated");
		terminated.setAccessible(true);
		try {
			Object attempt = call(register, forwarder, origin(register, "DIRECT"), "test", System.nanoTime() + TimeUnit.SECONDS.toNanos(4));
			Method expire = VoteForwarder.class.getDeclaredMethod("expire", attempt.getClass());
			expire.setAccessible(true);
			var release = new CountDownLatch(1);
			var expiry = new FutureTask<Void>(() -> {
				release.await(2, TimeUnit.SECONDS);
				expire.invoke(forwarder, attempt);
				return null;
			});
			Thread.ofVirtual().start(expiry);
			release.countDown();
			stopForTest(forwarder);
			expiry.get(2, TimeUnit.SECONDS);
			assertTrue(closeCalled.await(2, TimeUnit.SECONDS));
			for (String poolName : new String[] {"closers", "resolver", "deadlines"}) {
				var field = VoteForwarder.class.getDeclaredField(poolName);
				field.setAccessible(true);
				assertTrue(((java.util.concurrent.ExecutorService) field.get(forwarder)).awaitTermination(2, TimeUnit.SECONDS));
			}
			assertEquals(1, closeCalls.get());
			assertFalse((boolean) call(terminated, forwarder), "A failed close permanently fences retirement");
		} finally {
			stopForTest(forwarder);
			receiver.shutdown();
		}
	}

	@Test
	public void normalCompletionReportsSuccessOnlyWhenItWinsBeforeExpiryOrStop() throws Throwable {
		for (String winner : new String[] {"completion", "expiry", "worker-expiry", "stop"}) {
			var writing = new CountDownLatch(1);
			var release = new CountDownLatch(1);
			var closes = new AtomicInteger();
			var successes = new AtomicInteger();
			var logger = Logger.getAnonymousLogger();
			logger.setUseParentHandlers(false);
			logger.setLevel(Level.ALL);
			logger.addHandler(new Handler() {
				@Override
				public void publish(LogRecord record) {
					if (record.getMessage().startsWith("Payload forwarded")) {
						successes.incrementAndGet();
					}
				}
				@Override public void flush() {}
				@Override public void close() {}
			});
			var destination = new ForwardServer(true, "127.0.0.1", 1234, "",
					KeyGenerator.getInstance("HmacSHA256").generateKey());
			var settings = new VoteReceiver.Settings("127.0.0.1", 0, "test", true, true, null,
					Map.of(), Set.of(), null, Map.of("test", destination));
			var receiver = VoteReceiver.bind(settings, logger, ignored -> {});
			var forwarder = forwarderWithSockets(receiver, () -> new Socket() {
				@Override public void connect(SocketAddress address, int timeout) {}

				@Override
				public InputStream getInputStream() {
					return new ByteArrayInputStream("VOTIFIER 2 challenge\r\n".getBytes(StandardCharsets.UTF_8));
				}

				@Override
				public OutputStream getOutputStream() {
					return new ByteArrayOutputStream() {
						@Override
						public void flush() throws IOException {
							writing.countDown();
							try {
								if (!release.await(8, TimeUnit.SECONDS)) {
									throw new IOException("test flush was not released");
								}
							} catch (InterruptedException ex) {
								Thread.currentThread().interrupt();
								throw new IOException(ex);
							}
						}
					};
				}

				@Override
				public void close() throws IOException {
					closes.incrementAndGet();
					super.close();
				}
			});
			var timerRelease = new CountDownLatch(1);
			if (winner.equals("worker-expiry")) {
				var timerEntered = new CountDownLatch(1);
				var schedulerField = VoteForwarder.class.getDeclaredField("deadlines");
				schedulerField.setAccessible(true);
				var scheduler = (java.util.concurrent.ScheduledThreadPoolExecutor) schedulerField.get(forwarder);
				scheduler.execute(() -> {
					timerEntered.countDown();
					try {
						timerRelease.await(8, TimeUnit.SECONDS);
					} catch (InterruptedException ex) {
						Thread.currentThread().interrupt();
					}
				});
				assertTrue(timerEntered.await(2, TimeUnit.SECONDS));
			}
			var sender = new FutureTask<Void>(() -> {
				forwarder.forwardVote(new Vote("example.test", "TestVoter", "", "TestTimestamp"));
				return null;
			});
			Thread.ofVirtual().start(sender);
			try {
				assertTrue(writing.await(2, TimeUnit.SECONDS));
				if (winner.equals("expiry")) {
					var attempts = VoteForwarder.class.getDeclaredField("attempts");
					attempts.setAccessible(true);
					var lock = VoteForwarder.class.getDeclaredField("lifecycleLock");
					lock.setAccessible(true);
					synchronized (lock.get(forwarder)) {
						Object attempt = ((Set<?>) attempts.get(forwarder)).iterator().next();
						Method expire = VoteForwarder.class.getDeclaredMethod("expire", attempt.getClass());
						expire.setAccessible(true);
						call(expire, forwarder, attempt);
					}
				} else if (winner.equals("worker-expiry")) {
					Thread.sleep(5100);
				} else if (winner.equals("stop")) {
					stopForTest(forwarder);
				}
				release.countDown();
				sender.get(2, TimeUnit.SECONDS);
				stopForTest(forwarder);
				var closerField = VoteForwarder.class.getDeclaredField("closers");
				closerField.setAccessible(true);
				assertTrue(((ThreadPoolExecutor) closerField.get(forwarder)).awaitTermination(2, TimeUnit.SECONDS));
				assertEquals(1, closes.get());
				assertEquals(winner.equals("completion") ? 1 : 0, successes.get());
				var expired = VoteForwarder.class.getDeclaredField("expiredAttempts");
				expired.setAccessible(true);
				assertEquals(winner.endsWith("expiry") ? 1L : 0L, expired.getLong(forwarder));
			} finally {
				timerRelease.countDown();
				release.countDown();
				stopForTest(forwarder);
				receiver.shutdown();
			}
		}
	}

	@Test
	public void expirationDuringSocketRegistrationIsCountedAndClosedOnce() throws Throwable {
		var closes = new AtomicInteger();
		var cutoff = new java.util.concurrent.atomic.AtomicLong();
		var forwarder = forwarderWithSockets(null, () -> {
			while (cutoff.get() - System.nanoTime() > 0) {
				java.util.concurrent.locks.LockSupport.parkNanos(cutoff.get() - System.nanoTime());
			}
			return new Socket() {
				@Override
				public void close() throws IOException {
					closes.incrementAndGet();
					super.close();
				}
			};
		});
		Method register = attemptRegistration();
		var expired = VoteForwarder.class.getDeclaredField("expiredAttempts");
		expired.setAccessible(true);
		var closer = VoteForwarder.class.getDeclaredField("closers");
		closer.setAccessible(true);
		try {
			cutoff.set(System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(500));
			assertThrows(SocketTimeoutException.class, () -> call(register, forwarder, origin(register, "INITIAL"), "runtime", cutoff.get()));
		} finally {
			stopForTest(forwarder);
		}
		assertTrue(((ThreadPoolExecutor) closer.get(forwarder)).awaitTermination(2, TimeUnit.SECONDS));
		assertEquals(1L, expired.getLong(forwarder));
		assertEquals(1, closes.get());
	}

	@Test
	public void shutdownCannotOvertakeAReservedSocketBeforeRegistration() throws Exception {
		var allocating = new CountDownLatch(1);
		var release = new CountDownLatch(1);
		var closed = new CountDownLatch(1);
		var closes = new AtomicInteger();
		var forwarder = forwarderWithSockets(null, () -> {
			allocating.countDown();
			try {
				release.await(3, TimeUnit.SECONDS);
			} catch (InterruptedException ex) {
				Thread.currentThread().interrupt();
			}
			return new Socket() {
				@Override
				public void close() throws IOException {
					closes.incrementAndGet();
					super.close();
					closed.countDown();
				}
			};
		});
		Method register = attemptRegistration();
		var registration = new FutureTask<>(() -> register.invoke(forwarder, origin(register, "INITIAL"), "runtime",
				System.nanoTime() + TimeUnit.SECONDS.toNanos(4)));
		var stopping = new FutureTask<Void>(() -> {
			stopForTest(forwarder);
			return null;
		});
		Thread.ofVirtual().start(registration);
		try {
			assertTrue(allocating.await(2, TimeUnit.SECONDS));
			Thread stopper = Thread.ofPlatform().daemon().start(stopping);
			long waitUntil = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
			while (stopper.getState() != Thread.State.BLOCKED && System.nanoTime() < waitUntil) {
				Thread.sleep(1);
			}
			assertEquals(Thread.State.BLOCKED, stopper.getState());
			assertTrue(java.util.Arrays.stream(stopper.getStackTrace())
					.anyMatch(frame -> frame.getClassName().equals(VoteForwarder.class.getName())
							&& frame.getMethodName().equals("stop")));
			release.countDown();
			registration.get(2, TimeUnit.SECONDS);
			stopping.get(2, TimeUnit.SECONDS);
			assertTrue(closed.await(2, TimeUnit.SECONDS));
			assertEquals(1, closes.get());
		} finally {
			release.countDown();
			stopForTest(forwarder);
		}
	}

	private static Method attemptRegistration() throws ReflectiveOperationException {
		Class<?> origin = Class.forName(VoteForwarder.class.getName() + "$Origin");
		Method method = VoteForwarder.class.getDeclaredMethod("registerAttempt", origin, String.class, long.class);
		method.setAccessible(true);
		return method;
	}

	private static Object origin(Method method, String name) {
		for (Object constant : method.getParameterTypes()[0].getEnumConstants()) {
			if (((Enum<?>) constant).name().equals(name)) {
				return constant;
			}
		}
		throw new AssertionError("Unknown forwarding origin: " + name);
	}

	private static VoteForwarder forwarderWithSockets(VoteReceiver receiver, Supplier<Socket> sockets) throws Exception {
		var constructor = VoteForwarder.class.getDeclaredConstructor(VoteReceiver.class, int.class,
				BiFunction.class, Supplier.class);
		constructor.setAccessible(true);
		BiFunction<String, Integer, InetSocketAddress> resolve = InetSocketAddress::new;
		return constructor.newInstance(receiver, 1, resolve, sockets);
	}

	private static void stopForTest(VoteForwarder forwarder) throws Exception {
		Method stop = VoteForwarder.class.getDeclaredMethod("stop");
		stop.setAccessible(true);
		stop.invoke(forwarder);
	}

	public static final class SocksClient {
		public static void main(String[] arguments) throws Exception {
			var signingKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
			var target = new ForwardServer(true, "127.0.0.1", Integer.parseInt(arguments[0]), "", signingKey);
			var settings = new VoteReceiver.Settings("127.0.0.1", 0, "test", true, true, null,
					Map.of(), Set.of(), null, Map.of("test", target));
			var receiver = VoteReceiver.bind(settings, Logger.getAnonymousLogger(), accepted -> {});
			VoteForwarder forwarder;
			if (Boolean.parseBoolean(arguments[1])) {
				var constructor = VoteForwarder.class.getDeclaredConstructor(VoteReceiver.class, int.class, BiFunction.class);
				constructor.setAccessible(true);
				BiFunction<String, Integer, InetSocketAddress> delayed = (host, port) -> {
					try {
						Thread.sleep(3700);
					} catch (InterruptedException ex) {
						Thread.currentThread().interrupt();
					}
					return new InetSocketAddress(host, port);
				};
				forwarder = constructor.newInstance(receiver, 1, delayed);
			} else {
				forwarder = new VoteForwarder(receiver);
			}
			try {
				forwarder.forwardVote(new Vote("example.test", "TestVoter", "", "TestTimestamp"));
			} finally {
				stopForTest(forwarder);
				receiver.shutdown();
			}
		}
	}

	private static Object call(Method method, Object receiver, Object... arguments) throws Throwable {
		try {
			return method.invoke(receiver, arguments);
		} catch (InvocationTargetException failure) {
			throw failure.getCause();
		}
	}

	private static void readSocketHandshake(Socket socket, int timeoutMillis) throws Throwable {
		Method parser = VoteForwarder.class.getDeclaredMethod("readSocketGreeting", Socket.class, long.class);
		parser.setAccessible(true);
		call(parser, null, socket, System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis));
	}
}
