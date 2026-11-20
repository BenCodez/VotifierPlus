package com.bencodez.votifierplus.tests.net;

import com.vexsoftware.votifier.net.VoteForwarder;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.StringReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.FutureTask;
import java.util.function.BiFunction;
import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.net.VoteReceiver;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
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
					SocketChannel client = SocketChannel.open(new InetSocketAddress(server.getInetAddress(), server.getLocalPort()));
					Socket peer = server.accept()) {
				peer.getOutputStream().write(greeting.getBytes(StandardCharsets.UTF_8));
				assertThrows(SocketTimeoutException.class, () -> readSocketHandshake(client, 250));
			}
		}
	}

	@Test
	public void trickleTrafficCannotRenewTheHandshakeBudget() throws Exception {
		try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
				SocketChannel client = SocketChannel.open(new InetSocketAddress(server.getInetAddress(), server.getLocalPort()));
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
	public void stalledPayloadWriteExpiresAfterPartialProgress() throws Exception {
		try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
				SocketChannel client = SocketChannel.open(new InetSocketAddress(server.getInetAddress(), server.getLocalPort()));
				Socket peer = server.accept();
				Selector selector = Selector.open()) {
			client.socket().setSendBufferSize(4096);
			client.configureBlocking(false);
			Method write = VoteForwarder.class.getDeclaredMethod("writePayload",
					SocketChannel.class, Selector.class, byte[].class, long.class);
			write.setAccessible(true);
			assertThrows(SocketTimeoutException.class, () -> call(write, null, client, selector,
					new byte[4 * 1024 * 1024], System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(300)));
			peer.setSoTimeout(1000);
			assertEquals(0, peer.getInputStream().read());
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
			call(stop, forwarder);
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

	private static Object call(Method method, Object receiver, Object... arguments) throws Throwable {
		try {
			return method.invoke(receiver, arguments);
		} catch (InvocationTargetException failure) {
			throw failure.getCause();
		}
	}

	private static void readSocketHandshake(SocketChannel channel, int timeoutMillis) throws Throwable {
		Method parser = VoteForwarder.class.getDeclaredMethod("readChannelGreeting",
				SocketChannel.class, Selector.class, long.class);
		parser.setAccessible(true);
		channel.configureBlocking(false);
		try (Selector selector = Selector.open()) {
			parser.invoke(null, channel, selector, System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis));
		} catch (InvocationTargetException failure) {
			throw failure.getCause();
		}
	}
}
