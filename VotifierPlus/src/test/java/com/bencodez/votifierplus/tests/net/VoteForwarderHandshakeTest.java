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
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
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

	private static void readSocketHandshake(Socket socket, int timeoutMillis) throws Throwable {
		Method parser = VoteForwarder.class.getDeclaredMethod("readHandshakeLine", Socket.class, int.class);
		parser.setAccessible(true);
		try {
			parser.invoke(null, socket, timeoutMillis);
		} catch (InvocationTargetException failure) {
			throw failure.getCause();
		}
	}
}
