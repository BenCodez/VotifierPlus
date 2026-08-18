package com.bencodez.votifierplus.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.io.PushbackInputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.model.Vote;
import com.vexsoftware.votifier.net.InvalidVoteException;
import com.vexsoftware.votifier.net.ProxyHeaderProcessor;
import com.vexsoftware.votifier.net.ThrottleConfig;
import com.vexsoftware.votifier.net.VoteReceiver;

/**
 * Regression tests for bounded PROXY and HTTP CONNECT parsing.
 */
public class ProxyHeaderProcessorSecurityTest {

	private static KeyPair testKeyPair;

	private ProxyHeaderProcessor processor;
	private StubVoteReceiver receiver;

	@BeforeAll
	public static void setupClass() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		testKeyPair = keyPairGenerator.generateKeyPair();
	}

	@BeforeEach
	public void setup() throws Exception {
		processor = new ProxyHeaderProcessor();
		receiver = new StubVoteReceiver("127.0.0.1", 0);
	}

	@AfterEach
	public void tearDown() {
		if (receiver != null) {
			receiver.shutdown();
		}
	}

	@Test
	public void testValidProxyV1HeaderPreservesVotePayload() throws Exception {
		String header = "PROXY TCP4 192.0.2.10 192.0.2.20 1234 8192\r\n";
		String payload = "VOTE\nsite\nuser\n127.0.0.1\ntimestamp\n";
		PushbackInputStream input = input(header + payload);

		ProxyHeaderProcessor.ProxyHeaderResult result = processor.process(input, writer(), receiver);

		assertEquals("192.0.2.10", result.getRealIp());
		assertEquals(payload, readRemaining(input));
	}

	@Test
	public void testProxyV1HeaderOver107BytesIsRejected() throws Exception {
		String oversized = "PROXY " + "A".repeat(100) + "\r\n";
		InvalidVoteException exception = assertThrows(InvalidVoteException.class,
				() -> processor.process(input(oversized), writer(), receiver));

		assertTrue(exception.getMessage().contains("exceeds 107 bytes"));
	}

	@Test
	public void testValidConnectHeadersPreserveVotePayload() throws Exception {
		String headers = "CONNECT vote.example:443 HTTP/1.1\r\nHost: vote.example:443\r\n\r\n";
		String payload = "VOTE\nsite\nuser\n127.0.0.1\ntimestamp\n";
		PushbackInputStream input = input(headers + payload);
		ByteArrayOutputStream response = new ByteArrayOutputStream();
		BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(response, StandardCharsets.US_ASCII));

		processor.process(input, writer, receiver);
		writer.flush();

		assertTrue(response.toString(StandardCharsets.US_ASCII).contains("200 Connection Established"));
		assertEquals(payload, readRemaining(input));
	}

	@Test
	public void testOversizedConnectRequestLineIsRejected() throws Exception {
		String oversized = "CONNECT " + "a".repeat(8185) + "\r\n";
		InvalidVoteException exception = assertThrows(InvalidVoteException.class,
				() -> processor.process(input(oversized), writer(), receiver));

		assertTrue(exception.getMessage().contains("line exceeds 8192 bytes"));
	}

	@Test
	public void testMoreThan100ConnectHeadersAreRejected() throws Exception {
		StringBuilder request = new StringBuilder("CONNECT vote.example:443 HTTP/1.1\r\n");
		for (int i = 0; i < 101; i++) {
			request.append("X-Test-").append(i).append(": value\r\n");
		}
		request.append("\r\n");

		InvalidVoteException exception = assertThrows(InvalidVoteException.class,
				() -> processor.process(input(request.toString()), writer(), receiver));

		assertTrue(exception.getMessage().contains("Too many HTTP CONNECT headers"));
	}

	@Test
	public void testConnectHeadersOver32KiBAreRejected() throws Exception {
		StringBuilder request = new StringBuilder("CONNECT vote.example:443 HTTP/1.1\r\n");
		for (int i = 0; i < 5; i++) {
			request.append("X-Test: ").append("a".repeat(7000)).append("\r\n");
		}
		request.append("\r\n");

		InvalidVoteException exception = assertThrows(InvalidVoteException.class,
				() -> processor.process(input(request.toString()), writer(), receiver));

		assertTrue(exception.getMessage().contains("headers exceed 32768 bytes"));
	}

	@Test
	public void testProxyV2ReadsUseDecreasingCumulativeTimeout() throws Exception {
		byte[] header = new byte[] { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
				0x21, 0x11, 0x00, 0x03, 0x01, 0x02, 0x03 };
		ByteArrayInputStream fragmented = new ByteArrayInputStream(header) {
			@Override
			public synchronized int read(byte[] bytes, int offset, int length) {
				if (pos >= 16) {
					try {
						Thread.sleep(25);
					} catch (InterruptedException ex) {
						Thread.currentThread().interrupt();
					}
				}
				return super.read(bytes, offset, Math.min(length, pos < 16 ? 16 : 1));
			}
		};
		PushbackInputStream input = new PushbackInputStream(fragmented, 512);
		RecordingSocket socket = new RecordingSocket();

		processor.process(input, writer(), receiver, socket);

		assertTrue(socket.getRecordedTimeouts().stream().anyMatch(timeout -> timeout < 5000));
		assertEquals(5000, socket.getRecordedTimeouts().get(socket.getRecordedTimeouts().size() - 1));
	}

	private PushbackInputStream input(String value) {
		return new PushbackInputStream(
				new ByteArrayInputStream(value.getBytes(StandardCharsets.US_ASCII)), 512);
	}

	private BufferedWriter writer() {
		return new BufferedWriter(new OutputStreamWriter(new ByteArrayOutputStream(), StandardCharsets.US_ASCII));
	}

	private String readRemaining(PushbackInputStream input) throws Exception {
		ByteArrayOutputStream remaining = new ByteArrayOutputStream();
		input.transferTo(remaining);
		return remaining.toString(StandardCharsets.US_ASCII);
	}

	private static class RecordingSocket extends Socket {

		private final List<Integer> recordedTimeouts = new ArrayList<>();
		private int timeout = 5000;

		@Override
		public int getSoTimeout() {
			return timeout;
		}

		@Override
		public void setSoTimeout(int timeout) {
			this.timeout = timeout;
			recordedTimeouts.add(timeout);
		}

		List<Integer> getRecordedTimeouts() {
			return recordedTimeouts;
		}
	}

	private static class StubVoteReceiver extends VoteReceiver {

		StubVoteReceiver(String host, int port) throws Exception {
			super(host, port);
		}

		@Override
		public boolean isUseTokens() {
			return false;
		}

		@Override
		public void logWarning(String warning) {
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
		public ThrottleConfig getThrottleConfig() {
			return null;
		}
	}
}
