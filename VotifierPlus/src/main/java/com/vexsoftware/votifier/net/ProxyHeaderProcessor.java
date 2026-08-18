/*
 * Derived from original Votifier VoteReceiver (GPLv3).
 * Refactored into a dedicated component by BenCodez.
 *
 * See VoteReceiver for full modification summary.
 */
package com.vexsoftware.votifier.net;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.PushbackInputStream;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

import lombok.Getter;
import lombok.Setter;

public class ProxyHeaderProcessor {

	private static final int MAX_PROXY_V1_HEADER_BYTES = 107;
	private static final int MAX_CONNECT_LINE_BYTES = 8192;
	private static final int MAX_CONNECT_HEADERS = 100;
	private static final int MAX_CONNECT_HEADER_BYTES = 32768;
	private static final int HEADER_READ_TIMEOUT_MILLIS = 5000;
	private static final int DISCARD_BUFFER_BYTES = 1024;

	private static final byte[] PROXY_V1_PREFIX = "PROXY".getBytes(StandardCharsets.US_ASCII);
	private static final byte[] CONNECT_PREFIX = "CONNECT".getBytes(StandardCharsets.US_ASCII);
	private static final byte[] PROXY_V2_SIGNATURE = new byte[] { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55,
			0x49, 0x54, 0x0A };

	@Getter
	@Setter
	public static class ProxyHeaderResult {
		private String realIp;
	}

	public ProxyHeaderResult process(PushbackInputStream in, BufferedWriter writer, VoteReceiver receiver)
			throws Exception {
		return process(in, writer, receiver, null);
	}

	public ProxyHeaderResult process(PushbackInputStream in, BufferedWriter writer, VoteReceiver receiver, Socket socket)
			throws Exception {
		int previousTimeout = socket == null ? 0 : socket.getSoTimeout();
		long deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(HEADER_READ_TIMEOUT_MILLIS);

		try {
			return processWithDeadline(in, writer, receiver, socket, deadlineNanos);
		} finally {
			if (socket != null && !socket.isClosed()) {
				try {
					socket.setSoTimeout(previousTimeout);
				} catch (SocketException ex) {
					receiver.debug(ex);
				}
			}
		}
	}

	private ProxyHeaderResult processWithDeadline(PushbackInputStream in, BufferedWriter writer, VoteReceiver receiver,
			Socket socket, long deadlineNanos) throws Exception {
		ProxyHeaderResult result = new ProxyHeaderResult();
		byte[] prefix = new byte[16];
		int bytesRead = readPrefix(in, prefix, 1, socket, deadlineNanos);
		if (bytesRead == 0) {
			return result;
		}

		if (prefix[0] == PROXY_V1_PREFIX[0]) {
			bytesRead = readPrefix(in, prefix, PROXY_V1_PREFIX.length, bytesRead, socket, deadlineNanos);
			if (bytesRead == PROXY_V1_PREFIX.length && startsWith(prefix, bytesRead, PROXY_V1_PREFIX)) {
				in.unread(prefix, 0, bytesRead);
				String proxyHeader = readLine(in, socket, deadlineNanos, MAX_PROXY_V1_HEADER_BYTES, null,
						"PROXY protocol v1 header exceeds " + MAX_PROXY_V1_HEADER_BYTES + " bytes");
				receiver.debug("Discarded PROXY (v1) header: " + proxyHeader);

				String[] parts = proxyHeader.split("\\s+");
				if (parts.length >= 3) {
					String srcIp = parts[2].trim();
					if (!srcIp.isEmpty()) {
						result.setRealIp(srcIp);
					}
				}
				return result;
			}
		}

		if (prefix[0] == CONNECT_PREFIX[0]) {
			bytesRead = readPrefix(in, prefix, CONNECT_PREFIX.length, bytesRead, socket, deadlineNanos);
			if (bytesRead == CONNECT_PREFIX.length && startsWith(prefix, bytesRead, CONNECT_PREFIX)) {
				in.unread(prefix, 0, bytesRead);
				int[] totalHeaderBytes = new int[1];
				String connectLine = readLine(in, socket, deadlineNanos, MAX_CONNECT_LINE_BYTES, totalHeaderBytes,
						"HTTP CONNECT header line exceeds " + MAX_CONNECT_LINE_BYTES + " bytes");
				receiver.debug("Received CONNECT request: " + connectLine);

				int headerCount = 0;
				while (true) {
					String line = readLine(in, socket, deadlineNanos, MAX_CONNECT_LINE_BYTES, totalHeaderBytes,
							"HTTP CONNECT header line exceeds " + MAX_CONNECT_LINE_BYTES + " bytes");
					if (line.isEmpty()) {
						break;
					}
					if (++headerCount > MAX_CONNECT_HEADERS) {
						throw new InvalidVoteException("Too many HTTP CONNECT headers");
					}
					receiver.debug("Discarding header: " + line);
				}

				writer.write("HTTP/1.1 200 Connection Established\r\n\r\n");
				writer.flush();
				return result;
			}
		}

		if ((prefix[0] & 0xFF) == (PROXY_V2_SIGNATURE[0] & 0xFF)) {
			bytesRead = readPrefix(in, prefix, 16, bytesRead, socket, deadlineNanos);
			if (bytesRead < 16 && matchesPrefix(prefix, bytesRead, PROXY_V2_SIGNATURE)) {
				throw new InvalidVoteException("Incomplete PROXY protocol v2 header");
			}
			if (bytesRead == 16 && startsWith(prefix, bytesRead, PROXY_V2_SIGNATURE)) {
				int addressLength = ((prefix[14] & 0xFF) << 8) | (prefix[15] & 0xFF);
				discardFully(in, addressLength, socket, deadlineNanos);
				receiver.debug("Discarded PROXY protocol v2 header (" + (16 + addressLength) + " bytes)");
				return result;
			}
		}

		in.unread(prefix, 0, bytesRead);
		return result;
	}

	private int readPrefix(PushbackInputStream in, byte[] prefix, int targetLength, Socket socket, long deadlineNanos)
			throws Exception {
		return readPrefix(in, prefix, targetLength, 0, socket, deadlineNanos);
	}

	private int readPrefix(PushbackInputStream in, byte[] prefix, int targetLength, int offset, Socket socket,
			long deadlineNanos) throws Exception {
		int read = offset;
		while (read < targetLength) {
			int value = readByteWithDeadline(in, socket, deadlineNanos);
			if (value == -1) {
				break;
			}
			prefix[read++] = (byte) value;
		}
		return read;
	}

	private void discardFully(PushbackInputStream in, int length, Socket socket, long deadlineNanos) throws Exception {
		byte[] discard = new byte[Math.min(DISCARD_BUFFER_BYTES, Math.max(1, length))];
		int remaining = length;
		while (remaining > 0) {
			int read = readWithDeadline(in, discard, 0, Math.min(discard.length, remaining), socket, deadlineNanos);
			if (read == -1) {
				throw new InvalidVoteException("Incomplete PROXY protocol v2 header");
			}
			remaining -= read;
		}
	}

	private String readLine(PushbackInputStream in, Socket socket, long deadlineNanos, int maxLineBytes,
			int[] totalBytes, String overflowMessage) throws Exception {
		ByteArrayOutputStream lineBuffer = new ByteArrayOutputStream(Math.min(128, maxLineBytes));
		int lineBytes = 0;

		while (true) {
			int value = readByteWithDeadline(in, socket, deadlineNanos);
			if (value == -1) {
				throw new InvalidVoteException("Unexpected end of stream while reading proxy/tunnel headers");
			}

			lineBytes++;
			if (lineBytes > maxLineBytes) {
				throw new InvalidVoteException(overflowMessage);
			}
			incrementTotalBytes(totalBytes);

			if (value == '\n') {
				break;
			}

			if (value == '\r') {
				int next = readByteWithDeadline(in, socket, deadlineNanos);
				if (next == -1) {
					throw new InvalidVoteException("Unexpected end of stream while reading proxy/tunnel headers");
				}

				lineBytes++;
				if (lineBytes > maxLineBytes) {
					throw new InvalidVoteException(overflowMessage);
				}
				incrementTotalBytes(totalBytes);

				if (next != '\n') {
					throw new InvalidVoteException("Invalid line ending in proxy/tunnel headers");
				}
				break;
			}

			lineBuffer.write(value);
		}

		return lineBuffer.toString(StandardCharsets.US_ASCII.name()).trim();
	}

	private void incrementTotalBytes(int[] totalBytes) throws InvalidVoteException {
		if (totalBytes != null && ++totalBytes[0] > MAX_CONNECT_HEADER_BYTES) {
			throw new InvalidVoteException("HTTP CONNECT headers exceed " + MAX_CONNECT_HEADER_BYTES + " bytes");
		}
	}

	private int readByteWithDeadline(PushbackInputStream in, Socket socket, long deadlineNanos) throws Exception {
		setRemainingTimeout(socket, deadlineNanos);
		return in.read();
	}

	private int readWithDeadline(PushbackInputStream in, byte[] buffer, int offset, int length, Socket socket,
			long deadlineNanos) throws Exception {
		setRemainingTimeout(socket, deadlineNanos);
		return in.read(buffer, offset, length);
	}

	private void setRemainingTimeout(Socket socket, long deadlineNanos) throws Exception {
		long remainingNanos = deadlineNanos - System.nanoTime();
		if (remainingNanos <= 0) {
			throw new SocketTimeoutException("Timed out reading proxy/tunnel headers");
		}

		if (socket != null) {
			long timeoutMillis = TimeUnit.NANOSECONDS.toMillis(remainingNanos);
			if (TimeUnit.MILLISECONDS.toNanos(timeoutMillis) < remainingNanos) {
				timeoutMillis++;
			}
			socket.setSoTimeout((int) Math.max(1L, Math.min(Integer.MAX_VALUE, timeoutMillis)));
		}
	}

	private boolean startsWith(byte[] data, int dataLength, byte[] expected) {
		return dataLength >= expected.length && matchesPrefix(data, expected.length, expected);
	}

	private boolean matchesPrefix(byte[] data, int dataLength, byte[] expected) {
		int length = Math.min(dataLength, expected.length);
		for (int i = 0; i < length; i++) {
			if (data[i] != expected[i]) {
				return false;
			}
		}
		return true;
	}
}
