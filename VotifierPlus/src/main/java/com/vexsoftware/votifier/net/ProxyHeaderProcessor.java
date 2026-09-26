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
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Set;
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
	private static final int PROXY_V2_IPV4_BYTES = 12;
	private static final int PROXY_V2_IPV6_BYTES = 36;

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
				requireTrustedPeer(receiver, socket);
				in.unread(prefix, 0, bytesRead);
				String proxyHeader = readLine(in, socket, deadlineNanos, MAX_PROXY_V1_HEADER_BYTES, null,
						"PROXY protocol v1 header exceeds " + MAX_PROXY_V1_HEADER_BYTES + " bytes", true);
				receiver.debug("Discarded PROXY (v1) header: " + proxyHeader);
				parseV1(proxyHeader, result);
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
				requireTrustedPeer(receiver, socket);
				int addressLength = ((prefix[14] & 0xFF) << 8) | (prefix[15] & 0xFF);
				parseV2(in, prefix, addressLength, socket, deadlineNanos, result);
				receiver.debug("Discarded PROXY protocol v2 header (" + (16 + addressLength) + " bytes)");
				return result;
			}
		}

		in.unread(prefix, 0, bytesRead);
		return result;
	}

	private void requireTrustedPeer(VoteReceiver receiver, Socket socket) throws InvalidVoteException {
		InetAddress peer = socket == null ? null : socket.getInetAddress();
		Set<String> configured = receiver.getTrustedProxyIps();
		if (peer != null && configured != null) {
			for (String literal : configured) {
				if (literal == null) {
					continue;
				}
				try {
					if (Arrays.equals(peer.getAddress(), IpLiteral.parse(literal.trim(), peer.getAddress().length == 4 ? 4 : 6))) {
						return;
					}
				} catch (InvalidVoteException ignored) {
					// Invalid configuration entries cannot grant trust.
				}
			}
		}
		throw new InvalidVoteException("PROXY protocol header from untrusted socket peer");
	}

	private void parseV1(String header, ProxyHeaderResult result) throws InvalidVoteException {
		String[] parts = header.split(" ", -1);
		if (parts.length >= 2 && "PROXY".equals(parts[0]) && "UNKNOWN".equals(parts[1])) {
			return;
		}
		if (parts.length != 6 || !"PROXY".equals(parts[0])) {
			throw new InvalidVoteException("Invalid PROXY protocol v1 header");
		}
		int family;
		if ("TCP4".equals(parts[1])) {
			family = 4;
		} else if ("TCP6".equals(parts[1])) {
			family = 6;
		} else {
			throw new InvalidVoteException("Unsupported PROXY protocol v1 family");
		}
		byte[] source = IpLiteral.parse(parts[2], family);
		IpLiteral.parse(parts[3], family);
		parsePort(parts[4]);
		parsePort(parts[5]);
		result.setRealIp(IpLiteral.format(source));
	}

	private void parsePort(String value) throws InvalidVoteException {
		if (value.isEmpty() || value.length() > 5) {
			throw new InvalidVoteException("Invalid PROXY port");
		}
		int port = 0;
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			if (c < '0' || c > '9') {
				throw new InvalidVoteException("Invalid PROXY port");
			}
			port = port * 10 + c - '0';
		}
		if (port > 65535) {
			throw new InvalidVoteException("Invalid PROXY port");
		}
	}

	private void parseV2(PushbackInputStream in, byte[] header, int length, Socket socket, long deadlineNanos,
			ProxyHeaderResult result) throws Exception {
		int versionCommand = header[12] & 0xFF;
		int familyTransport = header[13] & 0xFF;
		if ((versionCommand & 0xF0) != 0x20) {
			throw new InvalidVoteException("Invalid PROXY protocol v2 version");
		}
		int command = versionCommand & 0x0F;
		if (command == 0) {
			discardFully(in, length, socket, deadlineNanos);
			return;
		}
		if (command != 1) {
			throw new InvalidVoteException("Unsupported PROXY protocol v2 command");
		}
		if (familyTransport == 0) {
			discardFully(in, length, socket, deadlineNanos);
			return;
		}
		int addressBytes;
		int ipBytes;
		if (familyTransport == 0x11) {
			addressBytes = PROXY_V2_IPV4_BYTES;
			ipBytes = 4;
		} else if (familyTransport == 0x21) {
			addressBytes = PROXY_V2_IPV6_BYTES;
			ipBytes = 16;
		} else {
			throw new InvalidVoteException("Unsupported PROXY protocol v2 family or transport");
		}
		if (length < addressBytes) {
			throw new InvalidVoteException("Incomplete PROXY protocol v2 address block");
		}
		byte[] addresses = new byte[addressBytes];
		int read = 0;
		while (read < addressBytes) {
			int count = readWithDeadline(in, addresses, read, addressBytes - read, socket, deadlineNanos);
			if (count == -1) {
				throw new InvalidVoteException("Incomplete PROXY protocol v2 header");
			}
			read += count;
		}
		discardFully(in, length - addressBytes, socket, deadlineNanos);
		result.setRealIp(IpLiteral.format(Arrays.copyOf(addresses, ipBytes)));
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
		return readLine(in, socket, deadlineNanos, maxLineBytes, totalBytes, overflowMessage, false);
	}

	private String readLine(PushbackInputStream in, Socket socket, long deadlineNanos, int maxLineBytes,
			int[] totalBytes, String overflowMessage, boolean requireCrLf) throws Exception {
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
				if (requireCrLf) {
					throw new InvalidVoteException("PROXY protocol v1 header requires CRLF");
				}
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

		return lineBuffer.toString(StandardCharsets.US_ASCII.name());
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
