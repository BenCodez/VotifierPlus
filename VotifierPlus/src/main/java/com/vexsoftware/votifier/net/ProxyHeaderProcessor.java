/*
 * Derived from original Votifier VoteReceiver (GPLv3).
 * Refactored into a dedicated component by BenCodez.
 *
 * See VoteReceiver for full modification summary.
 */
package com.vexsoftware.votifier.net;

import java.io.ByteArrayOutputStream;
import java.io.BufferedWriter;
import java.io.PushbackInputStream;
import java.nio.charset.StandardCharsets;

import lombok.Getter;
import lombok.Setter;

public class ProxyHeaderProcessor {

	private static final byte[] PROXY_V2_SIGNATURE = new byte[] { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55,
			0x49, 0x54, 0x0A };

	@Getter
	@Setter
	public static class ProxyHeaderResult {
		private String realIp;
	}

	public ProxyHeaderResult process(PushbackInputStream in, BufferedWriter writer, VoteReceiver receiver)
			throws Exception {
		ProxyHeaderResult result = new ProxyHeaderResult();

		byte[] headerPeek = new byte[32];
		int bytesRead = in.read(headerPeek);
		if (bytesRead <= 0) {
			return result;
		}

		String headerString = new String(headerPeek, 0, bytesRead, StandardCharsets.US_ASCII);

		if (headerString.startsWith("PROXY") && !headerString.contains("CONNECT")) {
			in.unread(headerPeek, 0, bytesRead);

			String proxyHeader = readLine(in);
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

		if (bytesRead >= 16 && isProxyV2(headerPeek)) {
			int addrLength = ((headerPeek[14] & 0xFF) << 8) | (headerPeek[15] & 0xFF);
			int totalLength = 16 + addrLength;
			int remaining = totalLength - bytesRead;

			if (remaining > 0) {
				byte[] discard = new byte[remaining];
				int read = 0;
				while (read < remaining) {
					int r = in.read(discard, read, remaining - read);
					if (r == -1) {
						break;
					}
					read += r;
				}

				if (read != remaining) {
					throw new Exception("Incomplete PROXY protocol v2 header");
				}
			}

			receiver.debug("Discarded PROXY protocol v2 header (" + totalLength + " bytes)");
			return result;
		}

		if (headerString.startsWith("CONNECT")) {
			in.unread(headerPeek, 0, bytesRead);

			String connectLine = readLine(in);
			receiver.debug("Received CONNECT request: " + connectLine);

			String line;
			while (!(line = readLine(in)).isEmpty()) {
				receiver.debug("Discarding header: " + line);
			}

			writer.write("HTTP/1.1 200 Connection Established\r\n\r\n");
			writer.flush();
			return result;
		}

		in.unread(headerPeek, 0, bytesRead);
		return result;
	}

	private boolean isProxyV2(byte[] header) {
		for (int i = 0; i < PROXY_V2_SIGNATURE.length; i++) {
			if (header[i] != PROXY_V2_SIGNATURE[i]) {
				return false;
			}
		}
		return true;
	}

	private String readLine(PushbackInputStream in) throws Exception {
		ByteArrayOutputStream lineBuffer = new ByteArrayOutputStream();
		int b;
		boolean seenCR = false;

		while ((b = in.read()) != -1) {
			if (b == '\r') {
				seenCR = true;
				continue;
			}

			if (b == '\n') {
				break;
			}

			if (seenCR) {
				in.unread(b);
				break;
			}

			lineBuffer.write(b);
		}

		return lineBuffer.toString("ASCII").trim();
	}
}