package com.vexsoftware.votifier.net;

import java.net.InetAddress;
import java.net.UnknownHostException;

/** Parses address literals without resolving host names or accepting scoped IPv6 addresses. */
final class IpLiteral {
	private IpLiteral() {
	}

	static byte[] parse(String value, int family) throws InvalidVoteException {
		if (value == null || value.isEmpty()) {
			throw new InvalidVoteException("Invalid PROXY address literal");
		}
		if (family == 4) {
			String[] parts = value.split("\\.", -1);
			if (parts.length != 4) {
				throw new InvalidVoteException("Invalid PROXY IPv4 literal");
			}
			byte[] address = new byte[4];
			for (int i = 0; i < 4; i++) {
				String part = parts[i];
				if (part.isEmpty() || part.length() > 3 || (part.length() > 1 && part.charAt(0) == '0')) {
					throw new InvalidVoteException("Invalid PROXY IPv4 literal");
				}
				int octet = 0;
				for (int j = 0; j < part.length(); j++) {
					char c = part.charAt(j);
					if (c < '0' || c > '9') {
						throw new InvalidVoteException("Invalid PROXY IPv4 literal");
					}
					octet = octet * 10 + c - '0';
				}
				if (octet > 255) {
					throw new InvalidVoteException("Invalid PROXY IPv4 literal");
				}
				address[i] = (byte) octet;
			}
			return address;
		}
		if (family != 6 || value.indexOf(':') < 0) {
			throw new InvalidVoteException("Invalid PROXY IPv6 literal");
		}
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':' || c == '.')) {
				throw new InvalidVoteException("Invalid PROXY IPv6 literal");
			}
		}
		try {
			byte[] address = InetAddress.getByName(value).getAddress();
			if (address.length == 16) {
				return address;
			}
		} catch (UnknownHostException ignored) {
			// Invalid numeric literal.
		}
		throw new InvalidVoteException("Invalid PROXY IPv6 literal");
	}

	static String format(byte[] address) throws InvalidVoteException {
		try {
			return InetAddress.getByAddress(address).getHostAddress();
		} catch (UnknownHostException ex) {
			throw new InvalidVoteException("Invalid PROXY address length");
		}
	}
}
