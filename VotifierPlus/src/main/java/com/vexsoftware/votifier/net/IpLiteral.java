package com.vexsoftware.votifier.net;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

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
		return parseIpv6(value);
	}

	private static byte[] parseIpv6(String value) throws InvalidVoteException {
		String[] halves = value.split("::", -1);
		if (halves.length > 2) throw new InvalidVoteException("Invalid PROXY IPv6 literal");

		List<Integer> left = parseIpv6Half(halves[0], halves.length == 1);
		List<Integer> right = halves.length == 2 ? parseIpv6Half(halves[1], true) : List.of();
		int omitted = 8 - left.size() - right.size();
		if (halves.length == 1 ? omitted != 0 : omitted < 1) {
			throw new InvalidVoteException("Invalid PROXY IPv6 literal");
		}

		byte[] address = new byte[16];
		int index = 0;
		for (int group : left) index = writeGroup(address, index, group);
		index += omitted * 2;
		for (int group : right) index = writeGroup(address, index, group);
		return address;
	}

	private static List<Integer> parseIpv6Half(String half, boolean mayEndWithIpv4) throws InvalidVoteException {
		List<Integer> groups = new ArrayList<>();
		if (half.isEmpty()) return groups;
		String[] parts = half.split(":", -1);
		for (int i = 0; i < parts.length; i++) {
			String part = parts[i];
			if (part.isEmpty()) throw new InvalidVoteException("Invalid PROXY IPv6 literal");
			if (part.indexOf('.') >= 0) {
				if (!mayEndWithIpv4 || i != parts.length - 1) {
					throw new InvalidVoteException("Invalid PROXY IPv6 literal");
				}
				byte[] ipv4 = parse(part, 4);
				groups.add((ipv4[0] & 0xFF) << 8 | ipv4[1] & 0xFF);
				groups.add((ipv4[2] & 0xFF) << 8 | ipv4[3] & 0xFF);
				continue;
			}
			if (part.length() > 4) throw new InvalidVoteException("Invalid PROXY IPv6 literal");
			int group = 0;
			for (int j = 0; j < part.length(); j++) group = group * 16 + Character.digit(part.charAt(j), 16);
			groups.add(group);
		}
		return groups;
	}

	private static int writeGroup(byte[] address, int index, int group) {
		address[index++] = (byte) (group >>> 8);
		address[index++] = (byte) group;
		return index;
	}

	static String format(byte[] address) throws InvalidVoteException {
		try {
			return InetAddress.getByAddress(address).getHostAddress();
		} catch (UnknownHostException ex) {
			throw new InvalidVoteException("Invalid PROXY address length");
		}
	}
}
