package com.vexsoftware.votifier.net;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.FutureTask;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.function.BiFunction;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;

import com.google.gson.JsonObject;
import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.model.Vote;

public class VoteForwarder {

	private static final String HANDSHAKE_PREFIX = "VOTIFIER";
	private static final String HANDSHAKE_V2 = "2";
	private static final String OPCODE_VOTE = "VOTE";
	private static final String FIELD_PAYLOAD = "payload";
	private static final String FIELD_SIGNATURE = "signature";
	private static final String FIELD_SERVICE_NAME = "serviceName";
	private static final String FIELD_USERNAME = "username";
	private static final String FIELD_ADDRESS = "address";
	private static final String FIELD_TIMESTAMP = "timestamp";
	private static final String FIELD_CHALLENGE = "challenge";
	private static final int MAX_HANDSHAKE_CHARS = 512;
	private static final int ATTEMPT_TIMEOUT_MILLIS = 5000;
	private static final int CONNECT_TIMEOUT_MILLIS = 1000;
	private static final int HANDSHAKE_TIMEOUT_MILLIS = 3000;

	private final VoteReceiver receiver;
	private final VoteThrottleService failureLogs = new VoteThrottleService(null);
	private final Map<SocketChannel, Selector> activeChannels = new HashMap<>();
	private final Set<FutureTask<InetSocketAddress>> pendingResolutions = new HashSet<>();
	private final ThreadPoolExecutor resolver;
	private final BiFunction<String, Integer, InetSocketAddress> resolveAddress;
	private volatile boolean stopped;

	public VoteForwarder(VoteReceiver receiver) {
		this(receiver, receiver.getForwardWorkerCount());
	}

	VoteForwarder(VoteReceiver receiver, int workers) {
		this(receiver, workers, InetSocketAddress::new);
	}

	VoteForwarder(VoteReceiver receiver, int workers, BiFunction<String, Integer, InetSocketAddress> resolveAddress) {
		this.receiver = receiver;
		this.resolveAddress = resolveAddress;
		resolver = new ThreadPoolExecutor(workers, workers, 1, TimeUnit.SECONDS, new ArrayBlockingQueue<>(workers),
				work -> {
					Thread thread = new Thread(work, "Votifier-Resolver");
					thread.setDaemon(true);
					return thread;
				}, new ThreadPoolExecutor.AbortPolicy());
		resolver.allowCoreThreadTimeOut(true);
	}

	public void forwardVote(Vote vote) {
		for (String name : receiver.getServers()) {
			if (stopped || Thread.currentThread().isInterrupted()) {
				return;
			}
			ForwardServer server = receiver.getServerData(name);

			if (!server.isEnabled()) {
				receiver.debug("Skipping disabled forward server: " + VoteLogSafety.field(name));
				continue;
			}

			receiver.debug("Preparing to forward vote to: " + VoteLogSafety.field(name) + ", tokens mode: " + server.isUseTokens());

			long deadline = deadlineAfter(ATTEMPT_TIMEOUT_MILLIS);
			try (SocketChannel channel = SocketChannel.open(); Selector selector = Selector.open()) {
				try {
					synchronized (activeChannels) {
						if (stopped) {
							return;
						}
						activeChannels.put(channel, selector);
					}
					InetSocketAddress address = resolve(server, deadline);
					channel.configureBlocking(false);
					long connectDeadline = limitedDeadline(deadline, CONNECT_TIMEOUT_MILLIS);
					remaining(connectDeadline);
					if (!channel.connect(address)) {
						while (!channel.finishConnect()) {
							awaitReady(channel, selector, SelectionKey.OP_CONNECT, connectDeadline);
						}
					}
					remaining(connectDeadline);
					long greetingDeadline = limitedDeadline(deadline, HANDSHAKE_TIMEOUT_MILLIS);
					String greeting = readChannelGreeting(channel, selector, greetingDeadline);
					receiver.debug("Received handshake from " + VoteLogSafety.field(name)
							+ " (" + (greeting == null ? 0 : greeting.length()) + " chars)");

					byte[] payload;
					if (server.isUseTokens()) {
						String[] parts = greeting.split(" ");
						if (parts.length < 3 || !HANDSHAKE_PREFIX.equals(parts[0]) || !HANDSHAKE_V2.equals(parts[1])) {
							throw new IllegalStateException("Invalid token-mode handshake");
						}

						String challenge = parts[2];

						JsonObject inner = new JsonObject();
						inner.addProperty(FIELD_SERVICE_NAME, vote.getServiceName());
						inner.addProperty(FIELD_USERNAME, vote.getUsername());
						inner.addProperty(FIELD_ADDRESS, vote.getAddress());
						inner.addProperty(FIELD_TIMESTAMP, vote.getTimeStamp());
						inner.addProperty(FIELD_CHALLENGE, challenge);

						String innerJson = inner.toString();

						Mac mac = Mac.getInstance("HmacSHA256");
						mac.init(server.getToken());
						String sig = Base64.getEncoder()
								.encodeToString(mac.doFinal(innerJson.getBytes(StandardCharsets.UTF_8)));

						JsonObject outer = new JsonObject();
						outer.addProperty(FIELD_PAYLOAD, innerJson);
						outer.addProperty(FIELD_SIGNATURE, sig);

						payload = (outer.toString() + "\r\n").getBytes(StandardCharsets.UTF_8);
					} else {
						String voteString = String.join("\n", OPCODE_VOTE, vote.getServiceName(), vote.getUsername(),
								vote.getAddress(), vote.getTimeStamp(), "") + "\n";
						payload = receiver.encrypt(voteString.getBytes(StandardCharsets.UTF_8), receiver.getPublicKey(server));
					}

					writePayload(channel, selector, payload, deadline);
					receiver.debug("Payload forwarded to " + VoteLogSafety.field(name) + " (" + payload.length + " bytes)");
				} finally {
					synchronized (activeChannels) {
						activeChannels.remove(channel);
					}
				}
			} catch (Exception ex) {
				if (ex instanceof InterruptedException) {
					Thread.currentThread().interrupt();
					return;
				}
				if (!stopped) {
					String warning = failureLogs.allowLog("forward|" + name,
							"Failed to forward vote to " + VoteLogSafety.field(name) + ": "
									+ VoteLogSafety.exceptionType(ex));
					if (warning != null) {
						receiver.log(warning);
					}
				}
			}
		}
	}

	private InetSocketAddress resolve(ForwardServer target, long deadline) throws Exception {
		remaining(deadline);
		var request = new FutureTask<>(() -> resolveAddress.apply(target.getHost(), target.getPort()));
		try {
			synchronized (activeChannels) {
				if (stopped) {
					throw new IOException("Forwarding has stopped");
				}
				resolver.execute(request);
				pendingResolutions.add(request);
			}
			return request.get(remaining(deadline), TimeUnit.NANOSECONDS);
		} finally {
			request.cancel(true);
			resolver.remove(request);
			synchronized (activeChannels) {
				pendingResolutions.remove(request);
			}
		}
	}

	int stop() {
		Map<SocketChannel, Selector> channels;
		List<FutureTask<InetSocketAddress>> requests;
		synchronized (activeChannels) {
			stopped = true;
			channels = Map.copyOf(activeChannels);
			activeChannels.clear();
			requests = List.copyOf(pendingResolutions);
			pendingResolutions.clear();
		}
		requests.forEach(request -> request.cancel(true));
		for (Runnable queued : resolver.shutdownNow()) {
			((FutureTask<?>) queued).cancel(false);
		}
		for (var entry : channels.entrySet()) {
			entry.getValue().wakeup();
			try {
				entry.getKey().close();
			} catch (IOException ex) {
				receiver.debug("Failed to close forwarding socket: " + VoteLogSafety.exceptionType(ex));
			}
		}
		return channels.size();
	}

	boolean isTerminated() {
		return resolver.isTerminated();
	}

	private static long deadlineAfter(int timeoutMillis) {
		return System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
	}

	private static long limitedDeadline(long overallDeadline, int timeoutMillis) {
		long now = System.nanoTime();
		return now + Math.min(overallDeadline - now, TimeUnit.MILLISECONDS.toNanos(timeoutMillis));
	}

	private static long remaining(long deadline) throws IOException {
		if (Thread.currentThread().isInterrupted()) {
			throw new java.io.InterruptedIOException("Forwarding interrupted");
		}
		long remaining = deadline - System.nanoTime();
		if (remaining <= 0) {
			throw new SocketTimeoutException("Forwarding attempt timed out");
		}
		return remaining;
	}

	private static void awaitReady(SocketChannel channel, Selector selector, int operation, long deadline)
			throws IOException {
		SelectionKey key = channel.keyFor(selector);
		if (key == null) {
			channel.register(selector, operation);
		} else {
			key.interestOps(operation);
		}
		selector.select(Math.max(1, TimeUnit.NANOSECONDS.toMillis(remaining(deadline))));
		selector.selectedKeys().clear();
		remaining(deadline);
	}

	private static void writePayload(SocketChannel channel, Selector selector, byte[] payload, long deadline)
			throws IOException {
		ByteBuffer bytes = ByteBuffer.wrap(payload);
		while (bytes.hasRemaining()) {
			remaining(deadline);
			if (channel.write(bytes) == 0) {
				awaitReady(channel, selector, SelectionKey.OP_WRITE, deadline);
			}
		}
		remaining(deadline);
	}

	private static String readChannelGreeting(SocketChannel channel, Selector selector, long deadline) throws Exception {
		var input = new InputStream() {
			@Override
			public int read(byte[] bytes, int offset, int length) throws IOException {
				ByteBuffer buffer = ByteBuffer.wrap(bytes, offset, length);
				while (true) {
					remaining(deadline);
					int count = channel.read(buffer);
					if (count != 0 || length == 0) {
						return count;
					}
					awaitReady(channel, selector, SelectionKey.OP_READ, deadline);
				}
			}

			@Override
			public int read() throws IOException {
				byte[] one = new byte[1];
				return read(one, 0, 1) < 0 ? -1 : Byte.toUnsignedInt(one[0]);
			}
		};
		var reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
		String greeting = readHandshakeLine(reader);
		remaining(deadline);
		return greeting;
	}

	static String readHandshakeLine(BufferedReader in) throws Exception {
		StringBuilder line = new StringBuilder();
		int value;
		while ((value = in.read()) != -1) {
			if (value == '\r') {
				in.mark(1);
				int next = in.read();
				if (next != '\n' && next != -1) {
					in.reset();
				}
				return line.toString();
			}
			if (value == '\n') {
				return line.toString();
			}
			if (line.length() >= MAX_HANDSHAKE_CHARS) {
				throw new IllegalStateException("Forward server handshake exceeds limit");
			}
			line.append((char) value);
		}
		return line.length() == 0 ? null : line.toString();
	}
}
