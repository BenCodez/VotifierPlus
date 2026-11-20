package com.vexsoftware.votifier.net;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.FilterInputStream;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.FutureTask;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.Supplier;
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
	private final Object lifecycleLock = new Object();
	private final Set<Attempt> attempts = new HashSet<>();
	private final ScheduledThreadPoolExecutor deadlines;
	private final ThreadPoolExecutor closers;
	private final int workers;
	private final Supplier<Socket> socketFactory;
	private int runtimeCalls;
	private int runtimeTargets;
	private boolean directCall;
	private boolean directTarget;
	private boolean directSealed;
	private long expiredAttempts;

	private static final class Attempt {
		final Socket socket;
		final boolean direct;
		final String name;
		ScheduledFuture<?> timer;
		boolean ended;
		boolean closeFinished;
		boolean closeRejected;

		Attempt(Socket socket, boolean direct, String name) {
			this.socket = socket;
			this.direct = direct;
			this.name = name;
		}
	}
	private final Set<FutureTask<InetSocketAddress>> pendingResolutions = new HashSet<>();
	private final ThreadPoolExecutor resolver;
	private final BiFunction<String, Integer, InetSocketAddress> resolveAddress;
	private volatile boolean stopped;

	/**
	 * Creates an independent forwarder using the supplied receiver's configuration.
	 * To share the listener's lifecycle, use its receiver-owned forwarder obtained
	 * from {@link VoteReceiver#getVoteForwarder()} after startup.
	 */
	public VoteForwarder(VoteReceiver receiver) {
		this(receiver, receiver.getForwardWorkerCount());
	}

	VoteForwarder(VoteReceiver receiver, int workers) {
		this(receiver, workers, InetSocketAddress::new);
	}

	VoteForwarder(VoteReceiver receiver, int workers, BiFunction<String, Integer, InetSocketAddress> resolveAddress) {
		this(receiver, workers, resolveAddress, Socket::new);
	}

	VoteForwarder(VoteReceiver receiver, int workers, BiFunction<String, Integer, InetSocketAddress> resolveAddress,
			Supplier<Socket> socketFactory) {
		this.receiver = receiver;
		this.workers = workers;
		this.resolveAddress = resolveAddress;
		this.socketFactory = socketFactory;
		int closeCapacity = Math.addExact(workers, 1);
		resolver = createPool(workers, "Votifier-Resolver");
		closers = createPool(closeCapacity, "Votifier-Socket-Close");
		deadlines = new ScheduledThreadPoolExecutor(1, work -> daemon(work, "Votifier-Deadline"));
		deadlines.setRemoveOnCancelPolicy(true);
		deadlines.setKeepAliveTime(1, TimeUnit.SECONDS);
		deadlines.allowCoreThreadTimeOut(true);
	}

	private static ThreadPoolExecutor createPool(int workers, String name) {
		var pool = new ThreadPoolExecutor(workers, workers, 1, TimeUnit.SECONDS, new ArrayBlockingQueue<>(workers),
				work -> daemon(work, name), new ThreadPoolExecutor.AbortPolicy());
		pool.allowCoreThreadTimeOut(true);
		return pool;
	}

	private static Thread daemon(Runnable work, String name) {
		Thread thread = new Thread(work, name);
		thread.setDaemon(true);
		return thread;
	}

	public void forwardVote(Vote vote) {
		forward(vote, true);
	}

	void forwardQueuedVote(Vote vote) {
		forward(vote, false);
	}

	private void forward(Vote vote, boolean direct) {
		boolean admitted;
		synchronized (lifecycleLock) {
			admitted = !stopped && (direct ? !directSealed && !directCall : runtimeCalls < workers);
			if (admitted) {
				if (direct) {
					directCall = true;
				} else {
					runtimeCalls++;
				}
			}
		}
		if (!admitted) {
			logFailure("admission", "Forwarding call rejected: capacity is full or stopping");
			return;
		}
		try {
			forwardTargets(vote, direct);
		} finally {
			synchronized (lifecycleLock) {
				if (direct) {
					directCall = false;
				} else {
					runtimeCalls--;
				}
			}
		}
	}

	private void forwardTargets(Vote vote, boolean direct) {
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
			Attempt attempt = null;
			try {
				attempt = registerAttempt(direct, name, deadline);
				Socket socket = attempt.socket;
				InetSocketAddress address = resolve(server, deadline);
				long connectDeadline = limitedDeadline(deadline, CONNECT_TIMEOUT_MILLIS);
				socket.connect(address, timeoutMillis(connectDeadline));
				remaining(connectDeadline);
				long greetingDeadline = limitedDeadline(deadline, HANDSHAKE_TIMEOUT_MILLIS);
				String greeting = readSocketGreeting(socket, greetingDeadline);
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

				remaining(deadline);
				var output = socket.getOutputStream();
				output.write(payload);
				output.flush();
				boolean completed;
				synchronized (lifecycleLock) {
					completed = !stopped && !attempt.ended && deadline - System.nanoTime() > 0;
					finishAttempt(attempt);
				}
				if (completed) {
					receiver.debug("Payload forwarded to " + VoteLogSafety.field(name) + " (" + payload.length + " bytes)");
				} else {
					logFailure("target|" + name, "Forwarding attempt ended before completion: " + VoteLogSafety.field(name));
				}
			} catch (Exception ex) {
				logFailure("target|" + name, "Failed to forward vote to " + VoteLogSafety.field(name) + ": "
						+ VoteLogSafety.exceptionType(ex));
				if (ex instanceof InterruptedException) {
					Thread.currentThread().interrupt();
					return;
				}
			} finally {
				if (attempt != null) {
					synchronized (lifecycleLock) {
						finishAttempt(attempt);
						awaitClose(attempt, deadline);
					}
					if (attempt.closeRejected) {
						logFailure("close|" + name, "Forwarding socket close submission failed");
					}
				}
			}
		}
	}

	private Attempt registerAttempt(boolean direct, String name, long deadline) throws Exception {
		synchronized (lifecycleLock) {
			while (!stopped && !direct && runtimeTargets == workers) {
				TimeUnit.NANOSECONDS.timedWait(lifecycleLock, remaining(deadline));
			}
			remaining(deadline);
			if (stopped || (direct && directTarget)) {
				throw new RejectedExecutionException("Forwarding socket capacity unavailable");
			}
			if (direct) {
				directTarget = true;
			} else {
				runtimeTargets++;
			}
			Socket socket;
			try {
				socket = socketFactory.get();
			} catch (RuntimeException | Error ex) {
				releaseTarget(direct);
				throw ex;
			}
			var attempt = new Attempt(socket, direct, name);
			attempts.add(attempt);
			try {
				attempt.timer = deadlines.schedule(() -> expire(attempt), remaining(deadline), TimeUnit.NANOSECONDS);
			} catch (Exception ex) {
				finishAttempt(attempt);
				throw ex;
			}
			return attempt;
		}
	}

	private void expire(Attempt attempt) {
		synchronized (lifecycleLock) {
			if (attempt.ended) {
				return;
			}
			expiredAttempts++;
			finishAttempt(attempt);
		}
	}

	// The only terminal transition and close submission. Caller holds lifecycleLock.
	private void finishAttempt(Attempt attempt) {
		if (attempt.ended) {
			return;
		}
		attempt.ended = true;
		if (attempt.timer != null) {
			attempt.timer.cancel(false);
		}
		try {
			closers.execute(() -> closeAttempt(attempt));
		} catch (RejectedExecutionException ex) {
			attempt.closeRejected = true;
			attempt.closeFinished = true;
			lifecycleLock.notifyAll();
		}
	}

	private void closeAttempt(Attempt attempt) {
		try {
			attempt.socket.close();
			if (!attempt.socket.isClosed()) {
				throw new IOException("Forwarding socket remained open");
			}
			synchronized (lifecycleLock) {
				attempt.closeFinished = true;
				attempts.remove(attempt);
				releaseTarget(attempt.direct);
			}
		} catch (Exception ex) {
			synchronized (lifecycleLock) {
				attempt.closeFinished = true;
				lifecycleLock.notifyAll();
			}
			logFailure("close|" + attempt.name, "Forwarding socket close failed: " + VoteLogSafety.exceptionType(ex));
		}
	}

	private void releaseTarget(boolean direct) {
		if (direct) {
			directTarget = false;
		} else {
			runtimeTargets--;
		}
		lifecycleLock.notifyAll();
	}

	private void awaitClose(Attempt attempt, long deadline) {
		try {
			while (!stopped && !attempt.closeFinished) {
				TimeUnit.NANOSECONDS.timedWait(lifecycleLock, remaining(deadline));
			}
		} catch (IOException ex) {
			// Closure retains the target permit beyond the caller deadline.
		} catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
		}
	}

	private void logFailure(String key, String message) {
		String warning = failureLogs.allowLog(key, message);
		if (warning != null) {
			receiver.log(warning);
		}
	}

	private InetSocketAddress resolve(ForwardServer target, long deadline) throws Exception {
		remaining(deadline);
		var request = new FutureTask<>(() -> resolveAddress.apply(target.getHost(), target.getPort()));
		try {
			synchronized (lifecycleLock) {
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
			synchronized (lifecycleLock) {
				pendingResolutions.remove(request);
			}
		}
	}

	void sealDirectCalls() {
		synchronized (lifecycleLock) {
			directSealed = true;
		}
	}

	int stop() {
		int cancellations = 0;
		int rejectedCloses = 0;
		long expired;
		List<FutureTask<InetSocketAddress>> requests;
		synchronized (lifecycleLock) {
			if (stopped) {
				return 0;
			}
			stopped = true;
			lifecycleLock.notifyAll();
			for (Attempt attempt : attempts) {
				if (!attempt.ended) {
					finishAttempt(attempt);
					cancellations++;
				}
				if (attempt.closeRejected) {
					rejectedCloses++;
				}
			}
			expired = expiredAttempts;
			requests = List.copyOf(pendingResolutions);
			pendingResolutions.clear();
			deadlines.shutdown();
			closers.shutdown();
		}
		requests.forEach(request -> request.cancel(true));
		for (Runnable queued : resolver.shutdownNow()) {
			((FutureTask<?>) queued).cancel(false);
		}
		if (receiver != null && (expired != 0 || rejectedCloses != 0)) {
			receiver.logWarning("Forwarding deadline expirations=" + expired + ", rejected socket closes=" + rejectedCloses);
		}
		return cancellations;
	}

	boolean isTerminated() {
		synchronized (lifecycleLock) {
			return stopped && runtimeCalls == 0 && !directCall && attempts.isEmpty()
					&& resolver.isTerminated() && deadlines.isTerminated() && closers.isTerminated();
		}
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

	private static int timeoutMillis(long deadline) throws IOException {
		return (int) Math.max(1, TimeUnit.NANOSECONDS.toMillis(remaining(deadline)));
	}

	private static String readSocketGreeting(Socket socket, long deadline) throws Exception {
		var input = new FilterInputStream(socket.getInputStream()) {
			@Override
			public int read(byte[] bytes, int offset, int length) throws IOException {
				socket.setSoTimeout(timeoutMillis(deadline));
				return super.read(bytes, offset, length);
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
