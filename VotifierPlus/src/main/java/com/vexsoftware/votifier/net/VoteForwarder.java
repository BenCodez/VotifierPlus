package com.vexsoftware.votifier.net;

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Map;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.FutureTask;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import java.util.function.BiFunction;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

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
	private static final int MAX_PENDING_RETRIES = 256;
	private static final int FIRST_RETRY_DELAY_SECONDS = 60;
	private static final long RETRY_LIFETIME_NANOS = TimeUnit.HOURS.toNanos(1);

	private final VoteReceiver receiver;
	private final VoteThrottleService failureLogs = new VoteThrottleService(null);
	private final Object lifecycleLock = new Object();
	private final Set<Attempt> attempts = new HashSet<>();
	private final ScheduledThreadPoolExecutor deadlines;
	private final ScheduledThreadPoolExecutor retries;
	private final int retryCapacity;
	private final ForwardRetryConfig retryConfig;
	private final LongSupplier retryClock;
	private final Map<String, Destination> previousSuccesses = new HashMap<>();
	private int pendingRetries;

	private record Credentials(boolean tokenMode, Key token) {
		private static Credentials capture(ForwardServer server) {
			if (server == null || !server.isEnabled()) {
				return null;
			}
			boolean tokenMode = server.isUseTokens();
			return new Credentials(tokenMode, tokenMode ? server.getToken() : null);
		}
	}

	private record Destination(String host, int port, boolean tokenMode, String fingerprint, ForwardRetryConfig policy) {}

	private record Retry(String name, Destination destination, Vote vote, long failedAt) {}

	private final ThreadPoolExecutor closers;
	private final int workers;
	private final Supplier<Socket> socketFactory;
	private int runtimeCalls;
	private int runtimeTargets;
	private boolean directCall;
	private boolean directTarget;
	private boolean directSealed;
	private long expiredAttempts;

	private enum Origin {
		DIRECT, INITIAL, RETRY
	}

	private static final class Attempt {
		final Socket socket;
		final Origin origin;
		final String name;
		ScheduledFuture<?> timer;
		boolean ended;
		boolean closeFinished;
		boolean closeRejected;

		Attempt(Socket socket, Origin origin, String name) {
			this.socket = socket;
			this.origin = origin;
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
		this(receiver, workers, resolveAddress, socketFactory,
				new ScheduledThreadPoolExecutor(1, work -> daemon(work, "Votifier-Retry")));
	}

	VoteForwarder(VoteReceiver receiver, int workers, BiFunction<String, Integer, InetSocketAddress> resolveAddress,
			Supplier<Socket> socketFactory, ScheduledThreadPoolExecutor retries) {
		this(receiver, workers, resolveAddress, socketFactory, retries,
				receiver == null ? ForwardRetryConfig.DEFAULT : receiver.getForwardRetryConfig(), System::nanoTime);
	}

	VoteForwarder(VoteReceiver receiver, int workers, BiFunction<String, Integer, InetSocketAddress> resolveAddress,
			Supplier<Socket> socketFactory, ScheduledThreadPoolExecutor retries, ForwardRetryConfig retryConfig,
			LongSupplier retryClock) {
		this.receiver = receiver;
		this.retries = retries;
		this.retryConfig = retryConfig;
		this.retryClock = retryClock;
		retryCapacity = receiver == null ? 0 : Math.min(MAX_PENDING_RETRIES, receiver.getForwardQueueCapacity());
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
		Vote snapshot = new Vote(vote.getServiceName(), vote.getUsername(), vote.getAddress(), vote.getTimeStamp());
		Set<String> names = receiver.getServers();
		synchronized (lifecycleLock) {
			previousSuccesses.keySet().retainAll(names);
		}
		for (String name : names) {
			if (stopped || Thread.currentThread().isInterrupted()) {
				return;
			}
			ForwardServer server = receiver.getServerData(name);
			Credentials credentials = captureCredentials(name, server);
			Destination destination = direct ? null : observeDestination(name, server, credentials);
			if (server == null || !server.isEnabled()) {
				receiver.debug("Skipping disabled or missing forward server: " + VoteLogSafety.field(name));
				continue;
			}
			if (credentials == null) {
				continue;
			}
			Long failedAt = send(snapshot, name, server, credentials, destination, direct ? Origin.DIRECT : Origin.INITIAL,
					deadlineAfter(ATTEMPT_TIMEOUT_MILLIS));
			if (failedAt != null && destination != null) {
				queueRetry(new Retry(name, destination, snapshot, failedAt));
			}
		}
	}

	private Credentials captureCredentials(String name, ForwardServer server) {
		try {
			return Credentials.capture(server);
		} catch (RuntimeException ex) {
			logFailure("retry-identity|" + name, "Unable to read forwarding credentials: " + VoteLogSafety.exceptionType(ex));
			return null;
		}
	}

	private Destination observeDestination(String name, ForwardServer server, Credentials credentials) {
		Destination destination = destinationOf(name, server, credentials);
		synchronized (lifecycleLock) {
			if (!Objects.equals(destination, previousSuccesses.get(name))) {
				previousSuccesses.remove(name);
			}
		}
		return destination;
	}

	private Destination destinationOf(String name, ForwardServer server, Credentials credentials) {
		if (credentials == null) {
			return null;
		}
		try {
			boolean tokenMode = credentials.tokenMode();
			String rsaKey = server.getKey();
			byte[] credential = tokenMode ? credentials.token().getEncoded()
					: rsaKey == null ? null : rsaKey.getBytes(StandardCharsets.UTF_8);
			if (credential == null) {
				return null;
			}
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(credential);
			ForwardRetryConfig policy = server.getRetryConfig() == null ? retryConfig : server.getRetryConfig();
			return new Destination(server.getHost(), server.getPort(), tokenMode, Base64.getEncoder().encodeToString(digest), policy);
		} catch (RuntimeException | NoSuchAlgorithmException ex) {
			logFailure("retry-identity|" + name, "Unable to establish forwarding retry identity: " + VoteLogSafety.exceptionType(ex));
			return null;
		}
	}

	private void rememberSuccess(String name, Destination destination) {
		// Read the effective target again in case configuration changed during the send.
		ForwardServer server = receiver.getServers().contains(name) ? receiver.getServerData(name) : null;
		if (destination.equals(destinationOf(name, server, captureCredentials(name, server)))) {
			synchronized (lifecycleLock) {
				if (!retries.isShutdown()) {
					previousSuccesses.put(name, destination);
				}
			}
		}
	}

	private boolean hasRequiredSuccess(Retry retry) {
		return hasRequiredSuccess(retry.name(), retry.destination());
	}

	private boolean hasRequiredSuccess(String name, Destination destination) {
		return !destination.policy().requirePreviousSuccessBeforeRetry()
				|| destination.equals(previousSuccesses.get(name));
	}

	private void queueRetry(Retry retry) {
		synchronized (lifecycleLock) {
			if (retries.isShutdown() || retry.destination().policy().maxRetries() == 0 || !hasRequiredSuccess(retry)) {
				return;
			}
			if (pendingRetries < retryCapacity) {
				long delay = TimeUnit.SECONDS.toNanos(FIRST_RETRY_DELAY_SECONDS) - (retryClock.getAsLong() - retry.failedAt());
				if (scheduleRetry(retry, 1, Math.max(0, delay))) {
					pendingRetries++;
				}
				return;
			}
		}
		logFailure("retry-queue", "Forwarding retry queue is full");
	}

	// Caller holds lifecycleLock. One slot covers both delayed and running work.
	private boolean scheduleRetry(Retry retry, int number, long delayNanos) {
		if (number > retry.destination().policy().maxRetries() || delayNanos >= retryTimeLeft(retry) || !hasRequiredSuccess(retry)) {
			return false;
		}
		retries.schedule(() -> runRetry(retry, number), delayNanos, TimeUnit.NANOSECONDS);
		return true;
	}

	private long retryTimeLeft(Retry retry) {
		return RETRY_LIFETIME_NANOS - (retryClock.getAsLong() - retry.failedAt());
	}

	private void runRetry(Retry retry, int number) {
		Long failedAt = null;
		try {
			if (!retries.isShutdown() && !receiver.isStopping() && retryTimeLeft(retry) > 0) {
				ForwardServer server = receiver.getServers().contains(retry.name())
						? receiver.getServerData(retry.name()) : null;
				Credentials credentials = captureCredentials(retry.name(), server);
				Destination destination = observeDestination(retry.name(), server, credentials);
				boolean eligible;
				synchronized (lifecycleLock) {
					eligible = retry.destination().equals(destination) && hasRequiredSuccess(retry);
				}
				long attemptStart = System.nanoTime();
				long timeLeft = retryTimeLeft(retry);
				if (eligible && timeLeft > 0) {
					long deadline = attemptStart + Math.min(timeLeft, TimeUnit.MILLISECONDS.toNanos(ATTEMPT_TIMEOUT_MILLIS));
					failedAt = send(retry.vote(), retry.name(), server, credentials, destination, Origin.RETRY, deadline);
				}
			}
		} catch (RuntimeException ex) {
			logFailure("retry-config", "Unable to check forwarding retry target: " + VoteLogSafety.exceptionType(ex));
		} finally {
			synchronized (lifecycleLock) {
				long interval = TimeUnit.SECONDS.toNanos(retry.destination().policy().retryIntervalSeconds());
				if (failedAt == null || retries.isShutdown()
						|| !scheduleRetry(retry, number + 1, Math.max(0, interval - (retryClock.getAsLong() - failedAt)))) {
					pendingRetries--;
				}
			}
		}
	}

	private Long send(Vote vote, String name, ForwardServer server, Credentials credentials, Destination destination,
			Origin origin, long deadline) {
		receiver.debug("Preparing to forward vote to: " + VoteLogSafety.field(name) + ", tokens mode: " + credentials.tokenMode());
		Attempt attempt = null;
		boolean preparingPayload = false;
		boolean writing = false;
		try {
			attempt = registerAttempt(origin, name, deadline);
			Socket socket = attempt.socket;
			InetSocketAddress address = resolve(server, deadline);
			long connectDeadline = limitedDeadline(deadline, CONNECT_TIMEOUT_MILLIS);
			socket.connect(address, timeoutMillis(connectDeadline));
			remaining(connectDeadline);
			long greetingDeadline = limitedDeadline(deadline, HANDSHAKE_TIMEOUT_MILLIS);
			String greeting = readSocketGreeting(socket, greetingDeadline);
			receiver.debug("Received handshake from " + VoteLogSafety.field(name)
					+ " (" + (greeting == null ? 0 : greeting.length()) + " chars)");

			if (greeting == null && credentials.tokenMode()) {
				throw new EOFException("Missing token-mode greeting");
			}
			preparingPayload = true;
			byte[] payload;
			if (credentials.tokenMode()) {
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
				mac.init(credentials.token());
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

			preparingPayload = false;
			remaining(deadline);
			var output = socket.getOutputStream();
			synchronized (lifecycleLock) {
				remaining(deadline);
				if (attempt.ended) {
					throw new IOException("Forwarding attempt already ended");
				}
				writing = true;
			}
			output.write(payload);
			output.flush();
			boolean completed;
			synchronized (lifecycleLock) {
				boolean expired = deadline - System.nanoTime() <= 0;
				completed = !stopped && !attempt.ended && !expired;
				finishAttempt(attempt, !stopped && expired);
			}
			if (completed) {
				if (origin == Origin.INITIAL && destination != null && destination.policy().requirePreviousSuccessBeforeRetry()) {
					rememberSuccess(name, destination);
				}
				receiver.debug("Payload forwarded to " + VoteLogSafety.field(name) + " (" + payload.length + " bytes)");
			} else {
				logFailure("target|" + name, "Forwarding attempt ended before completion: " + VoteLogSafety.field(name));
			}
		} catch (Exception ex) {
			long failedAt;
			boolean eligible;
			synchronized (lifecycleLock) {
				failedAt = retryClock.getAsLong();
				eligible = destination != null && hasRequiredSuccess(name, destination);
			}
			logFailure("target|" + name, "Failed to forward vote to " + VoteLogSafety.field(name) + ": "
					+ VoteLogSafety.exceptionType(ex));
			if (ex instanceof InterruptedException) {
				Thread.currentThread().interrupt();
			}
			// DNS waits signal their deadline via Future.get's TimeoutException.
			return (ex instanceof IOException || ex instanceof TimeoutException)
					&& !preparingPayload && !writing && !Thread.currentThread().isInterrupted() && eligible
					? failedAt : null;
		} finally {
			if (attempt != null) {
				synchronized (lifecycleLock) {
					finishAttempt(attempt, !stopped && deadline - System.nanoTime() <= 0);
					awaitClose(attempt, deadline);
				}
				if (attempt.closeRejected) {
					logFailure("close|" + name, "Forwarding socket close submission failed");
				}
			}
		}
		return null;
	}

	private Attempt registerAttempt(Origin origin, String name, long deadline) throws Exception {
		boolean direct = origin == Origin.DIRECT;
		synchronized (lifecycleLock) {
			while (!attemptAdmissionClosed(origin) && !direct && runtimeTargets == workers) {
				TimeUnit.NANOSECONDS.timedWait(lifecycleLock, remaining(deadline));
			}
			remaining(deadline);
			if (attemptAdmissionClosed(origin) || (direct && directTarget)) {
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
			var attempt = new Attempt(socket, origin, name);
			attempts.add(attempt);
			try {
				attempt.timer = deadlines.schedule(() -> expire(attempt), remaining(deadline), TimeUnit.NANOSECONDS);
			} catch (Exception ex) {
				finishAttempt(attempt, ex instanceof SocketTimeoutException);
				throw ex;
			}
			return attempt;
		}
	}

	// Caller holds lifecycleLock.
	private boolean attemptAdmissionClosed(Origin origin) {
		return stopped || (origin == Origin.RETRY && retries.isShutdown());
	}

	private void expire(Attempt attempt) {
		synchronized (lifecycleLock) {
			finishAttempt(attempt, true);
		}
	}

	// The only terminal transition and close submission. Caller holds lifecycleLock.
	private void finishAttempt(Attempt attempt) {
		finishAttempt(attempt, false);
	}

	private void finishAttempt(Attempt attempt, boolean expired) {
		if (attempt.ended) {
			return;
		}
		attempt.ended = true;
		if (expired) {
			expiredAttempts++;
		}
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
				releaseTarget(attempt.origin == Origin.DIRECT);
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

	// Stop direct calls and retries before the receiver drains initial forwarding.
	void sealDirectCalls() {
		synchronized (lifecycleLock) {
			directSealed = true;
			pendingRetries -= retries.shutdownNow().size();
			previousSuccesses.clear();
			for (Attempt attempt : attempts) {
				if (attempt.origin == Origin.RETRY) {
					finishAttempt(attempt);
				}
			}
			lifecycleLock.notifyAll();
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
			pendingRetries -= retries.shutdownNow().size();
			previousSuccesses.clear();
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
					&& retries.isTerminated() && resolver.isTerminated() && deadlines.isTerminated() && closers.isTerminated();
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
