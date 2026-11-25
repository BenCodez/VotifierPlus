/*
 * Copyright (C) 2012 Vex Software LLC
 * This file is part of Votifier.
 *
 * Votifier is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Votifier is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Votifier. If not, see <http://www.gnu.org/licenses/>.
 *
 * ----------------------------------------------------------------------
 * Modifications by: BenCodez
 *
 * Summary of changes:
 * - Refactored original monolithic VoteReceiver into multiple classes:
 *     - VoteConnectionHandler (connection handling + lifecycle)
 *     - VoteParser (V1/V2 protocol parsing)
 *     - ProxyHeaderProcessor (PROXY/CONNECT support)
 *     - VoteThrottleService (rate limiting + abuse protection)
 *     - VoteForwarder (vote forwarding logic)
 *
 * - Added support for:
 *     - Votifier V2 token-based protocol (JSON + HMAC validation)
 *     - PROXY protocol (v1) and HTTP CONNECT tunneling
 *     - Real IP detection for improved per-client throttling
 *
 * - Reworked connection handling:
 *     - Handler now returns Vote instead of performing side effects
 *     - VoteReceiver is responsible for forwarding + event dispatch
 *     - Added thread pool for concurrent connection handling
 *
 * - Improved performance and stability:
 *     - Asynchronous forwarding to prevent blocking vote processing
 *     - Socket timeouts and safer stream handling
 *
 * - Replaced string-based error handling with typed exceptions:
 *     - InvalidVoteException
 *     - VoteAuthenticationException
 *
 * - Enhanced validation:
 *     - Strict JSON parsing and required field enforcement
 *     - Non-empty field validation for V2 payloads
 *     - Constant-time HMAC comparison for signatures
 *
 * - Updated throttling system:
 *     - Separated from VoteReceiver into VoteThrottleService
 *     - Added per-client and tunnel-aware throttling modes
 *     - Log suppression to reduce spam from abusive sources
 *
 * - Updated unit tests to match new architecture and behavior
 *
 * ----------------------------------------------------------------------
 */
package com.vexsoftware.votifier.net;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.function.IntSupplier;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;

import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.model.Vote;

import lombok.Getter;

public abstract class VoteReceiver extends Thread {

	private final String host;
	private final int port;

	@Getter
	private ServerSocket server;

	private volatile boolean running = true;
	private final Object lifecycleLock = new Object();
	private final Set<Socket> connections = new HashSet<>();
	private final AtomicLong rejectedForwardingJobs = new AtomicLong();
	private final CountDownLatch retirementComplete = new CountDownLatch(1);
	private Thread retirementOwner;
	private volatile boolean retirementCleanupComplete;
	private volatile boolean connectionCloseFailed;
	private static final int DRAIN_SECONDS = 3;

	@Getter
	private volatile VoteThrottleService throttleService;

	@Getter
	private volatile VoteForwarder voteForwarder;

	private volatile ExecutorService connectionExecutor;
	private volatile ExecutorService forwardExecutor;

	public VoteReceiver(String host, int port) throws Exception {
		super("Votifier I/O");
		this.host = host;
		this.port = port;
		setPriority(Thread.MIN_PRIORITY);
		initialize();
	}

	/**
	 * Binds a receiver using explicit per-listener settings. Start it with
	 * {@link VoteReceiver#start()} and retire it with {@link VoteReceiver#shutdown()}.
	 *
	 * <p>The callback is invoked on a connection worker before forwarding and may
	 * run concurrently for different votes. It should enqueue platform work on
	 * the appropriate scheduler and return promptly. Treat the vote as read-only
	 * because forwarding uses the same object. The adapter owns the lifecycle of
	 * work it enqueues on its scheduler. The receiver can invoke the callback
	 * for connections already admitted while shutdown drains the worker pool.
	 * The adapter must gate and drain its scheduler work during disable.
	 *
	 * <p>The wire response acknowledges protocol acceptance before this
	 * callback. Callback failures are logged and forwarding can still proceed.
	 *
	 * @param settings listener configuration and protocol policy
	 * @param logger logger for the receiver
	 * @param onVote callback for a parsed, accepted vote
	 * @return bound, unstarted receiver
	 * @throws Exception if the listener cannot bind
	 */
	public static VoteReceiver bind(Settings settings, Logger logger, Consumer<Vote> onVote) throws Exception {
		return new ConfiguredReceiver(Objects.requireNonNull(settings), Objects.requireNonNull(logger),
				Objects.requireNonNull(onVote));
	}

	/**
	 * Configuration for one listener. Supply a new configuration and receiver
	 * when changing policy. Token support controls the greeting, while disableV1
	 * requires V2 authentication. An empty trusted-proxy set trusts no peer.
	 */
	public record Settings(String host, int port, String version, boolean tokenSupport, boolean disableV1,
			KeyPair keyPair, Map<String, Key> tokens, Set<String> trustedProxyIps, ThrottleConfig throttle,
			Map<String, ForwardServer> forwarding) {
		public Settings {
			Objects.requireNonNull(version);
			if (!disableV1) {
				Objects.requireNonNull(keyPair, "Legacy V1 requires an RSA key pair");
			}
			tokens = Map.copyOf(tokens);
			trustedProxyIps = Set.copyOf(trustedProxyIps);
			Map<String, ForwardServer> targets = new LinkedHashMap<>();
			forwarding.forEach((name, target) -> targets.put(Objects.requireNonNull(name), copyTarget(target)));
			forwarding = Collections.unmodifiableMap(targets);
		}

		@Override
		public Map<String, ForwardServer> forwarding() {
			Map<String, ForwardServer> targets = new LinkedHashMap<>();
			forwarding.forEach((name, target) -> targets.put(name, copyTarget(target)));
			return Collections.unmodifiableMap(targets);
		}

		@Override
		public String toString() {
			return "VoteReceiver.Settings";
		}
	}

	private static ForwardServer copyTarget(ForwardServer target) {
		return new ForwardServer(target.isEnabled(), target.getHost(), target.getPort(), target.getKey(),
				target.getToken(), target.getRetryConfig());
	}


	public void initialize() throws Exception {
		synchronized (lifecycleLock) {
			if (!running) {
				throw new IllegalStateException("Receiver has been shut down");
			}
			if (server != null && !server.isClosed()) {
				throw new IllegalStateException("Receiver already owns a listener");
			}
			ServerSocket next = new ServerSocket();
			try {
				next.bind(new InetSocketAddress(host, port));
				debug("Bound to " + next.getInetAddress().getHostAddress() + ":" + next.getLocalPort());
				server = next;
			} catch (Exception ex) {
				try {
					next.close();
				} catch (IOException closeFailure) {
					ex.addSuppressed(closeFailure);
				}
				logSevere("Error initializing vote receiver. Please verify that the configured IP address and port are not already in use.");
				ex.printStackTrace();
				throw new Exception(ex);
			}
		}
	}

	@Override
	public void start() {
		synchronized (lifecycleLock) {
			if (!running) {
				throw new IllegalThreadStateException("Receiver has been shut down");
			}
			super.start();
		}
	}

	/**
	 * Returns whether shutdown cleanup completed and all receiver-owned work has
	 * terminated. Platform scheduler work is outside this receiver's ownership.
	 */
	public final boolean isRetired() {
		return retirementCleanupComplete && !connectionCloseFailed && server != null && server.isClosed() && !isAlive()
				&& (connectionExecutor == null || connectionExecutor.isTerminated())
				&& (forwardExecutor == null || forwardExecutor.isTerminated())
				&& (voteForwarder == null || voteForwarder.isTerminated());
	}

	/**
	 * Closes the listener and all admitted sockets, then waits for workers within
	 * bounded drain windows. Platform-owned callbacks must return promptly.
	 */
	public void shutdown() {
		boolean ownsRetirement;
		synchronized (lifecycleLock) {
			if (retirementOwner == Thread.currentThread()) {
				return;
			}
			ownsRetirement = retirementOwner == null;
			if (ownsRetirement) {
				retirementOwner = Thread.currentThread();
				running = false;
			}
		}
		if (!ownsRetirement) {
			awaitRetirement();
			return;
		}

		try {
			retirementCleanupComplete = retire();
		} finally {
			retirementComplete.countDown();
		}
	}

	private boolean retire() {
		if (voteForwarder != null) {
			voteForwarder.sealDirectCalls();
		}
		List<Socket> sockets;
		synchronized (lifecycleLock) {
			sockets = List.copyOf(connections);
			connections.clear();
		}
		boolean listenerClosed = false;
		if (server != null) {
			try {
				server.close();
				listenerClosed = server.isClosed();
			} catch (IOException ex) {
				debug(ex);
			}
		}
		sockets.forEach(this::closeConnection);
		try {
			shutdownExecutor(connectionExecutor, "connection", null);
		} finally {
			try {
				shutdownExecutor(forwardExecutor, "forward", () -> voteForwarder.stop());
			} finally {
				if (voteForwarder != null) {
					voteForwarder.stop();
				}
			}
			long rejected = rejectedForwardingJobs.get();
			if (rejected != 0) {
				logWarning("Forwarding queue rejections at receiver retirement: " + rejected);
			}
		}
		return listenerClosed;
	}

	private void awaitRetirement() {
		try {
			if (!retirementComplete.await(4L * DRAIN_SECONDS, TimeUnit.SECONDS)) {
				logWarning("Timed out waiting for receiver retirement.");
			}
		} catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
		}
	}

	boolean isStopping() {
		return !running;
	}

	private void shutdownExecutor(ExecutorService executor, String name, IntSupplier cancelActive) {
		if (executor == null) {
			return;
		}

		executor.shutdown();
		boolean interrupted = false;
		try {
			try {
				if (executor.awaitTermination(DRAIN_SECONDS, TimeUnit.SECONDS)) {
					return;
				}
			} catch (InterruptedException ex) {
				interrupted = true;
			}
			int discarded = executor.shutdownNow().size();
			int socketCloseAttempts = cancelActive == null ? 0 : cancelActive.getAsInt();
			if (cancelActive != null && (discarded != 0 || socketCloseAttempts != 0)) {
				logWarning("Forced forwarding shutdown: discarded queued jobs=" + discarded
						+ ", active socket close attempts=" + socketCloseAttempts);
			}
			try {
				if (!executor.awaitTermination(DRAIN_SECONDS, TimeUnit.SECONDS)) {
					logWarning("Unable to fully shut down " + name + " executor.");
				}
			} catch (InterruptedException ex) {
				interrupted = true;
			}
		} finally {
			if (interrupted) {
				Thread.currentThread().interrupt();
			}
		}
	}

	public int getConnectionWorkerCount() {
		return 4;
	}

	public int getConnectionQueueCapacity() {
		return 64;
	}

	public long getConnectionQueueTimeoutMillis() {
		return 5000L;
	}

	public int getForwardWorkerCount() {
		return 1;
	}

	protected ForwardRetryConfig getForwardRetryConfig() {
		return ForwardRetryConfig.DEFAULT;
	}

	public int getForwardQueueCapacity() {
		return 256;
	}

	@Override
	public void run() {
		try {
			synchronized (lifecycleLock) {
				if (!running) {
					return;
				}
				throttleService = new VoteThrottleService(getThrottleConfig());
				int forwardWorkers = getForwardWorkerCount();
				voteForwarder = new VoteForwarder(this, forwardWorkers);
				connectionExecutor = createExecutor(getConnectionWorkerCount(), getConnectionQueueCapacity(),
						"Votifier-Connection-");
				forwardExecutor = createExecutor(forwardWorkers, getForwardQueueCapacity(), "Votifier-Forwarder-");
			}
			if (isUseTokens() && !isDisableV1()) {
				logWarning("TokenSupport is enabled, but legacy Votifier V1 votes are still accepted. "
						+ "Set DisableV1: true to require token-authenticated V2 votes.");
			}
			VoteConnectionHandler handler = new VoteConnectionHandler(this, throttleService);
			while (running) {
				try {
					submitConnection(acceptSocket(), handler);
				} catch (SocketException ex) {
					if (running) {
						logWarning("Connection error while accepting vote socket: " + VoteLogSafety.exceptionType(ex));
					}
					if (server.isClosed()) {
						break;
					}
				} catch (Exception ex) {
					if (running) {
						logWarning("Error accepting vote connection: " + VoteLogSafety.exceptionType(ex));
					}
				}
			}
		} finally {
			if (running) {
				shutdown();
			}
		}
	}

	private ThreadPoolExecutor createExecutor(int workers, int capacity, String threadPrefix) {
		return new ThreadPoolExecutor(workers, workers, 0L, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(capacity),
				new ThreadFactory() {
					private int id = 1;

					@Override
					public Thread newThread(Runnable work) {
						Thread thread = new Thread(work, threadPrefix + id++);
						thread.setDaemon(true);
						return thread;
					}
				}, new ThreadPoolExecutor.AbortPolicy());
	}

	private void submitConnection(Socket socket, VoteConnectionHandler handler) throws SocketException {
		long acceptedAtNanos = System.nanoTime();
		boolean submitted = false;
		try {
			socket.setSoTimeout(5000);
			synchronized (lifecycleLock) {
				if (!running) {
					return;
				}
				connections.add(socket);
				try {
					connectionExecutor.execute(() -> processConnection(socket, handler, acceptedAtNanos));
					submitted = true;
				} finally {
					if (!submitted) {
						connections.remove(socket);
					}
				}
			}
		} catch (RejectedExecutionException ex) {
			debug("Rejected vote connection because the connection queue is full.");
		} finally {
			if (!submitted) {
				closeConnection(socket);
			}
		}
	}

	private void processConnection(Socket socket, VoteConnectionHandler handler, long acceptedAtNanos) {
		try {
			if (!running) {
				return;
			}
			long queueTimeoutMillis = getConnectionQueueTimeoutMillis();
			if (queueTimeoutMillis > 0
					&& System.nanoTime() - acceptedAtNanos > TimeUnit.MILLISECONDS.toNanos(queueTimeoutMillis)) {
				debug("Closed stale vote connection after it exceeded the connection queue deadline.");
				return;
			}
			Vote vote = handler.handle(socket);
			if (vote != null) {
				callEvent(vote);
				submitForward(vote);
			}
		} catch (Exception ex) {
			logWarning("Error processing vote connection: " + VoteLogSafety.exceptionType(ex));
		} finally {
			closeConnection(socket);
			synchronized (lifecycleLock) {
				connections.remove(socket);
			}
		}
	}

	// Protocol OK and local delivery precede best-effort forwarding. A full
	// queue can lose forwarding but must never make ingress do outbound work.
	private void submitForward(Vote vote) {
		try {
			forwardExecutor.execute(() -> {
				try {
					voteForwarder.forwardQueuedVote(vote);
				} catch (Exception ex) {
					logWarning("Error forwarding vote: " + VoteLogSafety.exceptionType(ex));
				}
			});
		} catch (RejectedExecutionException ex) {
			long rejected = rejectedForwardingJobs.incrementAndGet();
			throttleService.logWarning(this, "forward-queue",
					"Unable to queue vote forwarding: forwarding executor is full or stopping. Total rejected jobs: "
							+ rejected);
		}
	}

	/**
	 * Accepts the next incoming connection.
	 *
	 * @return the accepted connection
	 * @throws IOException when the listener cannot accept a connection
	 */
	protected Socket acceptSocket() throws IOException {
		return server.accept();
	}

	private void closeConnection(Socket socket) {
		try {
			socket.close();
			if (!socket.isClosed()) {
				connectionCloseFailed = true;
			}
		} catch (IOException ex) {
			connectionCloseFailed = true;
			debug(ex);
		}
	}

	public abstract boolean isUseTokens();

	/**
	 * Returns whether legacy Votifier V1 packets must be rejected.
	 *
	 * @return true when only V2 votes should be accepted
	 */
	public boolean isDisableV1() {
		return VoteProtocolPolicy.isDisableV1();
	}

	public abstract ThrottleConfig getThrottleConfig();

	/** Socket peers allowed to supply PROXY protocol metadata. Empty by default. */
	public Set<String> getTrustedProxyIps() {
		return Collections.emptySet();
	}

	public abstract void logWarning(String warn);

	public abstract void logSevere(String msg);

	public abstract void log(String msg);

	public abstract void debug(String msg);

	public abstract void debug(Exception e);

	public abstract String getVersion();

	public abstract Set<String> getServers();

	public abstract KeyPair getKeyPair();

	public abstract Map<String, Key> getTokens();

	public abstract ForwardServer getServerData(String s);

	public abstract void callEvent(Vote e);

	public byte[] encrypt(byte[] data, PublicKey key) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(data);
	}

	public PublicKey getPublicKey(ForwardServer forwardServer) throws Exception {
		byte[] encoded = Base64.getDecoder().decode(forwardServer.getKey());
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
	}

	public String getChallenge() {
		return com.vexsoftware.votifier.crypto.TokenUtil.newToken();
	}
	private static final class ConfiguredReceiver extends VoteReceiver {
		private final Settings settings;
		private final Logger logger;
		private final Consumer<Vote> onVote;

		private ConfiguredReceiver(Settings settings, Logger logger, Consumer<Vote> onVote) throws Exception {
			super(settings.host(), settings.port());
			this.settings = settings;
			this.logger = logger;
			this.onVote = onVote;
		}

		@Override
		public boolean isUseTokens() {
			return settings.tokenSupport();
		}

		@Override
		public boolean isDisableV1() {
			return settings.disableV1();
		}

		@Override
		public ThrottleConfig getThrottleConfig() {
			return settings.throttle();
		}

		@Override
		public Set<String> getTrustedProxyIps() {
			return settings.trustedProxyIps();
		}

		@Override
		public void logWarning(String warning) {
			logger.warning(warning);
		}

		@Override
		public void logSevere(String message) {
			// The superclass can report bind failures before the adapter is initialized.
			Logger sink = logger == null ? Logger.getLogger(VoteReceiver.class.getName()) : logger;
			sink.severe(message);
		}

		@Override
		public void log(String message) {
			logger.info(message);
		}

		@Override
		public void debug(String message) {
			if (logger != null) {
				logger.fine(message);
			}
		}

		@Override
		public void debug(Exception exception) {
			logger.log(Level.FINE, "Vote receiver operation failed: {0}", VoteLogSafety.exceptionType(exception));
		}

		@Override
		public String getVersion() {
			return settings.version();
		}

		@Override
		public Set<String> getServers() {
			return settings.forwarding.keySet();
		}

		@Override
		public KeyPair getKeyPair() {
			return settings.keyPair();
		}

		@Override
		public Map<String, Key> getTokens() {
			return settings.tokens();
		}

		@Override
		public ForwardServer getServerData(String name) {
			ForwardServer target = settings.forwarding.get(name);
			return target == null ? null : copyTarget(target);
		}

		@Override
		public void callEvent(Vote vote) {
			try {
				onVote.accept(vote);
			} catch (RuntimeException failure) {
				logger.warning("Vote callback failed: " + VoteLogSafety.exceptionType(failure));
			}
		}

		@Override
		public void initialize() throws Exception {
			if (getServer() != null) {
				throw new IllegalStateException("Bind a new receiver to replace this listener");
			}
			super.initialize();
		}
	}

}
