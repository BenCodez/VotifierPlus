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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

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

	public void initialize() throws Exception {
		try {
			server = new ServerSocket();
			server.bind(new InetSocketAddress(host, port));
			debug("Bound to " + server.getInetAddress().getHostAddress() + ":" + server.getLocalPort());
		} catch (Exception ex) {
			logSevere(
					"Error initializing vote receiver. Please verify that the configured IP address and port are not already in use.");
			ex.printStackTrace();
			throw new Exception(ex);
		}
	}

	/**
	 * Closes the listener and all admitted sockets, then waits for workers within
	 * bounded drain windows. Platform-owned callbacks must return promptly.
	 */
	public void shutdown() {
		List<Socket> sockets;
		synchronized (lifecycleLock) {
			running = false;
			sockets = List.copyOf(connections);
			connections.clear();
		}
		if (server != null) {
			try {
				server.close();
			} catch (IOException ex) {
				debug(ex);
			}
		}
		sockets.forEach(this::closeConnection);
		try {
			shutdownExecutor(connectionExecutor, "connection", () -> {});
		} finally {
			shutdownExecutor(forwardExecutor, "forward", () -> voteForwarder.stop());
		}
	}

	boolean isStopping() {
		return !running;
	}

	private void shutdownExecutor(ExecutorService executor, String name, Runnable cancelActive) {
		if (executor == null) {
			return;
		}

		executor.shutdown();
		boolean interrupted = false;
		try {
			try {
				if (executor.awaitTermination(3, TimeUnit.SECONDS)) {
					return;
				}
			} catch (InterruptedException ex) {
				interrupted = true;
			}
			cancelActive.run();
			executor.shutdownNow();
			try {
				if (!executor.awaitTermination(3, TimeUnit.SECONDS)) {
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

	public int getForwardQueueCapacity() {
		return 256;
	}

	@Override
	public void run() {
		throttleService = new VoteThrottleService(getThrottleConfig());
		voteForwarder = new VoteForwarder(this);

		if (isUseTokens() && !isDisableV1()) {
			logWarning("TokenSupport is enabled, but legacy Votifier V1 votes are still accepted. "
					+ "Set DisableV1: true to require token-authenticated V2 votes.");
		}

		synchronized (lifecycleLock) {
			if (!running) {
				return;
			}
			connectionExecutor = createExecutor(getConnectionWorkerCount(), getConnectionQueueCapacity(),
					"Votifier-Connection-");
			forwardExecutor = createExecutor(getForwardWorkerCount(), getForwardQueueCapacity(), "Votifier-Forwarder-");
		}

		VoteConnectionHandler handler = new VoteConnectionHandler(this, throttleService);
		try {
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

	private void submitForward(Vote vote) {
		try {
			forwardExecutor.execute(() -> {
				try {
					voteForwarder.forwardVote(vote);
				} catch (Exception ex) {
					logWarning("Error forwarding vote: " + VoteLogSafety.exceptionType(ex));
				}
			});
		} catch (RejectedExecutionException ex) {
			throttleService.logWarning(this, "forward-queue", "Unable to queue vote forwarding: forwarding executor is full or stopping.");
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
		} catch (IOException ex) {
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
}
