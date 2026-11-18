package com.vexsoftware.votifier.net;

import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.model.Vote;

/** Platform-neutral adapter for the shared listener and forwarding runtime. */
public final class PlatformVoteReceiver extends VoteReceiver {

	/**
	 * Binds a receiver using explicit per-listener settings. Start it with
	 * {@link VoteReceiver#start()} and retire it with {@link VoteReceiver#shutdown()}.
	 *
	 * <p>The callback is invoked on a connection worker before forwarding and may
	 * run concurrently for different votes. It should enqueue platform work on
	 * the appropriate scheduler and return promptly. Treat the vote as read-only
	 * because forwarding uses the same object. The adapter owns the lifecycle of
	 * work it enqueues on its scheduler.
	 *
	 * @param settings listener configuration and protocol policy
	 * @param logger logger for the receiver
	 * @param onVote callback for a parsed, accepted vote
	 * @return bound, unstarted receiver
	 * @throws Exception if the listener cannot bind
	 */
	public static PlatformVoteReceiver bind(Settings settings, Logger logger, Consumer<Vote> onVote) throws Exception {
		return new PlatformVoteReceiver(Objects.requireNonNull(settings), Objects.requireNonNull(logger),
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
			return "PlatformVoteReceiver.Settings";
		}
	}

	private static ForwardServer copyTarget(ForwardServer target) {
		return new ForwardServer(target.isEnabled(), target.getHost(), target.getPort(), target.getKey(),
				target.getToken());
	}

	private final Settings settings;
	private final Logger logger;
	private final Consumer<Vote> onVote;

	private PlatformVoteReceiver(Settings settings, Logger logger, Consumer<Vote> onVote) throws Exception {
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
		Logger sink = logger == null ? Logger.getLogger(PlatformVoteReceiver.class.getName()) : logger;
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
		onVote.accept(vote);
	}

	@Override
	public void initialize() throws Exception {
		try {
			super.initialize();
		} catch (Exception failure) {
			if (getServer() != null) {
				try {
					getServer().close();
				} catch (IOException closeFailure) {
					failure.addSuppressed(closeFailure);
				}
			}
			throw failure;
		}
	}
}
