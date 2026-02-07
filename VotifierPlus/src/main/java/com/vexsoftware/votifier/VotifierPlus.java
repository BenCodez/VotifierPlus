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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Votifier.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.vexsoftware.votifier;

import java.io.File;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URL;
import java.security.CodeSource;
import java.security.Key;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.bukkit.Bukkit;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;

import com.bencodez.simpleapi.command.CommandHandler;
import com.bencodez.simpleapi.command.TabCompleteHandle;
import com.bencodez.simpleapi.command.TabCompleteHandler;
import com.bencodez.simpleapi.debug.DebugLevel;
import com.bencodez.simpleapi.metrics.BStatsMetrics;
import com.bencodez.simpleapi.scheduler.BukkitScheduler;
import com.bencodez.simpleapi.updater.Updater;
import com.vexsoftware.votifier.commands.CommandLoader;
import com.vexsoftware.votifier.commands.CommandVotifierPlus;
import com.vexsoftware.votifier.commands.VotifierPlusTabCompleter;
import com.vexsoftware.votifier.config.Config;
import com.vexsoftware.votifier.crypto.RSAIO;
import com.vexsoftware.votifier.crypto.RSAKeygen;
import com.vexsoftware.votifier.crypto.TokenUtil;
import com.vexsoftware.votifier.model.Vote;
import com.vexsoftware.votifier.model.VotifierEvent;
import com.vexsoftware.votifier.net.VoteReceiver;

import lombok.Getter;
import lombok.Setter;

/**
 * The main Votifier plugin class.
 * 
 * @author Blake Beaupain
 * @author Kramer Campbell
 */
public class VotifierPlus extends JavaPlugin {

	/** The Votifier instance. */
	private static VotifierPlus instance;

	@Getter
	public Config configFile;

	@Getter
	@Setter
	private Updater updater;

	/** The vote receiver. */
	private VoteReceiver voteReceiver;

	/** The RSA key pair. */
	@Setter
	private KeyPair keyPair;

	@Getter
	private ArrayList<CommandHandler> commands = new ArrayList<CommandHandler>();

	@Getter
	private String buildNumber = "NOTSET";

	@Getter
	private String profile;

	@Getter
	private String time;

	@Getter
	private BukkitScheduler bukkitScheduler;

	private HashMap<String, Key> tokens = new HashMap<String, Key>();

	private void loadTokens() {
		tokens.clear();
		if (!configFile.getData().contains("tokens")) {
			configFile.setValue("tokens.default", TokenUtil.newToken());
		}

		for (String key : configFile.getData().getConfigurationSection("tokens").getKeys(false)) {
			tokens.put(key, TokenUtil.createKeyFrom(configFile.getData().getString("tokens." + key)));
		}
	}

	@Override
	public void onEnable() {
		instance = this;
		bukkitScheduler = new BukkitScheduler(instance);

		configFile = new Config(this);
		configFile.setup();

		if (configFile.isJustCreated()) {
			int openPort = 8192;
			try {
				ServerSocket s = new ServerSocket();
				s.bind(new InetSocketAddress("0.0.0.0", 0));
				openPort = s.getLocalPort();
				s.close();
			} catch (Exception e) {

			}
			try {
				// First time run - do some initialization.
				getLogger().info("Configuring Votifier for the first time...");
				configFile.getData().set("port", openPort);
				configFile.saveData();

				/*
				 * Remind hosted server admins to be sure they have the right port number.
				 */
				getLogger().info("------------------------------------------------------------------------------");
				getLogger().info("Assigning Votifier to listen on an open port " + openPort
						+ ". If you are hosting server on a");
				getLogger().info("shared server please check with your hosting provider to verify that this port");
				getLogger().info("is available for your use. Chances are that your hosting provider will assign");
				getLogger().info("a different port, which you need to specify in config.yml");
				getLogger().info("------------------------------------------------------------------------------");

			} catch (Exception ex) {
				getLogger().severe("Error creating configuration file");
				debug(ex);
			}

			configFile.setValue("tokens.default", TokenUtil.newToken());
		}
		configFile.loadValues();
		loadTokens();

		loadVersionFile();

		getCommand("votifierplus").setExecutor(new CommandVotifierPlus(this));
		getCommand("votifierplus").setTabCompleter(new VotifierPlusTabCompleter());
		CommandLoader.getInstance().loadCommands();
		loadTabComplete();

		File rsaDirectory = new File(getDataFolder() + "/rsa");

		/*
		 * Create RSA directory and keys if it does not exist; otherwise, read keys.
		 */
		try {
			if (!rsaDirectory.exists()) {
				rsaDirectory.mkdir();
				keyPair = RSAKeygen.generate(2048);
				RSAIO.save(rsaDirectory, keyPair);
			} else {
				keyPair = RSAIO.load(rsaDirectory);
			}
		} catch (Exception ex) {
			getLogger().severe("Error reading configuration file or RSA keys");
			gracefulExit();
			return;
		}

		loadVoteReceiver();

		metrics();

		getBukkitScheduler().runTaskLaterAsynchronously(this, new Runnable() {

			@Override
			public void run() {
				new CheckUpdate(instance).checkUpdate();
			}
		}, 5);

		if (getProfile().contains("dev")) {
			getLogger().info(
					"Using dev build, this is not a stable build, use at your own risk. Build number: " + buildNumber);
		}
	}

	public void loadTabComplete() {
		TabCompleteHandler.getInstance()
				.addTabCompleteOption(new TabCompleteHandle("(Player)", new ArrayList<String>()) {

					@Override
					public void reload() {
						ArrayList<String> list = new ArrayList<String>();
						for (Player player : Bukkit.getOnlinePlayers()) {
							list.add(player.getName());
						}
						setReplace(list);
					}

					@Override
					public void updateReplacements() {
						ArrayList<String> list = new ArrayList<String>();
						for (Player player : Bukkit.getOnlinePlayers()) {
							list.add(player.getName());
						}
						setReplace(list);
					}
				}.updateOnLoginLogout());

		TabCompleteHandler.getInstance()
				.addTabCompleteOption(new TabCompleteHandle("(PlayerExact)", new ArrayList<String>()) {

					@Override
					public void reload() {
						ArrayList<String> list = new ArrayList<String>();
						for (Player player : Bukkit.getOnlinePlayers()) {
							list.add(player.getName());
						}
						setReplace(list);
					}

					@Override
					public void updateReplacements() {
						ArrayList<String> list = new ArrayList<String>();
						for (Player player : Bukkit.getOnlinePlayers()) {
							list.add(player.getName());
						}
						setReplace(list);
					}
				}.updateOnLoginLogout());

		ArrayList<String> options = new ArrayList<String>();
		options.add("True");
		options.add("False");
		TabCompleteHandler.getInstance().addTabCompleteOption("(Boolean)", options);
		options = new ArrayList<String>();
		TabCompleteHandler.getInstance().addTabCompleteOption("(List)", options);
		TabCompleteHandler.getInstance().addTabCompleteOption("(String)", options);
		TabCompleteHandler.getInstance().addTabCompleteOption("(Text)", options);
		TabCompleteHandler.getInstance().addTabCompleteOption("(Number)", options);

	}

	private void loadVoteReceiver() {
		try {
			voteReceiver = new VoteReceiver(configFile.getHost(), configFile.getPort()) {

				@Override
				public void logWarning(String warn) {
					getLogger().warning(warn);
				}

				@Override
				public void logSevere(String msg) {
					getLogger().severe(msg);
				}

				@Override
				public void log(String msg) {
					getLogger().info(msg);
				}

				@Override
				public String getVersion() {
					return getDescription().getVersion();
				}

				@Override
				public Set<String> getServers() {
					return configFile.getServers();
				}

				@Override
				public ForwardServer getServerData(String s) {
					ConfigurationSection d = configFile.getForwardingConfiguration(s);
					String token = d.getString("Token", "");
					Key tokenKey = null;
					if (!token.isEmpty()) {
						tokenKey = TokenUtil.createKeyFrom(token);
					}
					return new ForwardServer(d.getBoolean("Enabled"), d.getString("Host", ""), d.getInt("Port"),
							d.getString("Key", ""), tokenKey);
				}

				@Override
				public KeyPair getKeyPair() {
					return instance.getKeyPair();
				}

				@Override
				public void debug(Exception e) {
					instance.debug(e);
				}

				@Override
				public void debug(String debug) {
					instance.debug(debug);
				}

				@Override
				public void callEvent(Vote vote) {
					getBukkitScheduler().executeOrScheduleSync(instance, new Runnable() {
						public void run() {
							Bukkit.getServer().getPluginManager().callEvent(new VotifierEvent(vote));
						}
					});
				}

				@Override
				public Map<String, Key> getTokens() {
					return tokens;
				}

				@Override
				public boolean isUseTokens() {
					return configFile.isTokenSupport();
				}

				@Override
				public ThrottleConfig getThrottleConfig() {
					ConfigurationSection root = getConfigFile().getData().getConfigurationSection("ConnectionThrottle");

					if (root == null) {
						return new ThrottleConfig(false, Collections.<String>emptySet(), "2m", 20, "5m", 8, "10m", true,
								6, "15m", "60s");
					}

					boolean enabled = root.getBoolean("Enabled", true);

					java.util.List<String> ips = root.getStringList("TunnelRemoteIps");
					java.util.Set<String> tunnelIps = new java.util.HashSet<String>();
					if (ips != null) {
						for (String s : ips) {
							if (s != null) {
								s = s.trim();
								if (!s.isEmpty())
									tunnelIps.add(s);
							}
						}
					}
					if (tunnelIps.isEmpty())
						tunnelIps = Collections.<String>emptySet();
					else
						tunnelIps = Collections.unmodifiableSet(tunnelIps);

					String window = root.getString("Window", "2m");
					int failures = root.getInt("Failures", 20);
					String throttleFor = root.getString("ThrottleFor", "5m");

					int tunnelFailures = root.getInt("TunnelFailures", Math.max(3, failures / 2));
					String tunnelThrottleFor = root.getString("TunnelThrottleFor", "10m");

					ConfigurationSection ban = root.getConfigurationSection("PerClientBan");
					boolean banEnabled = ban == null ? true : ban.getBoolean("Enabled", true);
					int banFailures = ban == null ? 6 : ban.getInt("Failures", 6);
					String banFor = ban == null ? "15m" : ban.getString("BanFor", "15m");

					String logWindow = root.getString("LogWindow", "60s");

					return new ThrottleConfig(enabled, tunnelIps, window, failures, throttleFor, tunnelFailures,
							tunnelThrottleFor, banEnabled, banFailures, banFor, logWindow);
				}

			};
			voteReceiver.start();

			getLogger().info("Votifier enabled.");
		} catch (Exception ex) {
			gracefulExit();
			return;
		}
	}

	public void debug(DebugLevel debugLevel, String debug) {
		if (debugLevel.equals(DebugLevel.EXTRA)) {
			debug = "ExtraDebug: " + debug;
		} else if (debugLevel.equals(DebugLevel.INFO)) {
			debug = "Debug: " + debug;
		} else if (debugLevel.equals(DebugLevel.DEV)) {
			debug = "Developer Debug: " + debug;
		}

		if (configFile.getDebug().isDebug(debugLevel)) {
			getLogger().info(debug);
		}
	}

	/**
	 * Show exception in console if debug is on
	 *
	 * @param e Exception
	 */
	public void debug(Exception e) {
		if (getConfigFile().getDebug().isDebug()) {
			e.printStackTrace();
		}
	}

	public void debug(String debug) {
		debug(DebugLevel.INFO, debug);
	}

	public void devDebug(String debug) {
		debug(DebugLevel.DEV, debug);
	}

	public void extraDebug(String debug) {
		debug(DebugLevel.EXTRA, debug);
	}

	@Override
	public void onDisable() {
		// Interrupt the vote receiver.
		if (voteReceiver != null) {
			voteReceiver.shutdown();
		}
		getLogger().info("Votifier disabled.");
	}

	private void gracefulExit() {
		getLogger().severe("Votifier did not initialize properly!");
	}

	/**
	 * Gets the instance.
	 * 
	 * @return The instance
	 */
	public static VotifierPlus getInstance() {
		return instance;
	}

	/**
	 * Gets the vote receiver.
	 * 
	 * @return The vote receiver
	 */
	public VoteReceiver getVoteReceiver() {
		return voteReceiver;
	}

	/**
	 * Gets the keyPair.
	 * 
	 * @return The keyPair
	 */
	public KeyPair getKeyPair() {
		return keyPair;
	}

	private void metrics() {
		BStatsMetrics metrics = new BStatsMetrics(this, 5807);
		metrics.addCustomChart(new BStatsMetrics.SimplePie("Forwarding", new Callable<String>() {

			@Override
			public String call() throws Exception {
				int amount = 0;
				for (String server : configFile.getServers()) {
					if (configFile.getForwardingConfiguration(server).getBoolean("Enabled")) {
						amount++;
					}
				}
				return "" + amount;
			}
		}));
		if (!getBuildNumber().equals("NOTSET")) {
			metrics.addCustomChart(new BStatsMetrics.SimplePie("dev_build_number", new Callable<String>() {

				@Override
				public String call() throws Exception {
					return "" + getBuildNumber();
				}
			}));
		}
	}

	public void reload() {
		voteReceiver.shutdown();
		configFile.reloadData();
		loadTokens();
		loadVoteReceiver();
	}

	private YamlConfiguration getVersionFile() {
		try {
			CodeSource src = this.getClass().getProtectionDomain().getCodeSource();
			if (src != null) {
				URL jar = src.getLocation();
				ZipInputStream zip = null;
				zip = new ZipInputStream(jar.openStream());
				while (true) {
					ZipEntry e = zip.getNextEntry();
					if (e != null) {
						String name = e.getName();
						if (name.equals("votifierplusversion.yml")) {
							Reader defConfigStream = new InputStreamReader(zip);
							if (defConfigStream != null) {
								YamlConfiguration defConfig = YamlConfiguration.loadConfiguration(defConfigStream);
								defConfigStream.close();
								return defConfig;
							}
						}
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private void loadVersionFile() {
		YamlConfiguration conf = getVersionFile();
		if (conf != null) {
			time = conf.getString("time", "");
			profile = conf.getString("profile", "");
			buildNumber = conf.getString("buildnumber", "NOTSET");
		}
	}

}
