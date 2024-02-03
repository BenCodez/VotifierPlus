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

import com.bencodez.advancedcore.folialib.FoliaLib;
import java.io.File;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URL;
import java.security.CodeSource;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.bukkit.Bukkit;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;

import com.bencodez.advancedcore.AdvancedCorePlugin;
import com.bencodez.advancedcore.api.command.CommandHandler;
import com.bencodez.advancedcore.api.metrics.BStatsMetrics;
import com.bencodez.advancedcore.api.updater.Updater;
import com.vexsoftware.votifier.commands.CommandLoader;
import com.vexsoftware.votifier.commands.CommandVotifierPlus;
import com.vexsoftware.votifier.commands.VotifierPlusTabCompleter;
import com.vexsoftware.votifier.config.Config;
import com.vexsoftware.votifier.crypto.RSAIO;
import com.vexsoftware.votifier.crypto.RSAKeygen;
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
public class VotifierPlus extends AdvancedCorePlugin {

	/** The Votifier instance. */
	private static VotifierPlus instance;

    @Getter
    private FoliaLib foliaLib;

	public Config config;

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

	@Override
	public void onPostLoad() {
        this.foliaLib = new FoliaLib(this);

		getCommand("votifierplus").setExecutor(new CommandVotifierPlus(this));
		getCommand("votifierplus").setTabCompleter(new VotifierPlusTabCompleter());
		CommandLoader.getInstance().loadCommands();

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
	}

	private void loadVoteReceiver() {
		try {
			voteReceiver = new VoteReceiver(config.getHost(), config.getPort()) {

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
					return config.getServers();
				}

				@Override
				public ForwardServer getServerData(String s) {
					ConfigurationSection d = config.getForwardingConfiguration(s);
					return new ForwardServer(d.getBoolean("Enabled"), d.getString("Host", ""), d.getInt("Port"),
							d.getString("Key", ""));
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
                    foliaLib.getImpl().runAsync(new Runnable() {
                        public void run() {
                            Bukkit.getServer().getPluginManager().callEvent(new VotifierEvent(vote));
                        }
                    });
				}
			};
			voteReceiver.start();

			getLogger().info("Votifier enabled.");
		} catch (Exception ex) {
			gracefulExit();
			return;
		}
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

	@Override
	public void onPreLoad() {
		instance = this;

		config = new Config(this);
		config.setup();

		if (config.isJustCreated()) {
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
				config.getData().set("port", openPort);
				config.saveData();

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
		}
		config.loadValues();

		updateAdvancedCoreHook();
	}

	private void metrics() {
		BStatsMetrics metrics = new BStatsMetrics(this, 5807);
		metrics.addCustomChart(new BStatsMetrics.SimplePie("Forwarding", new Callable<String>() {

			@Override
			public String call() throws Exception {
				int amount = 0;
				for (String server : config.getServers()) {
					if (config.getForwardingConfiguration(server).getBoolean("Enabled")) {
						amount++;
					}
				}
				return "" + amount;
			}
		}));
	}

	@Override
	public void onUnLoad() {

	}

	@Override
	public void reload() {
		config.reloadData();
		updateAdvancedCoreHook();
		voteReceiver.shutdown();
		loadVoteReceiver();
	}

	@SuppressWarnings("deprecation")
	public void updateAdvancedCoreHook() {
		setConfigData(config.getData());
		setLoadRewards(false);
		setLoadServerData(false);
		setLoadUserData(false);
		setLoadGeyserAPI(false);
		setLoadLuckPerms(false);
	}

}
