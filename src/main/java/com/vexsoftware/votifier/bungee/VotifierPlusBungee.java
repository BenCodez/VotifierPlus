package com.vexsoftware.votifier.bungee;

import java.io.File;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;
import java.security.CodeSource;
import java.security.KeyPair;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.crypto.RSAIO;
import com.vexsoftware.votifier.crypto.RSAKeygen;
import com.vexsoftware.votifier.model.Vote;
import com.vexsoftware.votifier.net.VoteReceiver;

import lombok.Getter;
import lombok.Setter;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.config.Configuration;
import net.md_5.bungee.config.ConfigurationProvider;

public class VotifierPlusBungee extends Plugin {
	private VotifierPlusBungee instance;
	@Getter
	private VoteReceiver voteReceiver;
	@Getter
	private Config config;
	@Getter
	@Setter
	private KeyPair keyPair;
	private String buildNumber;

	@Override
	public void onEnable() {
		instance = this;
		config = new Config(this);
		config.load();
		getProxy().getPluginManager().registerCommand(this, new VotifierPlusCommand(this));
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
			return;
		}

		BStatsMetricsBungee metrics = new BStatsMetricsBungee(this, 20283);
		loadVersionFile();
		if (!buildNumber.equals("NOTSET")) {
			metrics.addCustomChart(new BStatsMetricsBungee.SimplePie("dev_build_number", () -> "" + buildNumber));
		}

		loadVoteReceiver();
	}

	private Configuration getVersionFile() {
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
								Configuration conf = ConfigurationProvider
										.getProvider(net.md_5.bungee.config.YamlConfiguration.class)
										.load(defConfigStream);

								defConfigStream.close();
								return conf;
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

	public void loadVersionFile() {
		Configuration conf = getVersionFile();
		if (conf != null) {
			buildNumber = conf.get("buildnumber", "NOTSET");
		}
	}

	public void reload() {
		config.load();
		loadVoteReceiver();
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
					Configuration d = config.getServerData(s);
					return new ForwardServer(d.getBoolean("Enabled"), d.getString("Host", ""), d.getInt("Port"),
							d.getString("Key", ""));
				}

				@Override
				public KeyPair getKeyPair() {
					return instance.getKeyPair();
				}

				@Override
				public void debug(Exception e) {
					if (config.getDebug()) {
						e.printStackTrace();
					}
				}

				@Override
				public void debug(String debug) {
					if (config.getDebug()) {
						getLogger().info("Debug: " + debug);
					}
				}

				@Override
				public void callEvent(Vote vote) {
					getProxy().getPluginManager()
							.callEvent(new com.vexsoftware.votifier.bungee.events.VotifierEvent(vote));
				}
			};
			voteReceiver.start();

			getLogger().info("Votifier enabled.");
		} catch (Exception ex) {
			return;
		}
	}

}
