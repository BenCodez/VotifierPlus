package com.vexsoftware.votifier.velocity;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;
import java.nio.file.Path;
import java.security.CodeSource;
import java.security.KeyPair;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.bstats.charts.SimplePie;
import org.bstats.velocity.Metrics;
import org.slf4j.Logger;

import com.google.inject.Inject;
import com.velocitypowered.api.command.CommandMeta;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.crypto.RSAIO;
import com.vexsoftware.votifier.crypto.RSAKeygen;
import com.vexsoftware.votifier.model.Vote;
import com.vexsoftware.votifier.net.VoteReceiver;

import lombok.Getter;
import lombok.Setter;
import ninja.leaping.configurate.ConfigurationNode;
import ninja.leaping.configurate.yaml.YAMLConfigurationLoader;

@Plugin(id = "votifierplus", name = "VotifierPlus", version = "1.0", url = "https://www.spigotmc.org/resources/votifierplus.74040", description = "Votifier Velocity Version", authors = {
		"BenCodez" })
public class VotifierPlusVelocity {
	@Getter
	private VoteReceiver voteReceiver;
	@Getter
	private Config config;
	@Getter
	@Setter
	private KeyPair keyPair;
	private ProxyServer server;
	private Logger logger;
	@Getter
	private Path dataDirectory;
	private final Metrics.Factory metricsFactory;
	private Object buildNumber = "NOTSET";
	private String version;
	private File versionFile;

	@Inject
	public VotifierPlusVelocity(ProxyServer server, Logger logger, Metrics.Factory metricsFactory,
			@DataDirectory Path dataDirectory) {
		this.server = server;
		this.logger = logger;
		this.dataDirectory = dataDirectory;
		this.metricsFactory = metricsFactory;
	}

	@Subscribe
	public void onProxyDisable(ProxyShutdownEvent event) {
		voteReceiver.shutdown();
	}

	private void getVersionFile() {
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
								versionFile = new File(dataDirectory.toFile(),
										"tmp" + File.separator + "votifierplusversion.yml");
								if (!versionFile.exists()) {
									versionFile.getParentFile().mkdirs();
									versionFile.createNewFile();
								}
								FileWriter fileWriter = new FileWriter(versionFile);

								int charVal;
								while ((charVal = defConfigStream.read()) != -1) {
									fileWriter.append((char) charVal);
								}

								fileWriter.close();
								YAMLConfigurationLoader loader = YAMLConfigurationLoader.builder().setFile(versionFile)
										.build();
								defConfigStream.close();
								ConfigurationNode node = loader.load();
								if (node != null) {
									version = node.getNode("version").getString("");
									buildNumber = node.getNode("buildnumber").getString("NOTSET");
								}
								return;
							}
						}
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Subscribe
	public void onProxyInitialization(ProxyInitializeEvent event) {
		File configFile = new File(dataDirectory.toFile(), "bungeeconfig.yml");
		configFile.getParentFile().mkdirs();
		if (!configFile.exists()) {
			try {
				configFile.createNewFile();
			} catch (IOException e) {
				e.printStackTrace();
			}

			InputStream toCopyStream = VotifierPlusVelocity.class.getClassLoader()
					.getResourceAsStream("bungeeconfig.yml");

			try (FileOutputStream fos = new FileOutputStream(configFile)) {
				byte[] buf = new byte[2048];
				int r;
				while (-1 != (r = toCopyStream.read(buf))) {
					fos.write(buf, 0, r);
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		config = new Config(configFile);

		CommandMeta meta = server.getCommandManager().metaBuilder("votifierplusbungee")
				// Specify other aliases (optional)
				.aliases("votifierplus", "votifierplusvelocity").build();
		server.getCommandManager().register(meta, new VotifierPlusVelocityCommand(this));
		loadVoteReceiver();
		File rsaDirectory = new File(dataDirectory.toFile(), "rsa");
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
			logger.error("Error reading configuration file or RSA keys");
			return;
		}

		try {
			getVersionFile();
			if (versionFile != null) {
				versionFile.delete();
				versionFile.getParentFile().delete();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		Metrics metrics = metricsFactory.make(this, 20282);
		metrics.addCustomChart(new SimplePie("plugin_version", () -> "" + version));
		if (!buildNumber.equals("NOTSET")) {
			metrics.addCustomChart(new SimplePie("dev_build_number", () -> "" + buildNumber));
		}

		logger.info("VotingPlugin velocity loaded, " + "Internal Jar Version: " + version);
		if (!buildNumber.equals("NOTSET")) {
			logger.info("Detected using dev build number: " + buildNumber);
		}

	}

	private void loadVoteReceiver() {
		try {
			voteReceiver = new VoteReceiver(config.getHost(), config.getPort()) {

				@Override
				public void logWarning(String warn) {
					logger.warn(warn);
				}

				@Override
				public void logSevere(String msg) {
					logger.error(msg);
				}

				@Override
				public void log(String msg) {
					logger.info(msg);
				}

				@Override
				public String getVersion() {
					return version;
				}

				@Override
				public Set<String> getServers() {
					Set<String> servers = new HashSet<String>();
					for (ConfigurationNode node : config.getServers()) {
						servers.add(node.getKey().toString());
					}
					return servers;
				}

				@Override
				public ForwardServer getServerData(String s) {
					ConfigurationNode d = config.getServersData(s);
					return new ForwardServer(d.getNode("Enabled").getBoolean(), d.getNode("Host").getString(),
							d.getNode("Port").getInt(), d.getNode("Key").getString());
				}

				@Override
				public KeyPair getKeyPair() {
					return keyPair;
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
						logger.info("Debug: " + debug);
					}
				}

				@Override
				public void callEvent(Vote vote) {
					server.getEventManager().fire(new com.vexsoftware.votifier.velocity.event.VotifierEvent(vote));
				}
			};
			voteReceiver.start();

			logger.info("Votifier enabled.");
		} catch (Exception ex) {
			return;
		}
	}

	public void reload() {
		config.reload();
		loadVoteReceiver();
	}
}
