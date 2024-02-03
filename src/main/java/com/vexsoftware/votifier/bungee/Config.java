package com.vexsoftware.votifier.bungee;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Set;

import lombok.Getter;
import net.md_5.bungee.config.Configuration;
import net.md_5.bungee.config.ConfigurationProvider;
import net.md_5.bungee.config.YamlConfiguration;

public class Config {
	private VotifierPlusBungee bungee;
	@Getter
	private Configuration data;

	public Config(VotifierPlusBungee bungee) {
		this.bungee = bungee;
	}

	public void load() {
		if (!bungee.getDataFolder().exists())
			bungee.getDataFolder().mkdir();

		File file = new File(bungee.getDataFolder(), "bungeeconfig.yml");

		if (!file.exists()) {
			try (InputStream in = bungee.getResourceAsStream("bungeeconfig.yml")) {
				Files.copy(in, file.toPath());
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		try {
			data = ConfigurationProvider.getProvider(YamlConfiguration.class)
					.load(new File(bungee.getDataFolder(), "bungeeconfig.yml"));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void save() {
		try {
			ConfigurationProvider.getProvider(YamlConfiguration.class).save(data,
					new File(bungee.getDataFolder(), "bungeeconfig.yml"));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public String getHost() {
		return getData().getString("host", "");
	}

	public int getPort() {
		return getData().getInt("port");
	}

	public boolean getDebug() {
		return getData().getBoolean("Debug", false);
	}

	public Set<String> getServers() {
		return (Set<String>) getData().getSection("Forwarding").getKeys();
	}

	public Configuration getServerData(String s) {
		return getData().getSection("Forwarding." + s);
	}

}
