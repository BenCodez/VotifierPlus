package com.vexsoftware.votifier.config;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

import org.bukkit.configuration.ConfigurationSection;

import com.bencodez.advancedcore.api.yml.YMLFile;
import com.bencodez.advancedcore.api.yml.annotation.AnnotationHandler;
import com.bencodez.advancedcore.api.yml.annotation.ConfigDataBoolean;
import com.bencodez.advancedcore.api.yml.annotation.ConfigDataInt;
import com.bencodez.advancedcore.api.yml.annotation.ConfigDataKeys;
import com.bencodez.advancedcore.api.yml.annotation.ConfigDataString;
import com.vexsoftware.votifier.VotifierPlus;

import lombok.Getter;
import lombok.Setter;

public class Config extends YMLFile {

	public Config(VotifierPlus plugin) {
		super(plugin, new File(VotifierPlus.getInstance().getDataFolder(), "config.yml"));
	}

	public void loadValues() {
		new AnnotationHandler().load(getData(), this);
	}

	@Override
	public void onFileCreation() {
		VotifierPlus.getInstance().saveResource("config.yml", true);
	}

	@ConfigDataString(path = "host")
	@Getter
	@Setter
	private String host = "0.0.0.0";

	@ConfigDataInt(path = "port")
	@Getter
	@Setter
	private int port = 8192;

	@ConfigDataBoolean(path = "debug")
	@Getter
	@Setter
	private boolean debug = false;

	@ConfigDataKeys(path = "Forwarding")
	@Getter
	@Setter
	private Set<String> servers = new HashSet<String>();

	@ConfigDataBoolean(path = "DisableUpdateChecking")
	@Getter
	private boolean disableUpdateChecking = false;

	public ConfigurationSection getForwardingConfiguration(String s) {
		return getData().getConfigurationSection("Forwarding." + s);
	}

}
