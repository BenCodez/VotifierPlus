package com.vexsoftware.votifier.config;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

import org.bukkit.configuration.ConfigurationSection;

import com.bencodez.simpleapi.debug.DebugLevel;
import com.bencodez.simpleapi.file.YMLFile;
import com.bencodez.simpleapi.file.annotation.AnnotationHandler;
import com.bencodez.simpleapi.file.annotation.ConfigDataBoolean;
import com.bencodez.simpleapi.file.annotation.ConfigDataInt;
import com.bencodez.simpleapi.file.annotation.ConfigDataKeys;
import com.bencodez.simpleapi.file.annotation.ConfigDataString;
import com.vexsoftware.votifier.VotifierPlus;

import lombok.Getter;
import lombok.Setter;

public class Config extends YMLFile {

	public Config(VotifierPlus plugin) {
		super(plugin, new File(VotifierPlus.getInstance().getDataFolder(), "config.yml"));
	}

	public void loadValues() {
		new AnnotationHandler().load(getData(), this);
		debug = DebugLevel.getDebug(debugLevelStr);
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

	@ConfigDataString(path = "DebugLevel", options = { "NONE", "INFO", "EXTRA", "DEV" })
	private String debugLevelStr = "NONE";

	@Getter
	@Setter
	private DebugLevel debug = DebugLevel.NONE;

	@ConfigDataKeys(path = "Forwarding")
	@Getter
	@Setter
	private Set<String> servers = new HashSet<String>();

	@Getter
	@Setter
	@ConfigDataString(path = "Format.NoPerms")
	private String formatNoPerms = "&cYou do not have enough permission!";

	@Getter
	@Setter
	@ConfigDataString(path = "Format.NotNumber")
	private String formatNotNumber = "&cError on &6%arg%&c, number expected!";

	@Getter
	@Setter
	@ConfigDataString(path = "Format.HelpLine")
	private String helpLine = "&3&l%Command% - &3%HelpMessage%";

	@ConfigDataBoolean(path = "DisableUpdateChecking")
	@Getter
	private boolean disableUpdateChecking = false;

	public ConfigurationSection getForwardingConfiguration(String s) {
		return getData().getConfigurationSection("Forwarding." + s);
	}

}
