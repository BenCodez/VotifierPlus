package com.vexsoftware.votifier.velocity;

import java.io.File;
import java.util.Collection;

import org.checkerframework.checker.nullness.qual.NonNull;

import com.bencodez.advancedcore.bungeeapi.velocity.VelocityYMLFile;

import ninja.leaping.configurate.ConfigurationNode;

public class Config extends VelocityYMLFile {

	public Config(File file) {
		super(file);
	}

	public String getHost() {
		return getString(getNode("host"), "");
	}

	public int getPort() {
		return getInt(getNode("port"), 0);
	}

	public boolean getDebug() {
		return getBoolean(getNode("Debug"), false);
	}

	public @NonNull Collection<? extends ConfigurationNode> getServers() {
		return getNode("Forwarding").getChildrenMap().values();
	}
	
	public ConfigurationNode getServersData(String s) {
		return getNode("Forwarding", s);
	}

}
