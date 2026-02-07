package com.vexsoftware.votifier.velocity;

import java.io.File;
import java.util.Collection;

import org.checkerframework.checker.nullness.qual.NonNull;
import org.spongepowered.configurate.ConfigurationNode;
import org.spongepowered.configurate.serialize.SerializationException;

import com.bencodez.simpleapi.file.velocity.VelocityYMLFile;

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
		return getNode("Forwarding").childrenMap().values();
	}

	public ConfigurationNode getServersData(String s) {
		return getNode("Forwarding", s);
	}

	public @NonNull Collection<? extends ConfigurationNode> getTokens() {
		return getNode("tokens").childrenMap().values();
	}

	public String getToken(String key) {
		return getString(getNode("tokens", key), null);
	}

	public boolean containsTokens() {
		return !getNode("tokens").virtual();
	}

	public void setToken(String key, String token) {
		try {
			getNode("tokens", key).set(token);
		} catch (SerializationException e) {
			e.printStackTrace();
		}
		save();
	}

	public boolean getTokenSupport() {
		return getBoolean(getNode("TokenSupport"), false);
	}
}
