package com.vexsoftware.votifier.velocity;

import java.io.File;
import java.util.Collection;

import org.checkerframework.checker.nullness.qual.NonNull;
import org.spongepowered.configurate.ConfigurationNode;
import org.spongepowered.configurate.serialize.SerializationException;

import com.bencodez.simpleapi.file.velocity.VelocityYMLFile;
import com.vexsoftware.votifier.net.VoteProtocolPolicy;

public class Config extends VelocityYMLFile {

	public Config(File file) {
		super(file);
		VoteProtocolPolicy.setDisableV1(getDisableV1());
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
		return getString(getNode("tokens", key), "");
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
		VoteProtocolPolicy.setDisableV1(getDisableV1());
		return getBoolean(getNode("TokenSupport"), false);
	}

	public boolean getDisableV1() {
		return getBoolean(getNode("DisableV1"), false);
	}
}
