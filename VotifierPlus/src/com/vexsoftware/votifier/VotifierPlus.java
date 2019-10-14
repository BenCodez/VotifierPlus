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
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.security.KeyPair;
import java.util.ArrayList;

import com.Ben12345rocks.AdvancedCore.AdvancedCorePlugin;
import com.Ben12345rocks.AdvancedCore.CommandAPI.CommandHandler;
import com.vexsoftware.votifier.commands.CommandLoader;
import com.vexsoftware.votifier.commands.CommandVotifierPlus;
import com.vexsoftware.votifier.commands.VotifierPlusTabCompleter;
import com.vexsoftware.votifier.config.Config;
import com.vexsoftware.votifier.crypto.RSAIO;
import com.vexsoftware.votifier.crypto.RSAKeygen;
import com.vexsoftware.votifier.net.VoteReceiver;

import lombok.Getter;

/**
 * The main Votifier plugin class.
 * 
 * @author Blake Beaupain
 * @author Kramer Campbell
 */
public class VotifierPlus extends AdvancedCorePlugin {

	/** The Votifier instance. */
	private static VotifierPlus instance;

	public Config config;

	/** The vote receiver. */
	private VoteReceiver voteReceiver;

	/** The RSA key pair. */
	private KeyPair keyPair;

	@Getter
	private ArrayList<CommandHandler> commands = new ArrayList<CommandHandler>();

	@Override
	public void onPostLoad() {

		getCommand("votifierplus").setExecutor(new CommandVotifierPlus(this));
		getCommand("votifierplus").setTabCompleter(new VotifierPlusTabCompleter());
		CommandLoader.getInstance().loadCommands();

		File rsaDirectory = new File(getDataFolder() + "/rsa");

		/*
		 * Create RSA directory and keys if it does not exist; otherwise, read
		 * keys.
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
	}

	private void loadVoteReceiver() {
		try {
			voteReceiver = new VoteReceiver(this, config.getHost(), config.getPort());
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
		VotifierPlus.instance = this;

		config = new Config();
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
				 * Remind hosted server admins to be sure they have the right
				 * port number.
				 */
				getLogger().info("------------------------------------------------------------------------------");
				getLogger().info("Assigning Votifier to listen on an open port " + openPort
						+ ". If you are hosting Craftbukkit on a");
				getLogger().info("shared server please check with your hosting provider to verify that this port");
				getLogger().info("is available for your use. Chances are that your hosting provider will assign");
				getLogger().info("a different port, which you need to specify in config.yml");
				getLogger().info("------------------------------------------------------------------------------");

			} catch (Exception ex) {
				VotifierPlus.getInstance().getLogger().severe("Error creating configuration file");
				VotifierPlus.getInstance().debug(ex);
			}
		}
		config.loadValues();

		updateAdvancedCoreHook();

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

	public void updateAdvancedCoreHook() {
		// getJavascriptEngine().put("VotingPlugin", this);
		// allowDownloadingFromSpigot(15358);
		setConfigData(config.getData());
		setLoadRewards(false);
		setLoadServerData(false);
		setLoadUserData(false);
	}

}
