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

package com.vexsoftware.votifier.net;

import java.io.BufferedWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

import org.bukkit.Bukkit;
import org.bukkit.configuration.ConfigurationSection;

import com.vexsoftware.votifier.VotifierPlus;
import com.vexsoftware.votifier.crypto.RSA;
import com.vexsoftware.votifier.model.Vote;
import com.vexsoftware.votifier.model.VotifierEvent;

/**
 * The vote receiving server.
 * 
 * @author Blake Beaupain
 * @author Kramer Campbell
 */
public class VoteReceiver extends Thread {

	private final VotifierPlus plugin;

	/** The host to listen on. */
	private final String host;

	/** The port to listen on. */
	private final int port;

	/** The server socket. */
	private ServerSocket server;

	/** The running flag. */
	private boolean running = true;

	/**
	 * Instantiates a new vote receiver.
	 * 
	 * @param plugin
	 *            plugin
	 * 
	 * @param host
	 *            The host to listen on
	 * @param port
	 *            The port to listen on
	 * @throws Exception
	 *             exception
	 */
	public VoteReceiver(final VotifierPlus plugin, String host, int port) throws Exception {
		super("Votifier I/O");
		this.plugin = plugin;
		this.host = host;
		this.port = port;

		setPriority(Thread.MIN_PRIORITY);

		initialize();
	}

	private void initialize() throws Exception {
		try {
			server = new ServerSocket();
			server.bind(new InetSocketAddress(host, port));
			plugin.debug(server.getInetAddress().getHostAddress() + ":" + server.getLocalPort());
		} catch (Exception ex) {
			plugin.getLogger().severe("Error initializing vote receiver. Please verify that the configured");
			plugin.getLogger().severe("IP address and port are not already in use. This is a common problem");
			plugin.getLogger().severe("with hosting services and, if so, you should check with your hosting provider.");
			ex.printStackTrace();
			throw new Exception(ex);
		}
	}

	/**
	 * Shuts the vote receiver down cleanly.
	 */
	public void shutdown() {
		running = false;
		if (server == null)
			return;
		try {
			server.close();
		} catch (Exception ex) {
			plugin.getLogger().warning("Unable to shut down vote receiver cleanly.");
		}
	}

	@Override
	public void run() {

		// Main loop.
		while (running) {
			try (Socket socket = server.accept()) {
				socket.setSoTimeout(5000); // Don't hang on slow connections.
				BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
				InputStream in = socket.getInputStream();

				// Send them our version.
				writer.write("VOTIFIERPLUS " + plugin.getVersion());
				writer.newLine();
				writer.flush();

				// Read the 256 byte block.
				byte[] block = new byte[256];
				in.read(block, 0, block.length);

				// Decrypt the block.
				block = RSA.decrypt(block, plugin.getKeyPair().getPrivate());
				int position = 0;

				// Perform the opcode check.
				String opcode = readString(block, position);
				position += opcode.length() + 1;
				if (!opcode.equals("VOTE")) {
					// Something went wrong in RSA.
					throw new Exception("Unable to decode RSA");
				}

				// Parse the block.
				String serviceName = readString(block, position);
				position += serviceName.length() + 1;
				String username = readString(block, position);
				position += username.length() + 1;
				String address = readString(block, position);
				position += address.length() + 1;
				String timeStamp = readString(block, position);
				position += timeStamp.length() + 1;

				// Create the vote.
				final Vote vote = new Vote();
				vote.setServiceName(serviceName);
				vote.setUsername(username);
				vote.setAddress(address);
				vote.setTimeStamp(timeStamp);

				if (timeStamp.equalsIgnoreCase("TestVote")) {
					plugin.getLogger().info("Test vote received");
				}

				plugin.debug("Received vote record -> " + vote);

				for (String server : plugin.config.getServers()) {
					ConfigurationSection d = plugin.config.getForwardingConfiguration(server);
					if (d.getBoolean("Enabled", false)) {
						plugin.debug("Sending vote to " + server);
						byte[] encodedPublicKey = DatatypeConverter.parseBase64Binary(d.getString("Key", ""));
						KeyFactory keyFactory = KeyFactory.getInstance("RSA");
						X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
						PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
						String serverIP = d.getString("Host", "");
						int serverPort = d.getInt("Port", 0);
						if (serverIP.length() != 0) {
							try {
								String VoteString = "VOTE\n" + vote.getServiceName() + "\n" + vote.getUsername() + "\n"
										+ vote.getAddress() + "\n" + vote.getTimeStamp() + "\n";

								SocketAddress sockAddr = new InetSocketAddress(serverIP, serverPort);
								Socket socket1 = new Socket();
								socket1.connect(sockAddr, 1000);
								OutputStream socketOutputStream = socket1.getOutputStream();
								socketOutputStream.write(encrypt(VoteString.getBytes(), publicKey));
								socketOutputStream.close();
								socket1.close();

							} catch (Exception e) {
								plugin.getLogger().info("Failed to send vote to " + server + "(" + serverIP + ":"
										+ serverPort + "): " + vote.toString() + ", ignore this if server is offline");
							}
						}

					}
				}

				// Call event in a synchronized fashion to ensure that the
				// custom event runs in the
				// the main server thread, not this one.
				plugin.getServer().getScheduler().scheduleSyncDelayedTask(plugin, new Runnable() {
					public void run() {
						Bukkit.getServer().getPluginManager().callEvent(new VotifierEvent(vote));
					}
				});

				// Clean up.
				writer.close();
				in.close();
				socket.close();
			} catch (SocketException ex) {
				plugin.getLogger().warning("Protocol error. Ignoring packet - " + ex.getLocalizedMessage());
				plugin.debug(ex);
			} catch (BadPaddingException ex) {
				plugin.getLogger().warning("Unable to decrypt vote record. Make sure that that your public key");
				plugin.getLogger().warning("matches the one you gave the server list.");
				plugin.debug(ex);
			} catch (Exception ex) {
				plugin.getLogger().warning("Exception caught while receiving a vote notification");
				plugin.debug(ex);
			}
		}

	}

	public byte[] encrypt(byte[] data, PublicKey key) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(data);
	}

	/**
	 * Reads a string from a block of data.
	 * 
	 * @param data
	 *            The data to read from
	 * @return The string
	 */
	private String readString(byte[] data, int offset) {
		StringBuilder builder = new StringBuilder();
		for (int i = offset; i < data.length; i++) {
			if (data[i] == '\n')
				break; // Delimiter reached.
			builder.append((char) data[i]);
		}
		return builder.toString();
	}
}
