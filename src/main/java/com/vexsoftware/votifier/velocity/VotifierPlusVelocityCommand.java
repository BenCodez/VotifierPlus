package com.vexsoftware.votifier.velocity;

import java.io.File;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.PublicKey;

import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.vexsoftware.votifier.crypto.RSAIO;
import com.vexsoftware.votifier.crypto.RSAKeygen;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;

public class VotifierPlusVelocityCommand implements SimpleCommand {
	private VotifierPlusVelocity plugin;

	public VotifierPlusVelocityCommand(VotifierPlusVelocity plugin) {
		this.plugin = plugin;
	}

	@Override
	public void execute(final Invocation invocation) {
		CommandSource source = invocation.source();
		// Get the arguments after the command alias
		String[] args = invocation.arguments();

		if (hasPermission(invocation)) {
			if (args.length > 0) {
				if (args[0].equalsIgnoreCase("reload")) {
					plugin.reload();
					source.sendMessage(Component.text("Reloading VotifierPlus").color(NamedTextColor.AQUA));
				}
				if (args[0].equalsIgnoreCase("GenerateKeys")) {
					File rsaDirectory = new File(plugin.getDataDirectory() + File.separator + "rsa");

					try {
						for (File file : rsaDirectory.listFiles()) {
							if (!file.isDirectory()) {
								file.delete();
							}
						}
						rsaDirectory.mkdir();
						plugin.setKeyPair(RSAKeygen.generate(2048));
						RSAIO.save(rsaDirectory, plugin.getKeyPair());
					} catch (Exception ex) {
						source.sendMessage(Component.text("Failed to create keys"));
						return;
					}
					source.sendMessage(Component.text("New keys generated"));
				}
				if (args[0].equalsIgnoreCase("vote") && args.length > 2) {
					try {
						PublicKey publicKey = plugin.getKeyPair().getPublic();
						String serverIP = plugin.getConfig().getHost();
						int serverPort = plugin.getConfig().getPort();

						String VoteString = "VOTE\n" + args[2] + "\n" + args[1] + "\n" + "Address" + "\n" + "TestVote"
								+ "\n";

						SocketAddress sockAddr = new InetSocketAddress(serverIP, serverPort);
						Socket socket1 = new Socket();
						socket1.connect(sockAddr, 1000);
						OutputStream socketOutputStream = socket1.getOutputStream();
						socketOutputStream.write(plugin.getVoteReceiver().encrypt(VoteString.getBytes(), publicKey));
						socketOutputStream.close();
						socket1.close();
						source.sendMessage(Component.text("Vote triggered"));

					} catch (Exception e) {
						e.printStackTrace();

					}

				}

			}
		} else {
			source.sendMessage(Component.text("You do not have permission to do this!"));
		}
	}

	@Override
	public boolean hasPermission(final Invocation invocation) {
		return invocation.source().hasPermission("votifierplus.admin");
	}
}
