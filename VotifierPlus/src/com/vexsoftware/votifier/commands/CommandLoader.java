package com.vexsoftware.votifier.commands;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.PublicKey;

import org.bukkit.command.CommandSender;

import com.Ben12345rocks.AdvancedCore.CommandAPI.CommandHandler;
import com.vexsoftware.votifier.VotifierPlus;

// TODO: Auto-generated Javadoc
/**
 * The Class CommandLoader.
 */
public class CommandLoader {

	private static CommandLoader instance = new CommandLoader();
	private VotifierPlus plugin = VotifierPlus.getInstance();

	public static CommandLoader getInstance() {
		return instance;
	}

	public void loadCommands() {
		plugin.getCommands()
				.add(new CommandHandler(new String[] { "Reload" }, "VotifierPlus.Reload", "Reload the plugin") {

					@Override
					public void execute(CommandSender sender, String[] args) {
						plugin.reload();
						sendMessage(sender, "&cVotifierPlus " + plugin.getVersion() + " reloaded");
					}
				});

		plugin.getCommands().add(new CommandHandler(new String[] { "Test", "(player)", "(Text)" }, "VotifierPlus.Test",
				"Test votifier connection") {

			@Override
			public void execute(CommandSender sender, String[] args) {
				try {
					PublicKey publicKey = plugin.getKeyPair().getPublic();
					String serverIP = plugin.config.getHost();
					int serverPort = plugin.config.getPort();
					if (serverIP.length() != 0) {
						String VoteString = "VOTE\n" + args[2] + "\n" + args[1] + "\n" + "Address" + "\n" + "TestVote"
								+ "\n";

						SocketAddress sockAddr = new InetSocketAddress(serverIP, serverPort);
						Socket socket1 = new Socket();
						socket1.connect(sockAddr, 1000);
						OutputStream socketOutputStream = socket1.getOutputStream();
						socketOutputStream.write(plugin.getVoteReceiver().encrypt(VoteString.getBytes(), publicKey));
						socketOutputStream.close();
						socket1.close();
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
				sendMessage(sender, "&cCheck console for test results");

			}
		});
	}
}
