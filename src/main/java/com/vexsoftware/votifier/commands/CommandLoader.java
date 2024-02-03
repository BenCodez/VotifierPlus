package com.vexsoftware.votifier.commands;

import java.io.File;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;

import org.bukkit.command.CommandSender;

import com.bencodez.advancedcore.api.command.CommandHandler;
import com.vexsoftware.votifier.VotifierPlus;
import com.vexsoftware.votifier.crypto.RSAIO;
import com.vexsoftware.votifier.crypto.RSAKeygen;

import net.md_5.bungee.api.ChatColor;
import net.md_5.bungee.api.chat.TextComponent;

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

	public ArrayList<TextComponent> helpText(CommandSender sender) {
		ArrayList<TextComponent> msg = new ArrayList<TextComponent>();
		HashMap<String, TextComponent> unsorted = new HashMap<String, TextComponent>();

		boolean requirePerms = false;
		ChatColor hoverColor = ChatColor.AQUA;
		for (CommandHandler cmdHandle : plugin.getCommands()) {
			if (!requirePerms || cmdHandle.hasPerm(sender)) {
				unsorted.put(cmdHandle.getHelpLineCommand("/votifierplus"),
						cmdHandle.getHelpLine("/votifierplus", "&6%Command% - &6%HelpMessage%", hoverColor));
			}
		}
		ArrayList<String> unsortedList = new ArrayList<String>();
		unsortedList.addAll(unsorted.keySet());
		Collections.sort(unsortedList, String.CASE_INSENSITIVE_ORDER);
		for (String cmd : unsortedList) {
			msg.add(unsorted.get(cmd));
		}

		return msg;
	}

	public void loadCommands() {
		plugin.getCommands()
				.add(new CommandHandler(plugin, new String[] { "Help" }, "VotifierPlus.Help", "Open help page") {

					@Override
					public void execute(CommandSender sender, String[] args) {
						sendMessageJson(sender, helpText(sender));
					}
				});
		plugin.getCommands()
				.add(new CommandHandler(plugin, new String[] { "Reload" }, "VotifierPlus.Reload", "Reload the plugin") {

					@Override
					public void execute(CommandSender sender, String[] args) {
						plugin.reload();
						sendMessage(sender, "&cVotifierPlus " + plugin.getVersion() + " reloaded");
					}
				});

		plugin.getCommands().add(new CommandHandler(plugin, new String[] { "GenerateKeys" },
				"VotifierPlus.GenerateKeys", "Regenerate votifier keys", true, true) {

			@Override
			public void execute(CommandSender sender, String[] args) {
				File rsaDirectory = new File(plugin.getDataFolder() + File.separator + "rsa");

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
					sendMessage(sender, "&cFailed to create keys");
					return;
				}
				sendMessage(sender, "&cNew keys generated");
			}
		});

		plugin.getCommands().add(new CommandHandler(plugin, new String[] { "Test", "(player)", "(Text)" },
				"VotifierPlus.Test", "Test votifier connection") {

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
