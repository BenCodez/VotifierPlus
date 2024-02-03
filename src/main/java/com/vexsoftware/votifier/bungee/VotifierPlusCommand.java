package com.vexsoftware.votifier.bungee;

import java.io.File;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.PublicKey;

import com.vexsoftware.votifier.crypto.RSAIO;
import com.vexsoftware.votifier.crypto.RSAKeygen;

import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.plugin.Command;

public class VotifierPlusCommand extends Command {
	private VotifierPlusBungee bungee;

	public VotifierPlusCommand(VotifierPlusBungee bungee) {
		super("votifierplusbungee", "votifierplus.admin");
		this.bungee = bungee;
	}

	@Override
	public void execute(CommandSender sender, String[] args) {
		if (sender.hasPermission("votifierplus.admin")) {
			if (args.length > 0) {
				if (args[0].equalsIgnoreCase("reload")) {
					bungee.reload();
					sender.sendMessage(new TextComponent("Reloading VotifierPlus"));
				}
				if (args[0].equalsIgnoreCase("GenerateKeys")) {
					File rsaDirectory = new File(bungee.getDataFolder() + File.separator + "rsa");

					try {
						for (File file : rsaDirectory.listFiles()) {
							if (!file.isDirectory()) {
								file.delete();
							}
						}
						rsaDirectory.mkdir();
						bungee.setKeyPair(RSAKeygen.generate(2048));
						RSAIO.save(rsaDirectory, bungee.getKeyPair());
					} catch (Exception ex) {
						sender.sendMessage(new TextComponent("Failed to create keys"));
						return;
					}
					sender.sendMessage(new TextComponent("New keys generated"));
				}
				if (args[0].equalsIgnoreCase("vote") && args.length > 2) {
					try {
						PublicKey publicKey = bungee.getKeyPair().getPublic();
						String serverIP = bungee.getConfig().getHost();
						int serverPort = bungee.getConfig().getPort();

						String VoteString = "VOTE\n" + args[2] + "\n" + args[1] + "\n" + "Address" + "\n" + "TestVote"
								+ "\n";

						SocketAddress sockAddr = new InetSocketAddress(serverIP, serverPort);
						Socket socket1 = new Socket();
						socket1.connect(sockAddr, 1000);
						OutputStream socketOutputStream = socket1.getOutputStream();
						socketOutputStream.write(bungee.getVoteReceiver().encrypt(VoteString.getBytes(), publicKey));
						socketOutputStream.close();
						socket1.close();
						sender.sendMessage(new TextComponent("Vote triggered"));

					} catch (Exception e) {
						e.printStackTrace();

					}

				}

			}
		} else {
			sender.sendMessage(new TextComponent("You do not have permission to do this!"));
		}
	}
}
