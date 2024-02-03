package com.vexsoftware.votifier.commands;

import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;

import com.bencodez.advancedcore.api.command.CommandHandler;
import com.vexsoftware.votifier.VotifierPlus;

// TODO: Auto-generated Javadoc
/**
 * The Class CommandVotifierPlus.
 */
public class CommandVotifierPlus implements CommandExecutor {
	/** The plugin. */
	private VotifierPlus plugin;

	/**
	 * Instantiates a new command vote.
	 *
	 * @param plugin
	 *            the plugin
	 */
	public CommandVotifierPlus(VotifierPlus plugin) {
		this.plugin = plugin;
	}

	/*
	 * (non-Javadoc)
	 * @see org.bukkit.command.CommandExecutor#onCommand(org.bukkit.command.
	 * CommandSender , org.bukkit.command.Command, java.lang.String,
	 * java.lang.String[])
	 */
	@Override
	public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {

		for (CommandHandler commandHandler : plugin.getCommands()) {
			if (commandHandler.runCommand(sender, args)) {
				return true;
			}
		}

		// invalid command
		sender.sendMessage(ChatColor.RED + "No valid arguments, see /votifierplus help!");
		return true;
	}

}
