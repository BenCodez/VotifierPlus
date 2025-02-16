package com.vexsoftware.votifier;

import com.bencodez.simpleapi.updater.Updater;

// TODO: Auto-generated Javadoc
/**
 * The Class CheckUpdate.
 */
public class CheckUpdate {

	/** The plugin. */
	static VotifierPlus plugin;

	/**
	 * Instantiates a new check update.
	 *
	 * @param plugin
	 *            the plugin
	 */
	public CheckUpdate(VotifierPlus plugin) {
		CheckUpdate.plugin = plugin;
	}

	/**
	 * Check update.
	 */
	public void checkUpdate() {
		if (plugin.configFile.isDisableUpdateChecking()) {
			return;
		}
		plugin.setUpdater(new Updater(plugin, 74040, false));
		final Updater.UpdateResult result = plugin.getUpdater().getResult();
		switch (result) {
			case FAIL_SPIGOT: {
				plugin.getLogger().info("Failed to check for update for " + plugin.getName() + "!");
				break;
			}
			case NO_UPDATE: {
				plugin.getLogger()
						.info(plugin.getName() + " is up to date! Version: " + plugin.getUpdater().getVersion());
				break;
			}
			case UPDATE_AVAILABLE: {
				plugin.getLogger().info(plugin.getName() + " has an update available! Your Version: "
						+ plugin.getDescription().getVersion() + " New Version: " + plugin.getUpdater().getVersion());
				break;
			}
			default: {
				break;
			}
		}
	}

}
