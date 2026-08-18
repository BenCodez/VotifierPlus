package com.vexsoftware.votifier.net;

/**
 * Process-wide protocol policy for the single VotifierPlus listener owned by a
 * plugin class loader.
 */
public final class VoteProtocolPolicy {

	private static volatile boolean disableV1;

	private VoteProtocolPolicy() {
	}

	public static boolean isDisableV1() {
		return disableV1;
	}

	public static void setDisableV1(boolean disableV1) {
		VoteProtocolPolicy.disableV1 = disableV1;
	}
}
