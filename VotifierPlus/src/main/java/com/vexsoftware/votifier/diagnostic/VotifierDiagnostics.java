package com.vexsoftware.votifier.diagnostic;

import java.util.ArrayList;
import java.util.List;

import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.net.VoteReceiver;

/** Optional adapter used by management software without a hard dependency. */
public final class VotifierDiagnostics {
    private VotifierDiagnostics() {
    }

    /**
     * Captures only state already owned by the receiver. A null receiver means
     * that listener state is unavailable, rather than falsely healthy.
     */
    public static VotifierDiagnosticsSnapshot snapshot(VoteReceiver receiver) {
        if (receiver == null) {
            return new VotifierDiagnosticsSnapshot(Boolean.TRUE, null, null, null);
        }
        List<String> destinations = new ArrayList<String>();
        boolean forwardingKnown = true;
        try {
            for (String name : receiver.getServers()) {
                if (name == null || name.trim().isEmpty()) {
                    // An unrepresentable configured entry means the forwarding inventory is incomplete.
                    forwardingKnown = false;
                    continue;
                }
                ForwardServer server = receiver.getServerData(name);
                if (server != null && server.isEnabled()) {
                    if (name.length() > VotifierDiagnosticsSnapshot.MAX_NAME_LENGTH
                            || destinations.size() >= VotifierDiagnosticsSnapshot.MAX_DESTINATIONS) {
                        // Do not claim complete evidence after the bounded snapshot omitted a risk.
                        forwardingKnown = false;
                        continue;
                    }
                    // Preserve configured identity; snapshot validation downgrades noncanonical names.
                    destinations.add(name);
                }
            }
        } catch (RuntimeException unavailable) {
            forwardingKnown = false;
            destinations.clear();
        }
        return new VotifierDiagnosticsSnapshot(Boolean.TRUE,
                receiver.getServer() != null && !receiver.getServer().isClosed(),
                forwardingKnown, destinations);
    }
}
