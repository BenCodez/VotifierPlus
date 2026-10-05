package com.bencodez.votifierplus.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Key;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.diagnostic.VotifierDiagnostics;
import com.vexsoftware.votifier.diagnostic.VotifierDiagnosticsSnapshot;
import com.vexsoftware.votifier.model.Vote;
import com.vexsoftware.votifier.net.ThrottleConfig;
import com.vexsoftware.votifier.net.VoteReceiver;

class VotifierDiagnosticsTest {
    @Test
    void unavailableReceiverDoesNotBecomeHealthy() {
        VotifierDiagnosticsSnapshot snapshot = VotifierDiagnostics.snapshot(null);

        assertEquals(Boolean.TRUE, snapshot.getProviderPresent());
        assertNull(snapshot.getListenerInitialized());
        assertNull(snapshot.getForwardingKnown());
        assertTrue(snapshot.getForwardingDestinations().isEmpty());
    }

    @Test
    void snapshotContainsOnlyEnabledBoundedDestinationNames() throws Exception {
        TestReceiver receiver = new TestReceiver();
        VotifierDiagnosticsSnapshot snapshot = VotifierDiagnostics.snapshot(receiver);

        assertEquals(Boolean.TRUE, snapshot.getProviderPresent());
        assertEquals(Boolean.TRUE, snapshot.getListenerInitialized());
        assertEquals(Boolean.TRUE, snapshot.getForwardingKnown());
        assertEquals(Collections.singletonList("backend"), snapshot.getForwardingDestinations());
        assertFalse(snapshot.getForwardingDestinations().toString().contains("secret-token"));
        receiver.getServer().close();
        assertEquals(Boolean.FALSE, VotifierDiagnostics.snapshot(receiver).getListenerInitialized());
    }

    @Test
    void snapshotBoundsAndDeduplicatesNames() {
        String longName = "x".repeat(81);
        VotifierDiagnosticsSnapshot snapshot = new VotifierDiagnosticsSnapshot(Boolean.TRUE, Boolean.FALSE,
                Boolean.TRUE, Arrays.asList("backend", "backend", "", longName, "other"));

        assertEquals(Arrays.asList("backend", "other"), snapshot.getForwardingDestinations());
        assertThrowsUnsupported(snapshot.getForwardingDestinations());
    }

    @Test
    void excessEnabledDestinationsMakeForwardingEvidenceUnknown() throws Exception {
        TestReceiver receiver = new TestReceiver(101);
        receiver.getServer().close();
        VotifierDiagnosticsSnapshot snapshot = VotifierDiagnostics.snapshot(receiver);

        assertEquals(Boolean.FALSE, snapshot.getListenerInitialized());
        assertEquals(Boolean.FALSE, snapshot.getForwardingKnown());
        assertEquals(100, snapshot.getForwardingDestinations().size());
    }

    @Test
    void distinctWhitespacePaddedTargetsDoNotBecomeCompleteNormalizedEvidence() throws Exception {
        TestReceiver receiver = new TestReceiver(-1);
        try {
            VotifierDiagnosticsSnapshot snapshot = VotifierDiagnostics.snapshot(receiver);
            assertEquals(Boolean.FALSE, snapshot.getForwardingKnown());
            assertEquals(List.of("backend"), snapshot.getForwardingDestinations());
        } finally {
            receiver.getServer().close();
        }
    }

    @Test
    void unclassifiableConfiguredTargetDoesNotBecomeDisabledForwarding() throws Exception {
        TestReceiver receiver = new TestReceiver(-2);
        try {
            VotifierDiagnosticsSnapshot snapshot = VotifierDiagnostics.snapshot(receiver);
            assertEquals(Boolean.FALSE, snapshot.getForwardingKnown());
            assertEquals(List.of(), snapshot.getForwardingDestinations());
        } finally {
            receiver.getServer().close();
        }
    }

    @Test
    void receiverReplacementsAreSafelyPublishedOnEveryPlatform() throws Exception {
        for (String type : List.of("com.vexsoftware.votifier.VotifierPlus",
                "com.vexsoftware.votifier.bungee.VotifierPlusBungee",
                "com.vexsoftware.votifier.velocity.VotifierPlusVelocity")) {
            assertTrue(java.lang.reflect.Modifier.isVolatile(Class.forName(type)
                    .getDeclaredField("voteReceiver").getModifiers()), type);
        }
    }

    @Test
    void platformEntryPointsExposeTheOptionalAccessor() throws Exception {
        assertTrue(Class.forName("com.vexsoftware.votifier.VotifierPlus")
                .getMethod("getNetworkHealthSnapshot") != null);
        assertTrue(Class.forName("com.vexsoftware.votifier.bungee.VotifierPlusBungee")
                .getMethod("getNetworkHealthSnapshot") != null);
        assertTrue(Class.forName("com.vexsoftware.votifier.velocity.VotifierPlusVelocity")
                .getMethod("getNetworkHealthSnapshot") != null);
    }

    private static void assertThrowsUnsupported(List<String> names) {
        try {
            names.add("unexpected");
            throw new AssertionError("snapshot list must be immutable");
        } catch (UnsupportedOperationException expected) {
            // expected
        }
    }

    private static final class TestReceiver extends VoteReceiver {
        private final int destinationCount;

        TestReceiver() throws Exception {
            this(2);
        }

        TestReceiver(int destinationCount) throws Exception {
            super("127.0.0.1", 0);
            this.destinationCount = destinationCount;
        }

        @Override public boolean isUseTokens() { return false; }
        @Override public ThrottleConfig getThrottleConfig() { return null; }
        @Override public void logWarning(String warn) { }
        @Override public void logSevere(String msg) { }
        @Override public void log(String msg) { }
        @Override public void debug(String msg) { }
        @Override public void debug(Exception e) { }
        @Override public String getVersion() { return "test"; }
        @Override public Set<String> getServers() {
            if (destinationCount == -1) return Set.of("backend", " backend ");
            if (destinationCount == -2) return Set.of("missing");
            if (destinationCount == 2) return Set.of("backend", "disabled");
            java.util.LinkedHashSet<String> names = new java.util.LinkedHashSet<String>();
            for (int i = 0; i < destinationCount; i++) names.add("backend-" + i);
            return names;
        }
        @Override public KeyPair getKeyPair() { return null; }
        @Override public Map<String, Key> getTokens() { return Collections.emptyMap(); }
        @Override public ForwardServer getServerData(String name) {
            if ("missing".equals(name)) return null;
            return new ForwardServer(!"disabled".equals(name), "private-host", 8192, "secret-key",
                    null);
        }
        @Override public void callEvent(Vote vote) { }
    }
}
