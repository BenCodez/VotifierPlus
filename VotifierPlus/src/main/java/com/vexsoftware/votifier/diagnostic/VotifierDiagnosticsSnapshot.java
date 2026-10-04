package com.vexsoftware.votifier.diagnostic;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Bounded, read-only Votifier state for optional management-plane diagnostics.
 *
 * <p>This type deliberately contains destination names only. It does not expose
 * forwarding endpoints, ports, keys, tokens, or configuration text.</p>
 */
public final class VotifierDiagnosticsSnapshot {
    public static final int MAX_DESTINATIONS = 100;
    public static final int MAX_NAME_LENGTH = 80;

    private final Boolean providerPresent;
    private final Boolean listenerInitialized;
    private final Boolean forwardingKnown;
    private final List<String> forwardingDestinations;

    public VotifierDiagnosticsSnapshot(Boolean providerPresent, Boolean listenerInitialized,
            Boolean forwardingKnown, Iterable<String> forwardingDestinations) {
        this.providerPresent = providerPresent;
        this.listenerInitialized = listenerInitialized;
        BoundedNames bounded = boundedNames(forwardingDestinations);
        this.forwardingKnown = forwardingKnown == null || !Boolean.TRUE.equals(forwardingKnown)
                ? forwardingKnown : bounded.complete ? Boolean.TRUE : Boolean.FALSE;
        this.forwardingDestinations = bounded.names;
    }

    public Boolean getProviderPresent() {
        return providerPresent;
    }

    public Boolean getListenerInitialized() {
        return listenerInitialized;
    }

    public Boolean getForwardingKnown() {
        return forwardingKnown;
    }

    public List<String> getForwardingDestinations() {
        return forwardingDestinations;
    }

    private static BoundedNames boundedNames(Iterable<String> values) {
        if (values == null) {
            return new BoundedNames(Collections.emptyList(), true);
        }
        Set<String> unique = new LinkedHashSet<String>();
        boolean complete = true;
        for (String value : values) {
            if (value == null) {
                complete = false;
                continue;
            }
            String name = value.trim();
            if (name.isEmpty() || name.length() > MAX_NAME_LENGTH) {
                complete = false;
                continue;
            }
            if (!name.equals(value) || name.codePoints().anyMatch(Character::isISOControl)) {
                complete = false;
                continue;
            }
            unique.add(name);
            if (unique.size() > MAX_DESTINATIONS) {
                complete = false;
                unique.remove(name);
            }
        }
        return new BoundedNames(Collections.unmodifiableList(new ArrayList<String>(unique)), complete);
    }

    private static final class BoundedNames {
        private final List<String> names;
        private final boolean complete;

        private BoundedNames(List<String> names, boolean complete) {
            this.names = names;
            this.complete = complete;
        }
    }
}
