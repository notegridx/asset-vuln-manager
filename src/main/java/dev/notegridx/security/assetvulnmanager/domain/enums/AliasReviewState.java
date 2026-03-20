package dev.notegridx.security.assetvulnmanager.domain.enums;

public enum AliasReviewState {
    MANUAL,   // Default for manually created or legacy-compatible aliases
    AUTO,     // Automatically inserted and considered confirmed
    SUGGEST   // Suggested by system but not treated as fully trusted AUTO entries
}