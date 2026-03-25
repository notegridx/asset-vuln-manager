package dev.notegridx.security.assetvulnmanager.utility;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

/**
 * Standardizes timestamp precision at the application layer to avoid DB-specific differences.
 * - MICROS: aligns well with MySQL DATETIME(6)/TIMESTAMP(6)
 * - Can be switched to MILLIS for more conservative precision if needed
 */
public final class DbTime {

    private static final ChronoUnit UNIT = ChronoUnit.MICROS;

    private DbTime() {}

    public static LocalDateTime now() {
        return LocalDateTime.now().truncatedTo(UNIT);
    }

    public static LocalDateTime normalize(LocalDateTime t) {
        return (t == null) ? null : t.truncatedTo(UNIT);
    }
}