package dev.notegridx.security.assetvulnmanager.utility;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public final class UiDateTime {

    private static final DateTimeFormatter DATE_TIME_SECONDS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final DateTimeFormatter DATE_TIME_MINUTES =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    private UiDateTime() {
    }

    /**
     * 詳細表示向け:
     * 2026-03-16 17:22:29
     */
    public static String format(LocalDateTime value) {
        if (value == null) {
            return "-";
        }
        return DATE_TIME_SECONDS.format(value);
    }

    /**
     * 一覧表示向け:
     * 2026-03-16 17:22
     */
    public static String shortFormat(LocalDateTime value) {
        if (value == null) {
            return "-";
        }
        return DATE_TIME_MINUTES.format(value);
    }
}