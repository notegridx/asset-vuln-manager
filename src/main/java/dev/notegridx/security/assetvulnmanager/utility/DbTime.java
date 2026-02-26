package dev.notegridx.security.assetvulnmanager.utility;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

/**
 * DB依存を避けるため、アプリ側で時刻精度を統一する。
 * - MICROS: MySQL DATETIME(6)/TIMESTAMP(6) と相性がよい
 * - もっと保守的にするなら MILLIS に変更してもOK
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