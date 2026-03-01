package dev.notegridx.security.assetvulnmanager.domain.enums;

public enum AliasReviewState {
    MANUAL,   // 人手登録・既存互換のデフォルト
    AUTO,     // 自動投入（確定）
    SUGGEST   // 提案（自動投入するがAUTO扱いにはしない）
}