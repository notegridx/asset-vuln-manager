package dev.notegridx.security.assetvulnmanager.domain.enums;

/**
 * /admin/runs に集約するジョブ種別。
 * 将来増えても schema 変更なし（ENUM追加のみ）。
 */
public enum AdminJobType {
    CPE_SYNC,
    CVE_FEED_SYNC,
    CVE_DELTA_UPDATE,
    ALERT_RECALCULATE,
    ALIAS_SEED_IMPORT,

    // 将来の統合枠（必要に応じて細分化してOK）
    IMPORT
}