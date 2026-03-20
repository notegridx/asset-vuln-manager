package dev.notegridx.security.assetvulnmanager.domain.enums;

/**
 * Job types tracked in /admin/runs.
 *
 * WHY:
 * Designed to be extensible without schema changes.
 * New job types can be introduced by adding enum values only.
 */
public enum AdminJobType {
    CPE_SYNC,
    CVE_FEED_SYNC,
    CVE_DELTA_UPDATE,
    KEV_SYNC,

    ALERT_RECALCULATE,
    CANONICAL_BACKFILL,
    ALIAS_SEED_IMPORT,

    // Reserved for future consolidation or grouping if job types expand.
    IMPORT
}