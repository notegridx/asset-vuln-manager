package dev.notegridx.security.assetvulnmanager.domain;

import jakarta.persistence.*;
import lombok.Getter;
import org.springframework.cglib.core.Local;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "cpe_sync_state",
        uniqueConstraints = @UniqueConstraint(name = "uq_cpe_sync_state_feed", columnNames = {"feed_name"})
)
@Getter
public class CpeSyncState {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "feed_name", nullable = false, length = 64)
    private String feedName;

    @Column(name = "meta_sha256", length = 128)
    private String metaSha256;

    @Column(name = "meta_last_modified", length = 64)
    private String metaLastModified;

    @Column(name = "meta_size")
    private Long metaSize;

    @Column(name = "last_synced_at")
    private LocalDateTime lastSyncedAt;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    protected CpeSyncState() {}

    public CpeSyncState(String feedName) {
        this.feedName = requireNotBlank(feedName, "feedName");
    }

    public boolean isSameMeta(String sha256, String lastModified, Long size) {
        if (notBlank(sha256)) {
            return sha256.equalsIgnoreCase(nullToEmpty(this.metaSha256));
        }
        boolean lmSame = notBlank(lastModified) && lastModified.equalsIgnoreCase(nullToEmpty(this.metaLastModified));
        boolean sizeSame = (size != null && size.equals(this.metaSize));
        return lmSame && sizeSame;
    }

    public void updateMeta(String sha256, String lastModified, Long size, LocalDateTime syncedAt) {
        this.metaSha256 = normalizeNullable(sha256);
        this.metaLastModified = normalizeNullable(lastModified);
        this.metaSize = size;
        this.lastSyncedAt = syncedAt;
    }

    private static boolean notBlank(String s) {
        return s != null && !s.trim().isEmpty();
    }

    private static String nullToEmpty(String s) {
        return (s == null) ? "" : s;
    }

    private static String normalizeNullable(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static String requireNotBlank(String s, String field) {
        if (s == null || s.trim().isEmpty()) throw new IllegalArgumentException(field + " is required");
        return s.trim();
    }

    @PrePersist
    void prePersist() {
        LocalDateTime now = LocalDateTime.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    @PreUpdate
    void preUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
 }
