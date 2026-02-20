package dev.notegridx.security.assetvulnmanager.domain;

import java.time.LocalDateTime;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Table(name = "cve_sync_state",
        uniqueConstraints = @UniqueConstraint(name = "uq_cve_sync_feed", columnNames = {"feed_name"})
)
@Getter
public class CveSyncState {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name="feed_name", nullable = false, length = 64)
    private String feedName;

    @Column(name="meta_sha256", length = 128)
    private String metaSha256;

    @Column(name="meta_last_modified", length = 64)
    private String metaLastModified;

    @Column(name="meta_size")
    private Long metaSize;

    @Column(name="last_synced_at")
    private LocalDateTime lastSyncedAt;

    @Column(name="created_at", nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name="updated_at", nullable = false)
    private LocalDateTime updatedAt = LocalDateTime.now();

    protected CveSyncState() {}

    public CveSyncState(String feedName) {
        this.feedName = feedName;
    }

    public boolean isSameMeta(String sha256, String lastModified, Long size) {
        return eq(metaSha256, sha256)
                && eq(metaLastModified, lastModified)
                && eq(metaSize, size);
    }

    public void updateMeta(String sha256, String lastModified, Long size, LocalDateTime now) {
        this.metaSha256 = sha256;
        this.metaLastModified = lastModified;
        this.metaSize = size;
        this.lastSyncedAt = now;
        this.updatedAt = (now != null) ? now : LocalDateTime.now();
    }

    private static boolean eq(Object a, Object b) {
        return (a == null) ? (b == null) : a.equals(b);
    }
}