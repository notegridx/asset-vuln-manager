package dev.notegridx.security.assetvulnmanager.domain;

import java.time.LocalDateTime;

import dev.notegridx.security.assetvulnmanager.utility.DbTime;
import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Table(
        name = "kev_sync_state",
        uniqueConstraints = @UniqueConstraint(name = "uq_kev_sync_state_feed", columnNames = {"feed_name"})
)
@Getter
public class KevSyncState {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "feed_name", nullable = false, length = 64)
    private String feedName;

    @Column(name = "etag", length = 255)
    private String etag;

    @Column(name = "last_modified", length = 128)
    private String lastModified;

    @Column(name = "body_sha256", length = 128)
    private String bodySha256;

    @Column(name = "body_size")
    private Long bodySize;

    @Column(name = "fetched_at")
    private LocalDateTime fetchedAt;

    @Column(nullable = false, name = "created_at")
    private LocalDateTime createdAt;

    @Column(nullable = false, name = "updated_at")
    private LocalDateTime updatedAt;

    protected KevSyncState() {}

    public static KevSyncState of(String feedName) {
        KevSyncState s = new KevSyncState();
        s.feedName = feedName;
        return s;
    }

    public void updateMeta(String etag, String lastModified, String sha256, Long size, LocalDateTime fetchedAt) {
        this.etag = norm(etag);
        this.lastModified = norm(lastModified);
        this.bodySha256 = norm(sha256);
        this.bodySize = size;
        this.fetchedAt = fetchedAt;
    }

    @PrePersist
    void onCreate() {
        LocalDateTime now = DbTime.now();
        if (createdAt == null) createdAt = now;
        if (updatedAt == null) updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = DbTime.now();
    }

    private static String norm(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }
}