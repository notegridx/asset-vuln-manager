package dev.notegridx.security.assetvulnmanager.domain;

import jakarta.persistence.*;
import lombok.Getter;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "cpe_vendors",
        uniqueConstraints = @UniqueConstraint(name = "uq_cpe_vendors_name", columnNames = {"name_norm"})
)
@Getter
public class CpeVendor {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "name_norm", nullable = false, length = 255)
    private String nameNorm;

    @Column(name = "display_name", length = 255)
    private String displayName;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @Column(nullable = false, length = 20)
    private String source = "CPE_DICT";

    protected CpeVendor() {}

    public CpeVendor(String nameNorm, String displayName) {
        this.nameNorm = requireNotBlank(nameNorm, "nameNorm");
        this.displayName = normalizeNullable(displayName);
        this.source = "CPE_DICT";
    }

    public void updateDisplayName(String displayName) {
        this.displayName = normalizeNullable(displayName);
    }

    public void markAsNvdCve() {
        this.source = "NVD_CVE";
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