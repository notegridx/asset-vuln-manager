package dev.notegridx.security.assetvulnmanager.domain;

import jakarta.persistence.*;
import lombok.Getter;

import java.time.LocalDateTime;

import dev.notegridx.security.assetvulnmanager.utility.DbTime;

@Entity
@Table(
        name = "cpe_products",
        uniqueConstraints = @UniqueConstraint(name = "uq_cpe_products_vendor_name", columnNames = {"vendor_id", "name_norm"}),
        indexes = {
                @Index(name = "idx_cpe_products_vendor", columnList = "vendor_id"),
                @Index(name = "idx_cpe_products_name", columnList = "name_norm"),
                @Index(name = "idx_cpe_products_vendor_name", columnList = "vendor_id, name_norm")
        }
)
@Getter
public class CpeProduct {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "vendor_id", nullable = false)
    private CpeVendor vendor;

    @Column(name = "name_norm", nullable = false, length = 255)
    private String nameNorm;

    @Column(name = "display_name", length = 255)
    private String displayName;

    @Column(nullable = false, length = 20)
    private String source = "CPE_DICT";

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    protected CpeProduct() {}

    public CpeProduct(CpeVendor vendor, String nameNorm, String displayName) {
        this.vendor = requireNotNull(vendor, "vendor");
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

    private static <T> T requireNotNull(T v, String field) {
        if (v == null) throw new IllegalArgumentException(field + " is required");
        return v;
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
        LocalDateTime now = DbTime.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    @PreUpdate
    void preUpdate() {
        this.updatedAt = DbTime.now();
    }
}
