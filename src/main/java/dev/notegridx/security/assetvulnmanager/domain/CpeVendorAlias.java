package dev.notegridx.security.assetvulnmanager.domain;

import jakarta.persistence.*;
import lombok.Getter;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "cpe_vendor_aliases",
        uniqueConstraints = {
                @UniqueConstraint(name = "uq_vendor_alias", columnNames = {"alias_norm"})
        },
        indexes = {
                @Index(name = "idx_vendor_alias_vendor", columnList = "cpe_vendor_id"),
                @Index(name = "idx_vendor_alias_status", columnList = "status")
        }
)
@Getter
public class CpeVendorAlias {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "alias_norm", nullable = false, length = 255)
    private String aliasNorm;

    @Column(name = "cpe_vendor_id", nullable = false)
    private Long cpeVendorId;

    @Column(nullable = false, length = 16)
    private String status = "ACTIVE"; // ACTIVE/INACTIVE

    @Column(length = 1024)
    private String note;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    protected CpeVendorAlias() {
    }

    public CpeVendorAlias(String aliasNorm, Long cpeVendorId, String note) {
        this.aliasNorm = aliasNorm;
        this.cpeVendorId = cpeVendorId;
        this.note = note;
        this.status = "ACTIVE";
    }

    // 既存の class に追記（@Getter のままでOK）
    public void setStatus(String status) {
        if (status == null || status.trim().isEmpty()) {
            this.status = "ACTIVE";
            return;
        }
        this.status = status.trim().toUpperCase(java.util.Locale.ROOT);
    }

    @PrePersist
    void prePersist() {
        LocalDateTime now = LocalDateTime.now();
        this.createdAt = now;
        this.updatedAt = now;
        if (this.status == null) this.status = "ACTIVE";
    }

    @PreUpdate
    void preUpdate() {
        this.updatedAt = LocalDateTime.now();
        if (this.status == null) this.status = "ACTIVE";
    }
}