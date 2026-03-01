package dev.notegridx.security.assetvulnmanager.domain;

import jakarta.persistence.*;
import lombok.Getter;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "cpe_product_aliases",
        uniqueConstraints = {
                @UniqueConstraint(name = "uq_product_alias", columnNames = {"cpe_vendor_id", "alias_norm"})
        },
        indexes = {
                @Index(name = "idx_product_alias_vendor", columnList = "cpe_vendor_id"),
                @Index(name = "idx_product_alias_product", columnList = "cpe_product_id"),
                @Index(name = "idx_product_alias_status", columnList = "status")
        }
)
@Getter
public class CpeProductAlias {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cpe_vendor_id", nullable = false)
    private Long cpeVendorId;

    @Column(name = "alias_norm", nullable = false, length = 255)
    private String aliasNorm;

    @Column(name = "cpe_product_id", nullable = false)
    private Long cpeProductId;

    @Column(nullable = false, length = 16)
    private String status = "ACTIVE"; // ACTIVE/INACTIVE

    @Column(length = 1024)
    private String note;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    protected CpeProductAlias() {
    }

    public CpeProductAlias(Long cpeVendorId, String aliasNorm, Long cpeProductId, String note) {
        this.cpeVendorId = cpeVendorId;
        this.aliasNorm = aliasNorm;
        this.cpeProductId = cpeProductId;
        this.note = note;
        this.status = "ACTIVE";
    }

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