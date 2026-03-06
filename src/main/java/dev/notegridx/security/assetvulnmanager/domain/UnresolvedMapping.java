package dev.notegridx.security.assetvulnmanager.domain;

import java.time.LocalDateTime;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Table(name = "unresolved_mappings")
@Getter
public class UnresolvedMapping {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String source;

    @Column(nullable = false)
    private String vendorRaw;

    @Column(nullable = false)
    private String productRaw;

    private String versionRaw;

    private String normalizedVendor;
    private String normalizedProduct;

    private String candidateVendorIds;
    private String candidateProductIds;

    @Column(nullable = false)
    private String status = "NEW";

    private String note;

    @Column(nullable = false)
    private LocalDateTime firstSeenAt;

    @Column(nullable = false)
    private LocalDateTime lastSeenAt;

    @Column(nullable = false, name = "created_at")
    private LocalDateTime createdAt;

    @Column(nullable = false, name = "updated_at")
    private LocalDateTime updatedAt;

    protected UnresolvedMapping() {
    }

    public static UnresolvedMapping create(
            String source,
            String vendorRaw,
            String productRaw,
            String versionRaw
    ) {
        UnresolvedMapping um = new UnresolvedMapping();
        um.source = source;
        um.vendorRaw = vendorRaw;
        um.productRaw = productRaw;
        um.versionRaw = versionRaw;
        um.status = "NEW";
        um.firstSeenAt = LocalDateTime.now();
        um.lastSeenAt = LocalDateTime.now();
        return um;
    }

    @PrePersist
    void prePersist() {
        LocalDateTime now = LocalDateTime.now();
        if (firstSeenAt == null) firstSeenAt = now;
        if (lastSeenAt == null) lastSeenAt = now;
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    void preUpdate() {
        updatedAt = LocalDateTime.now();
    }

    // ===== setters（CsvImportService が使う分）=====

    public void setSource(String source) {
        this.source = source;
    }

    public void setVendorRaw(String vendorRaw) {
        this.vendorRaw = vendorRaw;
    }

    public void setProductRaw(String productRaw) {
        this.productRaw = productRaw;
    }

    public void setVersionRaw(String versionRaw) {
        this.versionRaw = versionRaw;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public void setNote(String note) {
        this.note = note;
    }

    public void setFirstSeenAt(LocalDateTime firstSeenAt) {
        this.firstSeenAt = firstSeenAt;
    }

    public void setLastSeenAt(LocalDateTime lastSeenAt) {
        this.lastSeenAt = lastSeenAt;
    }

    public void setNormalizedVendor(String normalizedVendor) {
        this.normalizedVendor = normalizedVendor;
    }

    public void setNormalizedProduct(String normalizedProduct) {
        this.normalizedProduct = normalizedProduct;
    }

    public void setCandidateVendorIds(String candidateVendorIds) {
        this.candidateVendorIds = candidateVendorIds;
    }

    public void setCandidateProductIds(String candidateProductIds) {
        this.candidateProductIds = candidateProductIds;
    }
}