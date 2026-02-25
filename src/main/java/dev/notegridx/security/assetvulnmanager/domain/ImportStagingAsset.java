package dev.notegridx.security.assetvulnmanager.domain;

import java.time.LocalDateTime;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Table(name = "import_staging_assets")
@Getter
public class ImportStagingAsset {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "import_run_id", nullable = false)
    private Long importRunId;

    @Column(name = "row_no", nullable = false)
    private int rowNo;

    @Column(name = "external_key", length = 128)
    private String externalKey;

    @Column(length = 255)
    private String name;

    @Column(name = "asset_type", length = 32)
    private String assetType;

    @Column(length = 255)
    private String owner;

    @Lob
    private String note;

    @Column(name = "is_valid", nullable = false)
    private boolean isValid = true;

    @Column(name = "validation_error", length = 1024)
    private String validationError;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    protected ImportStagingAsset() {
    }

    public static ImportStagingAsset of(Long runId, int rowNo) {
        ImportStagingAsset a = new ImportStagingAsset();
        a.importRunId = runId;
        a.rowNo = rowNo;
        return a;
    }

    public void fill(String externalKey, String name, String assetType, String owner, String note) {
        this.externalKey = externalKey;
        this.name = name;
        this.assetType = assetType;
        this.owner = owner;
        this.note = note;
    }

    public void markInvalid(String error) {
        this.isValid = false;
        this.validationError = error;
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