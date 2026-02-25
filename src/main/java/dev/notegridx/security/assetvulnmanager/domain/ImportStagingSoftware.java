package dev.notegridx.security.assetvulnmanager.domain;

import java.time.LocalDateTime;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Table(name = "import_staging_software")
@Getter
public class ImportStagingSoftware {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "import_run_id", nullable = false)
    private Long importRunId;

    @Column(name = "row_no", nullable = false)
    private int rowNo;

    @Column(name = "external_key", length = 128, nullable = false)
    private String externalKey;

    @Column(length = 255)
    private String vendor;

    @Column(length = 255)
    private String product;

    @Column(length = 64)
    private String version;

    @Column(name = "install_location", length = 1024)
    private String installLocation;

    @Column(name = "installed_at")
    private LocalDateTime installedAt;

    @Column(name = "package_identifier", length = 255)
    private String packageIdentifier;

    @Column(length = 64)
    private String arch;

    @Column(name = "source_type", nullable = false, length = 64)
    private String sourceType = "JSON_UPLOAD";

    @Column(name = "last_seen_at")
    private LocalDateTime lastSeenAt;

    @Column(name = "is_valid", nullable = false)
    private boolean isValid = true;

    @Column(name = "validation_error", length = 1024)
    private String validationError;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    protected ImportStagingSoftware() {
    }

    public static ImportStagingSoftware of(Long runId, int rowNo) {
        ImportStagingSoftware s = new ImportStagingSoftware();
        s.importRunId = runId;
        s.rowNo = rowNo;
        return s;
    }

    public void fill(
            String externalKey,
            String vendor,
            String product,
            String version,
            String installLocation,
            LocalDateTime installedAt,
            String packageIdentifier,
            String arch,
            String sourceType,
            LocalDateTime lastSeenAt
    ) {
        this.externalKey = externalKey;
        this.vendor = vendor;
        this.product = product;
        this.version = version;
        this.installLocation = installLocation;
        this.installedAt = installedAt;
        this.packageIdentifier = packageIdentifier;
        this.arch = arch;
        this.sourceType = (sourceType == null || sourceType.isBlank()) ? "JSON_UPLOAD" : sourceType;
        this.lastSeenAt = lastSeenAt;
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
        if (this.sourceType == null || this.sourceType.isBlank()) this.sourceType = "JSON_UPLOAD";
    }

    @PreUpdate
    void preUpdate() {
        this.updatedAt = LocalDateTime.now();
        if (this.sourceType == null || this.sourceType.isBlank()) this.sourceType = "JSON_UPLOAD";
    }
}