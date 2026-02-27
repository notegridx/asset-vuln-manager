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

    @Column(name = "external_key", length = 128, nullable = false)
    private String externalKey;

    @Column(nullable = false)
    private String name;

    @Column(name = "asset_type")
    private String assetType;

    private String owner;

    @Lob
    private String note;

    // ===== Existing columns =====
    @Column(nullable = false)
    private String source = "JSON_UPLOAD";

    @Column(length = 64)
    private String platform;

    @Column(name = "os_version", length = 128)
    private String osVersion;

    // ===== Added (osquery-derived inventory identifiers / OS / hardware) =====

    @Column(name = "system_uuid", length = 128)
    private String systemUuid;

    @Column(name = "serial_number", length = 128)
    private String serialNumber;

    @Column(name = "hardware_vendor", length = 255)
    private String hardwareVendor;

    @Column(name = "hardware_model", length = 255)
    private String hardwareModel;

    @Column(name = "computer_name", length = 255)
    private String computerName;

    @Column(name = "local_hostname", length = 255)
    private String localHostname;

    @Column(name = "cpu_brand", length = 255)
    private String cpuBrand;

    @Column(name = "cpu_physical_cores")
    private Integer cpuPhysicalCores;

    @Column(name = "cpu_logical_cores")
    private Integer cpuLogicalCores;

    @Column(name = "arch", length = 64)
    private String arch;

    @Column(name = "os_name", length = 255)
    private String osName;

    @Column(name = "os_build", length = 128)
    private String osBuild;

    @Column(name = "os_major")
    private Integer osMajor;

    @Column(name = "os_minor")
    private Integer osMinor;

    @Column(name = "os_patch")
    private Integer osPatch;

    @Column(name = "last_seen_at")
    private LocalDateTime lastSeenAt;

    // ===== Validation / bookkeeping =====

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
        ImportStagingAsset s = new ImportStagingAsset();
        s.importRunId = runId;
        s.rowNo = rowNo;
        return s;
    }

    public void fill(
            String externalKey,
            String name,
            String assetType,
            String owner,
            String note,
            String source,
            String platform,
            String osVersion,
            String systemUuid,
            String serialNumber,
            String hardwareVendor,
            String hardwareModel,
            String computerName,
            String localHostname,
            String cpuBrand,
            Integer cpuPhysicalCores,
            Integer cpuLogicalCores,
            String arch,
            String osName,
            String osBuild,
            Integer osMajor,
            Integer osMinor,
            Integer osPatch,
            LocalDateTime lastSeenAt
    ) {
        this.externalKey = externalKey;
        this.name = name;
        this.assetType = assetType;
        this.owner = owner;
        this.note = note;

        this.source = (source == null || source.isBlank()) ? "JSON_UPLOAD" : source;
        this.platform = platform;
        this.osVersion = osVersion;

        this.systemUuid = systemUuid;
        this.serialNumber = serialNumber;
        this.hardwareVendor = hardwareVendor;
        this.hardwareModel = hardwareModel;
        this.computerName = computerName;
        this.localHostname = localHostname;

        this.cpuBrand = cpuBrand;
        this.cpuPhysicalCores = cpuPhysicalCores;
        this.cpuLogicalCores = cpuLogicalCores;
        this.arch = arch;

        this.osName = osName;
        this.osBuild = osBuild;
        this.osMajor = osMajor;
        this.osMinor = osMinor;
        this.osPatch = osPatch;

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
        if (this.source == null || this.source.isBlank()) this.source = "JSON_UPLOAD";
    }

    @PreUpdate
    void preUpdate() {
        this.updatedAt = LocalDateTime.now();
        if (this.source == null || this.source.isBlank()) this.source = "JSON_UPLOAD";
    }
}