package dev.notegridx.security.assetvulnmanager.domain;

import java.time.LocalDateTime;

import dev.notegridx.security.assetvulnmanager.utility.DbTime;

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

    // invalid行も保存してPreviewで見せるため nullable=true にする
    @Column(name = "external_key", length = 128)
    private String externalKey;

    // invalid行も保存してPreviewで見せるため nullable=true にする
    @Column(length = 255)
    private String name;

    @Column(name = "asset_type")
    private String assetType;

    private String owner;

    @Lob
    private String note;

    // source は fill で補正を入れるので NOT NULL のままでOK
    @Column(nullable = false)
    private String source = "JSON_UPLOAD";

    @Column(length = 64)
    private String platform;

    @Column(name = "os_version", length = 128)
    private String osVersion;

    @Column(name = "system_uuid", length = 128)
    private String systemUuid;

    @Column(name = "serial_number", length = 128)
    private String serialNumber;

    @Column(name = "hardware_vendor", length = 255)
    private String hardwareVendor;

    @Column(name = "hardware_model", length = 255)
    private String hardwareModel;

    @Column(name = "hardware_version", length = 255)
    private String hardwareVersion;

    @Column(name = "computer_name", length = 255)
    private String computerName;

    @Column(name = "local_hostname", length = 255)
    private String localHostname;

    @Column(name = "hostname", length = 255)
    private String hostname;

    @Column(name = "cpu_brand", length = 255)
    private String cpuBrand;

    @Column(name = "cpu_physical_cores")
    private Integer cpuPhysicalCores;

    @Column(name = "cpu_logical_cores")
    private Integer cpuLogicalCores;

    @Column(name = "cpu_sockets")
    private Integer cpuSockets;

    @Column(name = "physical_memory")
    private Long physicalMemory;

    @Column(name = "arch", length = 64)
    private String arch;

    @Column(name = "board_vendor", length = 255)
    private String boardVendor;

    @Column(name = "board_model", length = 255)
    private String boardModel;

    @Column(name = "board_version", length = 255)
    private String boardVersion;

    @Column(name = "board_serial", length = 255)
    private String boardSerial;

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
            String hardwareVersion,
            String computerName,
            String localHostname,
            String hostname,
            String cpuBrand,
            Integer cpuPhysicalCores,
            Integer cpuLogicalCores,
            Integer cpuSockets,
            Long physicalMemory,
            String arch,
            String boardVendor,
            String boardModel,
            String boardVersion,
            String boardSerial,
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
        this.hardwareVersion = hardwareVersion;
        this.computerName = computerName;
        this.localHostname = localHostname;
        this.hostname = hostname;

        this.cpuBrand = cpuBrand;
        this.cpuPhysicalCores = cpuPhysicalCores;
        this.cpuLogicalCores = cpuLogicalCores;
        this.cpuSockets = cpuSockets;
        this.physicalMemory = physicalMemory;
        this.arch = arch;

        this.boardVendor = boardVendor;
        this.boardModel = boardModel;
        this.boardVersion = boardVersion;
        this.boardSerial = boardSerial;

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
        LocalDateTime now = DbTime.now();
        this.createdAt = now;
        this.updatedAt = now;
        if (this.source == null || this.source.isBlank()) this.source = "JSON_UPLOAD";
    }

    @PreUpdate
    void preUpdate() {
        this.updatedAt = DbTime.now();
        if (this.source == null || this.source.isBlank()) this.source = "JSON_UPLOAD";
    }
}