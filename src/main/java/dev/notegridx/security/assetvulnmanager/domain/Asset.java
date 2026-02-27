package dev.notegridx.security.assetvulnmanager.domain;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;

import lombok.Getter;

@Entity
@Table(
        name = "assets",
        uniqueConstraints = @UniqueConstraint(
                name = "uq_assets_external_key",
                columnNames = {"external_key"}
        )
)
@Getter
public class Asset {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "external_key", length = 128)
    private String externalKey;

    @NotBlank
    @Column(nullable = false)
    private String name;

    @Column(name = "asset_type")
    private String assetType;

    private String owner;

    @Lob
    private String note;

    // ===== Added: inventory identifiers / OS / hardware =====

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

    // ===== Existing: provenance / platform =====

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @OneToMany(mappedBy = "asset", fetch = FetchType.LAZY, cascade = CascadeType.ALL, orphanRemoval = true)
    private List<SoftwareInstall> softwareInstalls = new ArrayList<>();

    @Column(nullable = false)
    private String source = "MANUAL";

    @Column
    private String platform;

    @Column(name = "os_version")
    private String osVersion;

    @Column(name = "last_seen_at")
    private LocalDateTime lastSeenAt;

    protected Asset() {
    }

    public Asset(String name) {
        this.name = requireNotBlank(name, "name");
    }

    // =========================================================
    // Update / ingestion helpers
    // =========================================================

    public void markSeen(String source) {
        markSeenAt(source, LocalDateTime.now());
    }

    public void markSeenAt(String source, LocalDateTime seenAt) {
        String s = (source == null) ? null : source.trim();
        this.source = (s == null || s.isEmpty()) ? "MANUAL" : s;
        this.lastSeenAt = seenAt;
    }

    /**
     * Existing behavior: updates basic identity fields.
     * (Inventory/hardware columns are updated by updateInventory(...) to keep compatibility.)
     */
    public void updateDetails(String externalKey, String assetType, String owner, String note) {
        this.externalKey = normalizeNullable(externalKey);
        this.assetType = normalizeNullable(assetType);
        this.owner = normalizeNullable(owner);
        this.note = note;
    }

    public void updateName(String name) {
        this.name = requireNotBlank(name, "name");
    }

    /**
     * Added behavior: update osquery-derived inventory fields (all optional).
     */
    public void updateInventory(
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
            Integer osPatch
    ) {
        this.platform = normalizeNullable(platform);
        this.osVersion = normalizeNullable(osVersion);

        this.systemUuid = normalizeNullable(systemUuid);
        this.serialNumber = normalizeNullable(serialNumber);
        this.hardwareVendor = normalizeNullable(hardwareVendor);
        this.hardwareModel = normalizeNullable(hardwareModel);
        this.computerName = normalizeNullable(computerName);
        this.localHostname = normalizeNullable(localHostname);

        this.cpuBrand = normalizeNullable(cpuBrand);
        this.cpuPhysicalCores = cpuPhysicalCores;
        this.cpuLogicalCores = cpuLogicalCores;
        this.arch = normalizeNullable(arch);

        this.osName = normalizeNullable(osName);
        this.osBuild = normalizeNullable(osBuild);
        this.osMajor = osMajor;
        this.osMinor = osMinor;
        this.osPatch = osPatch;
    }

    public void setSource(String source) {
        String s = (source == null) ? null : source.trim();
        this.source = (s == null || s.isEmpty()) ? "MANUAL" : s;
    }

    public void setPlatform(String platform) {
        this.platform = normalizeNullable(platform);
    }

    public void setOsVersion(String osVersion) {
        this.osVersion = normalizeNullable(osVersion);
    }

    // =========================================================
    // JPA lifecycle
    // =========================================================

    @PrePersist
    void prePersist() {
        LocalDateTime now = LocalDateTime.now();
        this.createdAt = now;
        this.updatedAt = now;
        if (this.source == null || this.source.trim().isEmpty()) this.source = "MANUAL";
        // lastSeenAt は null 許容（初回観測まで未設定でもOK）
    }

    @PreUpdate
    void preUpdate() {
        this.updatedAt = LocalDateTime.now();
        if (this.source == null || this.source.trim().isEmpty()) this.source = "MANUAL";
    }

    // =========================================================
    // Internal helpers
    // =========================================================

    private static String requireNotBlank(String value, String field) {
        if (value == null) throw new IllegalArgumentException(field + " is required");
        String v = value.trim();
        if (v.isEmpty()) throw new IllegalArgumentException(field + " is required");
        return v;
    }

    private static String normalizeNullable(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }
}