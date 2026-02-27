package dev.notegridx.security.assetvulnmanager.domain;

import java.time.LocalDateTime;

import dev.notegridx.security.assetvulnmanager.domain.enums.SoftwareType;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Entity
@Table(
        name = "software_installs",
        uniqueConstraints = @UniqueConstraint(
                name = "uq_sw_asset_vendor_product_version",
                columnNames = {"asset_id", "vendor", "product", "version"}
        )
)
@Getter
public class SoftwareInstall {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "asset_id", nullable = false)
    private Asset asset;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private SoftwareType type = SoftwareType.APPLICATION;

    @Column(nullable = false, length = 32)
    private String source = "MANUAL";

    // ===== Raw input (for troubleshooting & dictionary training) =====

    @Column(name = "vendor_raw", length = 255)
    private String vendorRaw;

    @Column(name = "product_raw", length = 255)
    private String productRaw;

    @Column(name = "version_raw", length = 128)
    private String versionRaw;

    @Column(name = "version_norm", length = 128)
    private String versionNorm;

    @Column(name = "last_seen_at")
    private LocalDateTime lastSeenAt;

    /**
     * FK is defined in schema.sql (import_runs.id) but we keep it as scalar Long
     * (same style as cpeVendorId/cpeProductId) to avoid entity coupling.
     */
    @Column(name = "import_run_id")
    private Long importRunId;

    // ===== New columns (requested) =====

    @Column(name = "install_location", length = 1024)
    private String installLocation;

    @Column(name = "installed_at")
    private LocalDateTime installedAt;

    @Column(name = "package_identifier", length = 255)
    private String packageIdentifier;

    @Column(name = "arch", length = 64)
    private String arch;

    @Column(name = "source_type", nullable = false, length = 64)
    private String sourceType = "UNKNOWN";

    // ===== Added: higher-precision identifiers / provenance =====

    @Column(name = "publisher", length = 255)
    private String publisher;

    @Column(name = "bundle_id", length = 255)
    private String bundleId;

    @Column(name = "package_manager", length = 64)
    private String packageManager;

    @Column(name = "install_source", length = 64)
    private String installSource;

    @Column(name = "edition", length = 128)
    private String edition;

    @Column(name = "channel", length = 64)
    private String channel;

    @Column(name = "release", length = 128)
    private String release;

    @Column(name = "purl", length = 512)
    private String purl;

    // ===== Existing (display & matching key) =====

    @Column(nullable = false)
    private String vendor = "";

    @NotBlank
    @Column(nullable = false)
    private String product;

    @Column(nullable = false, length = 64)
    private String version = "";

    @Column(name = "cpe_name", length = 512)
    private String cpeName;

    @Column(name = "normalized_vendor")
    private String normalizedVendor;

    @Column(name = "normalized_product")
    private String normalizedProduct;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @Column(name = "cpe_vendor_id")
    private Long cpeVendorId;

    @Column(name = "cpe_product_id")
    private Long cpeProductId;

    protected SoftwareInstall() {
    }

    public SoftwareInstall(Asset asset, String product) {
        this.asset = asset;
        this.product = requireNotBlank(product, "product");
        this.vendor = "";
        this.version = "";
        this.type = SoftwareType.APPLICATION;
        this.source = "MANUAL";
        this.sourceType = "UNKNOWN";
    }

    /**
     * Existing behavior: updates the "display/matching key" columns and normalized keys.
     * (raw / last_seen / importRun are handled by dedicated methods below)
     */
    public void updateDetails(String vendor, String product, String version, String cpeName) {
        String p = requireNotBlank(product, "product");
        this.product = p;

        this.vendor = normalizeToEmpty(vendor);
        this.version = normalizeToEmpty(version);

        String cpe = normalizeNullable(cpeName);
        this.cpeName = (cpe == null) ? null : cpe;

        this.normalizedVendor = normalizeForKey(this.vendor);
        this.normalizedProduct = normalizeForKey(this.product);
    }

    public void linkCanonical(Long vendorId, Long productId) {
        this.cpeVendorId = vendorId;
        this.cpeProductId = productId;
    }

    public void unlinkCanonical() {
        this.cpeVendorId = null;
        this.cpeProductId = null;
    }

    // =========================================================
    // New helper methods for snapshot ingestion / troubleshooting
    // =========================================================

    public void setType(SoftwareType type) {
        if (type == null) return;
        this.type = type;
    }

    public void setSource(String source) {
        String s = normalizeNullable(source);
        this.source = (s == null) ? "MANUAL" : s;
    }

    /**
     * Sets ingestion source (CSV/OSQUERY/FLEET/WAZUH/MANUAL...) and updates last_seen_at.
     */
    public void markSeen(String source) {
        String s = normalizeNullable(source);
        this.source = (s == null) ? "MANUAL" : s;
        this.lastSeenAt = LocalDateTime.now();
    }

    /**
     * Stores raw values for troubleshooting / dictionary training.
     */
    public void captureRaw(String vendorRaw, String productRaw, String versionRaw) {
        this.vendorRaw = normalizeNullable(vendorRaw);
        this.productRaw = normalizeNullable(productRaw);
        this.versionRaw = normalizeNullable(versionRaw);

        // version_norm: first step = "trimmed string", not numeric comparison
        this.versionNorm = normalizeVersionNorm(this.versionRaw);
    }

    public void attachImportRun(Long importRunId) {
        this.importRunId = importRunId;
    }

    /**
     * JSON/OSQUERY 等の拡張カラム更新用（要件: last_seen_at 更新 / source_type 固定などに使う）
     *
     * NOTE: initial JSON import policy:
     *  - sourceType: "JSON_UPLOAD"
     *  - lastSeenAt: import-time now
     */
    public void updateImportExtended(
            String installLocation,
            LocalDateTime installedAt,
            String packageIdentifier,
            String arch,
            String sourceType,
            LocalDateTime lastSeenAt
    ) {
        updateImportExtended(
                installLocation,
                installedAt,
                packageIdentifier,
                arch,
                sourceType,
                lastSeenAt,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
        );
    }

    public void updateImportExtended(
            String installLocation,
            LocalDateTime installedAt,
            String packageIdentifier,
            String arch,
            String sourceType,
            LocalDateTime lastSeenAt,
            String publisher,
            String bundleId,
            String packageManager,
            String installSource,
            String edition,
            String channel,
            String release,
            String purl
    ) {
        this.installLocation = normalizeNullable(installLocation);
        this.installedAt = installedAt;
        this.packageIdentifier = normalizeNullable(packageIdentifier);
        this.arch = normalizeNullable(arch);

        String st = normalizeNullable(sourceType);
        this.sourceType = (st == null) ? "UNKNOWN" : st;

        this.lastSeenAt = lastSeenAt;

        this.publisher = normalizeNullable(publisher);
        this.bundleId = normalizeNullable(bundleId);
        this.packageManager = normalizeNullable(packageManager);
        this.installSource = normalizeNullable(installSource);

        this.edition = normalizeNullable(edition);
        this.channel = normalizeNullable(channel);
        this.release = normalizeNullable(release);

        this.purl = normalizeNullable(purl);
    }

    // =========================================================
    // Normalizers
    // =========================================================

    private static String normalizeNullable(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static String normalizeToEmpty(String s) {
        if (s == null) return "";
        String t = s.trim();
        return t.isEmpty() ? "" : t;
    }

    private static String normalizeForKey(String s) {
        if (s == null) return null;
        String x = s.trim().toLowerCase();
        x = x.replaceAll("\\s+", " ");
        x = x.replaceAll("[\\p{Punct}&&[^._-]]+", "");
        x = x.replaceAll("\\s+", " ").trim();
        return x.isEmpty() ? null : x;
    }

    private static String normalizeVersionNorm(String s) {
        String t = normalizeNullable(s);
        if (t == null) return null;
        // First step only: trimmed string. (No semantic version comparison here.)
        return t;
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

        if (this.vendor == null) this.vendor = "";
        if (this.version == null) this.version = "";

        if (this.source == null || this.source.trim().isEmpty()) this.source = "MANUAL";
        if (this.sourceType == null || this.sourceType.trim().isEmpty()) this.sourceType = "UNKNOWN";

        // lastSeenAt は null 許容
    }

    @PreUpdate
    void preUpdate() {
        this.updatedAt = LocalDateTime.now();

        if (this.vendor == null) this.vendor = "";
        if (this.version == null) this.version = "";

        if (this.source == null || this.source.trim().isEmpty()) this.source = "MANUAL";
        if (this.sourceType == null || this.sourceType.trim().isEmpty()) this.sourceType = "UNKNOWN";
    }
}