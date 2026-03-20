package dev.notegridx.security.assetvulnmanager.domain;

import java.time.LocalDateTime;

import dev.notegridx.security.assetvulnmanager.utility.DbTime;
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

    // Allow null so invalid rows can still be persisted and shown in preview for user correction.
    @Column(name = "external_key", length = 128)
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

    @Column(name = "type", length = 32)
    private String type;

    @Column(name = "source", length = 32)
    private String source;

    @Column(name = "vendor_raw", length = 255)
    private String vendorRaw;

    @Column(name = "product_raw", length = 255)
    private String productRaw;

    @Column(name = "version_raw", length = 128)
    private String versionRaw;

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

    @Column(name = "release_label", length = 128)
    private String release;

    @Column(name = "purl", length = 512)
    private String purl;

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
            LocalDateTime lastSeenAt,
            String type,
            String source,
            String vendorRaw,
            String productRaw,
            String versionRaw,
            String publisher,
            String bundleId,
            String packageManager,
            String installSource,
            String edition,
            String channel,
            String release,
            String purl
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

        this.type = type;
        this.source = source;

        this.vendorRaw = vendorRaw;
        this.productRaw = productRaw;
        this.versionRaw = versionRaw;

        this.publisher = publisher;
        this.bundleId = bundleId;
        this.packageManager = packageManager;
        this.installSource = installSource;

        this.edition = edition;
        this.channel = channel;
        this.release = release;

        this.purl = purl;
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
        if (this.sourceType == null || this.sourceType.isBlank()) this.sourceType = "JSON_UPLOAD";
    }

    @PreUpdate
    void preUpdate() {
        this.updatedAt = DbTime.now();
        if (this.sourceType == null || this.sourceType.isBlank()) this.sourceType = "JSON_UPLOAD";
    }

    @Entity
    @Table(
            name = "kev_sync_state",
            uniqueConstraints = @UniqueConstraint(name = "uq_kev_sync_state_feed", columnNames = {"feed_name"})
    )
    @Getter
    public static class KevSyncState {

        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        @Column(name = "feed_name", nullable = false, length = 64)
        private String feedName;

        @Column(name = "etag", length = 255)
        private String etag;

        @Column(name = "last_modified", length = 128)
        private String lastModified;

        @Column(name = "body_sha256", length = 128)
        private String bodySha256;

        @Column(name = "body_size")
        private Long bodySize;

        @Column(name = "fetched_at")
        private LocalDateTime fetchedAt;

        @Column(nullable = false, name = "created_at")
        private LocalDateTime createdAt;

        @Column(nullable = false, name = "updated_at")
        private LocalDateTime updatedAt;

        protected KevSyncState() {}

        public static KevSyncState of(String feedName) {
            KevSyncState s = new KevSyncState();
            s.feedName = feedName;
            return s;
        }

        public void updateMeta(String etag, String lastModified, String sha256, Long size, LocalDateTime fetchedAt) {
            this.etag = norm(etag);
            this.lastModified = norm(lastModified);
            this.bodySha256 = norm(sha256);
            this.bodySize = size;
            this.fetchedAt = fetchedAt;
        }

        @PrePersist
        void onCreate() {
            LocalDateTime now = DbTime.now();
            if (createdAt == null) createdAt = now;
            if (updatedAt == null) updatedAt = now;
        }

        @PreUpdate
        void onUpdate() {
            updatedAt = DbTime.now();
        }

        private static String norm(String s) {
            if (s == null) return null;
            String t = s.trim();
            return t.isEmpty() ? null : t;
        }
    }
}
