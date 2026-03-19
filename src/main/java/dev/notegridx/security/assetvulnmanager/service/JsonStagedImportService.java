package dev.notegridx.security.assetvulnmanager.service;

import java.io.IOException;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.*;

import com.fasterxml.jackson.annotation.JsonAlias;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.ImportRun;
import dev.notegridx.security.assetvulnmanager.domain.ImportStagingAsset;
import dev.notegridx.security.assetvulnmanager.domain.ImportStagingSoftware;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.domain.enums.SoftwareImportMode;
import dev.notegridx.security.assetvulnmanager.domain.enums.SoftwareType;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportRunRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportStagingAssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportStagingSoftwareRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;

@Service
public class JsonStagedImportService {

    // =========================================================
    // Dependencies
    // =========================================================

    private final ObjectMapper objectMapper;

    private final ImportRunRepository importRunRepository;
    private final ImportStagingAssetRepository stagingAssetRepository;
    private final ImportStagingSoftwareRepository stagingSoftwareRepository;

    private final AssetRepository assetRepository;
    private final SoftwareInstallRepository softwareInstallRepository;
    private final SoftwareDictionaryValidator softwareDictionaryValidator;
    private final CanonicalBackfillService canonicalBackfillService;
    private final AssetSoftwareReplaceService assetSoftwareReplaceService;

    public JsonStagedImportService(
            ObjectMapper objectMapper,
            ImportRunRepository importRunRepository,
            ImportStagingAssetRepository stagingAssetRepository,
            ImportStagingSoftwareRepository stagingSoftwareRepository,
            AssetRepository assetRepository,
            SoftwareInstallRepository softwareInstallRepository,
            SoftwareDictionaryValidator softwareDictionaryValidator,
            CanonicalBackfillService canonicalBackfillService,
            AssetSoftwareReplaceService assetSoftwareReplaceService
    ) {
        this.objectMapper = objectMapper;
        this.importRunRepository = importRunRepository;
        this.stagingAssetRepository = stagingAssetRepository;
        this.stagingSoftwareRepository = stagingSoftwareRepository;
        this.assetRepository = assetRepository;
        this.softwareInstallRepository = softwareInstallRepository;
        this.softwareDictionaryValidator = softwareDictionaryValidator;
        this.canonicalBackfillService = canonicalBackfillService;
        this.assetSoftwareReplaceService = assetSoftwareReplaceService;
    }

    // =========================================================
    // JSON DTOs
    // =========================================================

    /**
     * Represents a single asset row from JSON input.
     * Field aliases allow flexible mapping from external sources (e.g. osquery).
     */

    public static class AssetJsonRow {

        @JsonAlias("external_key")
        public String externalKey;

        public String name;

        @JsonAlias("asset_type")
        public String assetType;

        public String owner;
        public String note;
        public String source;
        public String platform;

        @JsonAlias("os_version")
        public String osVersion;

        @JsonAlias("system_uuid")
        public String systemUuid;

        @JsonAlias("serial_number")
        public String serialNumber;

        @JsonAlias("hardware_vendor")
        public String hardwareVendor;

        @JsonAlias("hardware_model")
        public String hardwareModel;

        @JsonAlias("hardware_version")
        public String hardwareVersion;

        @JsonAlias("computer_name")
        public String computerName;

        @JsonAlias("local_hostname")
        public String localHostname;

        public String hostname;

        @JsonAlias("cpu_brand")
        public String cpuBrand;

        @JsonAlias("cpu_physical_cores")
        public Integer cpuPhysicalCores;

        @JsonAlias("cpu_logical_cores")
        public Integer cpuLogicalCores;

        @JsonAlias("cpu_sockets")
        public Integer cpuSockets;

        @JsonAlias("physical_memory")
        public Long physicalMemory;

        public String arch;

        @JsonAlias("board_vendor")
        public String boardVendor;

        @JsonAlias("board_model")
        public String boardModel;

        @JsonAlias("board_version")
        public String boardVersion;

        @JsonAlias("board_serial")
        public String boardSerial;

        @JsonAlias("os_name")
        public String osName;

        @JsonAlias("os_build")
        public String osBuild;

        @JsonAlias("os_major")
        public Integer osMajor;

        @JsonAlias("os_minor")
        public Integer osMinor;

        @JsonAlias("os_patch")
        public Integer osPatch;

        @JsonAlias("last_seen_at")
        public String lastSeenAt;
    }

    /**
     * Represents a single software row from JSON input.
     * Raw fields are preserved for dictionary matching.
     */

    public static class SoftwareJsonRow {

        @JsonAlias("external_key")
        public String externalKey;

        public String vendor;
        public String product;
        public String version;

        @JsonAlias("install_location")
        public String installLocation;

        @JsonAlias("installed_at")
        public String installedAt;

        @JsonAlias("package_identifier")
        public String packageIdentifier;

        public String arch;

        public String type;
        public String source;

        @JsonAlias("source_type")
        public String sourceType;

        @JsonAlias("vendor_raw")
        public String vendorRaw;

        @JsonAlias("product_raw")
        public String productRaw;

        @JsonAlias("version_raw")
        public String versionRaw;

        public String publisher;

        @JsonAlias("bundle_id")
        public String bundleId;

        @JsonAlias("package_manager")
        public String packageManager;

        @JsonAlias("install_source")
        public String installSource;

        public String edition;
        public String channel;
        public String release;
        public String purl;

        @JsonAlias("last_seen_at")
        public String lastSeenAt;
    }

    // =========================================================
    // Stage: Assets
    // =========================================================

    /**
     * Parses JSON asset array and stores it into staging tables.
     *
     * Validation rules:
     * - externalKey is required
     * - name is required
     *
     * No actual Asset entities are created at this stage.
     */

    @Transactional
    public ImportRun stageAssets(String originalFilename, byte[] bytes) {

        // Same staging concept as CSV:
        // Validate → store → do not mutate domain entities yet

        String sha256 = sha256Hex(bytes);

        ImportRun run = ImportRun.newStaged("JSON_UPLOAD", "JSON_ASSETS", originalFilename, sha256);
        run = importRunRepository.save(run);

        List<AssetJsonRow> rows = parseJsonArray(bytes, new TypeReference<List<AssetJsonRow>>() {});
        int total = rows.size();
        int valid = 0;
        int invalid = 0;

        List<ImportStagingAsset> staging = new ArrayList<>();
        for (int i = 0; i < rows.size(); i++) {
            int rowNo = i + 1;
            AssetJsonRow r = rows.get(i);

            ImportStagingAsset s = ImportStagingAsset.of(run.getId(), rowNo);

            String externalKey = normNullable(r.externalKey);
            String name = normNullable(r.name);

            s.fill(
                    externalKey,
                    name,
                    normNullable(r.assetType),
                    normNullable(r.owner),
                    r.note,
                    normNullable(r.source),
                    normNullable(r.platform),
                    normNullable(r.osVersion),
                    normNullable(r.systemUuid),
                    normNullable(r.serialNumber),
                    normNullable(r.hardwareVendor),
                    normNullable(r.hardwareModel),
                    normNullable(r.hardwareVersion),
                    normNullable(r.computerName),
                    normNullable(r.localHostname),
                    normNullable(r.hostname),
                    normNullable(r.cpuBrand),
                    r.cpuPhysicalCores,
                    r.cpuLogicalCores,
                    r.cpuSockets,
                    r.physicalMemory,
                    normNullable(r.arch),
                    normNullable(r.boardVendor),
                    normNullable(r.boardModel),
                    normNullable(r.boardVersion),
                    normNullable(r.boardSerial),
                    normNullable(r.osName),
                    normNullable(r.osBuild),
                    r.osMajor,
                    r.osMinor,
                    r.osPatch,
                    parseDateTimeNullable(r.lastSeenAt)
            );

            if (externalKey == null) {
                s.markInvalid("externalKey is required");
            } else if (name == null) {
                s.markInvalid("name is required");
            }

            if (s.isValid()) valid++;
            else invalid++;
            staging.add(s);
        }

        stagingAssetRepository.saveAll(staging);
        run.markCounts(total, valid, invalid);
        return importRunRepository.save(run);
    }

    // =========================================================
    // Stage: Software
    // =========================================================

    /**
     * Parses JSON software array and stores it into staging tables.
     *
     * Validation rules:
     * - externalKey must exist
     * - product must exist
     * - referenced asset must exist
     *
     * Raw values (vendorRaw/productRaw/versionRaw) are preserved
     * to support synonym resolution and dictionary matching.
     */

    @Transactional
    public ImportRun stageSoftware(String originalFilename, byte[] bytes) {

        // JSON allows more flexible field presence,
        // so we fallback between raw and normalized fields.

        String sha256 = sha256Hex(bytes);

        ImportRun run = ImportRun.newStaged("JSON_UPLOAD", "JSON_SOFTWARE", originalFilename, sha256);
        run = importRunRepository.save(run);

        List<SoftwareJsonRow> rows = parseJsonArray(bytes, new TypeReference<List<SoftwareJsonRow>>() {});
        int total = rows.size();
        int valid = 0;
        int invalid = 0;

        List<ImportStagingSoftware> staging = new ArrayList<>();
        for (int i = 0; i < rows.size(); i++) {
            int rowNo = i + 1;
            SoftwareJsonRow r = rows.get(i);

            ImportStagingSoftware s = ImportStagingSoftware.of(run.getId(), rowNo);

            String externalKey = normNullable(r.externalKey);

            String vendorRaw = normNullable(r.vendorRaw);
            String productRaw = normNullable(r.productRaw);
            String versionRaw = normNullableAllowEmpty(r.versionRaw);

            String vendor = normNullable(r.vendor);
            if (vendor == null) vendor = vendorRaw;
            if (vendorRaw == null) vendorRaw = vendor;

            String product = normNullable(r.product);
            if (product == null) product = productRaw;
            if (productRaw == null) productRaw = product;

            String version = normNullableAllowEmpty(r.version);
            if (version == null) version = versionRaw;
            if (versionRaw == null) versionRaw = version;

            LocalDateTime installedAt = parseDateTimeNullable(r.installedAt);

            s.fill(
                    externalKey,
                    vendor,
                    product,
                    version,
                    normNullable(r.installLocation),
                    installedAt,
                    normNullable(r.packageIdentifier),
                    normNullable(r.arch),
                    normNullable(r.sourceType) == null ? "JSON_UPLOAD" : normNullable(r.sourceType),
                    parseDateTimeNullable(r.lastSeenAt),
                    normNullable(r.type),
                    normNullable(r.source),
                    vendorRaw,
                    productRaw,
                    versionRaw,
                    normNullable(r.publisher),
                    normNullable(r.bundleId),
                    normNullable(r.packageManager),
                    normNullable(r.installSource),
                    normNullable(r.edition),
                    normNullable(r.channel),
                    normNullable(r.release),
                    normNullable(r.purl)
            );

            if (externalKey == null) {
                s.markInvalid("externalKey is required");
            } else if (product == null || product.isBlank()) {
                s.markInvalid("product is required");
            } else if (!assetRepository.existsByExternalKey(externalKey)) {
                s.markInvalid("asset not found for externalKey=" + externalKey + " (import assets first)");
            }

            if (s.isValid()) valid++;
            else invalid++;
            staging.add(s);
        }

        stagingSoftwareRepository.saveAll(staging);
        run.markCounts(total, valid, invalid);
        return importRunRepository.save(run);
    }

    // =========================================================
    // Import: Assets
    // =========================================================

    /**
     * Converts staged asset rows into Asset entities.
     *
     * Policy:
     * - externalKey is the identity key
     * - existing assets are updated (upsert)
     * - name IS updated (JSON differs from CSV behavior)
     * - inventory fields are updated via updateInventory(...)
     */

    @Transactional
    public ImportRun importAssets(Long runId) {

        // NOTE:
        // JSON import updates asset name, unlike CSV import.
        // This reflects JSON being treated as a more authoritative source.

        ImportRun run = importRunRepository.findById(runId)
                .orElseThrow(() -> new IllegalArgumentException("import_run not found: " + runId));

        List<ImportStagingAsset> rows = stagingAssetRepository.findByImportRunIdOrderByRowNoAsc(runId);

        int upserted = 0;
        LocalDateTime now = LocalDateTime.now();

        for (ImportStagingAsset r : rows) {
            if (!r.isValid()) continue;

            String externalKey = normNullable(r.getExternalKey());
            String name = normNullable(r.getName());
            if (externalKey == null || name == null) continue;

            Asset asset = assetRepository.findByExternalKey(externalKey).orElse(null);
            if (asset == null) {
                asset = new Asset(name);
                asset.updateDetails(externalKey, r.getAssetType(), r.getOwner(), r.getNote());
            } else {
                asset.updateName(name);
                asset.updateDetails(externalKey, r.getAssetType(), r.getOwner(), r.getNote());
            }

            asset.updateInventory(
                    r.getPlatform(),
                    r.getOsVersion(),
                    r.getSystemUuid(),
                    r.getSerialNumber(),
                    r.getHardwareVendor(),
                    r.getHardwareModel(),
                    r.getHardwareVersion(),
                    r.getComputerName(),
                    r.getLocalHostname(),
                    r.getHostname(),
                    r.getCpuBrand(),
                    r.getCpuPhysicalCores(),
                    r.getCpuLogicalCores(),
                    r.getCpuSockets(),
                    r.getPhysicalMemory(),
                    r.getArch(),
                    r.getBoardVendor(),
                    r.getBoardModel(),
                    r.getBoardVersion(),
                    r.getBoardSerial(),
                    r.getOsName(),
                    r.getOsBuild(),
                    r.getOsMajor(),
                    r.getOsMinor(),
                    r.getOsPatch()
            );

            String src = normNullable(r.getSource());
            asset.setSource(src == null ? "JSON_UPLOAD" : src);

            LocalDateTime seenAt = (r.getLastSeenAt() != null) ? r.getLastSeenAt() : now;
            asset.markSeenAt(asset.getSource(), seenAt);

            assetRepository.save(asset);
            upserted++;
        }

        run.markImported(upserted, 0, "Assets imported: upserted=" + upserted + " at " + now);
        return importRunRepository.save(run);
    }

    // =========================================================
    // Import: Software (mode-aware)
    // =========================================================

    /**
     * Entry point supporting import mode control.
     *
     * REPLACE_ASSET_SOFTWARE:
     *   Existing software for each asset is replaced before import.
     */

    @Transactional
    public ImportRun importSoftware(Long runId, SoftwareImportMode mode) {
        SoftwareImportMode effective = (mode == null) ? SoftwareImportMode.REPLACE_ASSET_SOFTWARE : mode;

        if (effective == SoftwareImportMode.REPLACE_ASSET_SOFTWARE) {
            assetSoftwareReplaceService.prepareReplaceForRun(runId);
        }

        return importSoftware(runId);
    }

    // =========================================================
    // Import: Software (core logic)
    // =========================================================

    /**
     * Converts staged software rows into SoftwareInstall entities.
     *
     * Key behaviors:
     * - Upsert per (asset, vendor, product, version)
     * - Raw values are preserved for traceability
     * - Canonical linking is attempted during import
     * - Backfill is executed for unresolved entries
     *
     * Performance optimizations:
     * - assetCache: avoids repeated DB lookups
     * - resolveCache: avoids repeated dictionary resolution
     * - existingByAssetCache: avoids repeated full scans per asset
     */

    @Transactional
    public ImportRun importSoftware(Long runId) {

        // This method is intentionally optimized for bulk ingestion:
        // avoid N+1 queries and repeated resolution work.

        ImportRun run = importRunRepository.findById(runId)
                .orElseThrow(() -> new IllegalArgumentException("import_run not found: " + runId));

        List<ImportStagingSoftware> rows = stagingSoftwareRepository.findByImportRunIdOrderByRowNoAsc(runId);

        int upserted = 0;
        LocalDateTime now = LocalDateTime.now();

        List<Long> backfillCandidateIds = new ArrayList<>();
        Map<String, Optional<Asset>> assetCache = new HashMap<>();
        Map<String, SoftwareDictionaryValidator.Resolve> resolveCache = new HashMap<>();
        Map<Long, Map<String, SoftwareInstall>> existingByAssetCache = new HashMap<>();

        for (ImportStagingSoftware r : rows) {
            if (!r.isValid()) continue;

            String externalKey = normNullable(r.getExternalKey());
            if (externalKey == null) continue;

            Optional<Asset> assetOpt = assetCache.computeIfAbsent(
                    externalKey,
                    assetRepository::findByExternalKey
            );
            Asset asset = assetOpt.orElse(null);
            if (asset == null) continue;

            String vendorRaw = normEmpty(r.getVendorRaw());
            String productRaw = normEmpty(r.getProductRaw());
            String versionRaw = normEmpty(r.getVersionRaw());

            if (vendorRaw.isEmpty()) vendorRaw = normEmpty(r.getVendor());
            if (productRaw.isEmpty()) productRaw = normEmpty(r.getProduct());
            if (versionRaw.isEmpty()) versionRaw = normEmpty(r.getVersion());

            String vendorDisplay = vendorRaw;
            String productDisplay = productRaw;
            String versionDisplay = versionRaw;

            if (productDisplay.isEmpty()) continue;

            Long assetId = asset.getId();

            Map<String, SoftwareInstall> existingForAsset = existingByAssetCache.computeIfAbsent(
                    assetId,
                    id -> {
                        Map<String, SoftwareInstall> m = new HashMap<>();
                        for (SoftwareInstall s : softwareInstallRepository.findByAssetIdOrderByIdAsc(id)) {
                            String key = softwareIdentityKey(
                                    normEmpty(s.getVendor()),
                                    normEmpty(s.getProduct()),
                                    normEmpty(s.getVersion())
                            );
                            m.put(key, s);
                        }
                        return m;
                    }
            );

            String softwareKey = softwareIdentityKey(vendorDisplay, productDisplay, versionDisplay);
            SoftwareInstall sw = existingForAsset.get(softwareKey);

            if (sw == null) {
                sw = new SoftwareInstall(asset, productDisplay);
                sw.updateDetails(vendorDisplay, productDisplay, versionDisplay, null);
            } else {
                sw.updateDetails(vendorDisplay, productDisplay, versionDisplay, sw.getCpeName());
            }

            sw.attachImportRun(runId);

            String st = normNullable(r.getSourceType());
            String src = normNullable(r.getSource());
            LocalDateTime seenAt = (r.getLastSeenAt() != null) ? r.getLastSeenAt() : now;

            if (src == null) src = "JSON_UPLOAD";
            if (st == null) st = "JSON_UPLOAD";

            trySetSoftwareType(sw, r.getType());

            sw.captureRaw(vendorRaw, productRaw, versionRaw);
            sw.setSource(src);

            sw.updateImportExtended(
                    r.getInstallLocation(),
                    r.getInstalledAt(),
                    r.getPackageIdentifier(),
                    r.getArch(),
                    st,
                    seenAt,
                    r.getPublisher(),
                    r.getBundleId(),
                    r.getPackageManager(),
                    r.getInstallSource(),
                    r.getEdition(),
                    r.getChannel(),
                    r.getRelease(),
                    r.getPurl()
            );

            String vIn = normNullable(vendorRaw);
            String pIn = normNullable(productRaw);

            boolean windowsComponent = looksLikeWindowsComponent(pIn);

            if (windowsComponent) {
                sw.unlinkCanonical();
            } else {
                String resolveKey = (vIn == null ? "" : vIn) + "\u0000" + (pIn == null ? "" : pIn);
                SoftwareDictionaryValidator.Resolve res = resolveCache.computeIfAbsent(
                        resolveKey,
                        k -> softwareDictionaryValidator.resolve(vIn, pIn)
                );

                if (res.hit()) {
                    sw.linkCanonical(res.vendorId(), res.productId());
                } else {
                    sw.unlinkCanonical();
                }
            }

            SoftwareInstall saved = softwareInstallRepository.save(sw);
            upserted++;

            existingForAsset.put(softwareKey, saved);

            boolean fullyLinked = saved.getCpeVendorId() != null && saved.getCpeProductId() != null;
            if (!windowsComponent && !fullyLinked && saved.getId() != null) {
                backfillCandidateIds.add(saved.getId());
            }
        }

        canonicalBackfillService.backfillForSoftwareIds(backfillCandidateIds, false);

        run.markImported(0, upserted, null);
        return importRunRepository.save(run);
    }

    private String softwareIdentityKey(String vendor, String product, String version) {
        return normEmpty(vendor) + "\u0000" + normEmpty(product) + "\u0000" + normEmpty(version);
    }

    /**
     * Attempts to map string value to SoftwareType enum.
     * Invalid values are ignored to keep import resilient.
     */
    private static void trySetSoftwareType(SoftwareInstall sw, String type) {
        String t = normNullable(type);
        if (t == null) return;
        try {
            sw.setType(SoftwareType.valueOf(t));
        } catch (IllegalArgumentException ex) {
            // ignore unknown values
        }
    }

    /**
     * Parses JSON array into a list of typed objects.
     * The input must be a top-level JSON array.
     */
    private <T> List<T> parseJsonArray(byte[] bytes, TypeReference<List<T>> typeRef) {
        try {
            return objectMapper.readValue(bytes, typeRef);
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid JSON array: " + e.getMessage(), e);
        }
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest(bytes);
            return HexFormat.of().formatHex(dig).toUpperCase();
        } catch (Exception e) {
            throw new IllegalStateException("sha256 failed: " + e.getMessage(), e);
        }
    }

    /**
     * Normalizes string by trimming and converting blanks to null.
     */
    private static String normNullable(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    /**
     * Same as normNullable but allows empty semantics for version fields.
     */
    private static String normNullableAllowEmpty(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    /**
     * Converts null to empty string for identity key generation.
     */
    private static String normEmpty(String s) {
        if (s == null) return "";
        String t = s.trim();
        return t.isEmpty() ? "" : t;
    }

    /**
     * Parses ISO-8601 or local datetime formats.
     * Invalid values are ignored.
     */
    private static LocalDateTime parseDateTimeNullable(String s) {
        String t = normNullable(s);
        if (t == null) return null;

        try {
            return OffsetDateTime.parse(t).toLocalDateTime();
        } catch (DateTimeParseException ex) {
            try {
                return LocalDateTime.parse(t);
            } catch (DateTimeParseException ex2) {
                return null;
            }
        }
    }

    private static final java.util.regex.Pattern DN_O =
            java.util.regex.Pattern.compile("(?i)(?:^|,)\\s*O\\s*=\\s*([^,]+)");
    private static final java.util.regex.Pattern DN_CN =
            java.util.regex.Pattern.compile("(?i)(?:^|,)\\s*CN\\s*=\\s*([^,]+)");

    private static final java.util.regex.Pattern GUID =
            java.util.regex.Pattern.compile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");

    @SuppressWarnings("unused")
    private static String cleanVendorDisplay(String vendorInput) {
        String t = normNullable(vendorInput);
        if (t == null) return "";

        if (t.contains("=")) {
            var mo = DN_O.matcher(t);
            if (mo.find()) t = mo.group(1).trim();
            else {
                var mcn = DN_CN.matcher(t);
                if (mcn.find()) t = mcn.group(1).trim();
            }
        }

        t = t.replaceAll("(?i)\\band/or its affiliates\\b", " ");
        t = t.replaceAll("(?i)\\b(inc\\.?|llc|ltd\\.?|corp\\.?|corporation|company|co\\.?|gmbh|ag|s\\.a\\.?|technologies|technology|foundation)\\b", " ");
        t = t.replaceAll("\\s+", " ").trim();
        return t;
    }

    // =========================================================
    // Canonical linking behavior
    // =========================================================

    /**
     * Windows components (AppX-style identifiers, GUIDs, etc.)
     * are excluded from canonical linking because they do not map
     * reliably to CPE dictionary entries.
     */
    private static boolean looksLikeWindowsComponent(String productRawOrDisplay) {
        String t = normNullable(productRawOrDisplay);
        if (t == null) return false;

        if (GUID.matcher(t).matches()) return true;

        String lower = t.toLowerCase(java.util.Locale.ROOT);
        if (lower.startsWith("windows.") || lower.startsWith("microsoft.") || lower.startsWith("microsoftwindows.")) return true;

        int dots = 0;
        for (int i = 0; i < t.length(); i++) if (t.charAt(i) == '.') dots++;
        return dots >= 2;
    }
}