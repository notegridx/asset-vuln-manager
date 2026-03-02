package dev.notegridx.security.assetvulnmanager.service;

import java.io.IOException;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.ImportRun;
import dev.notegridx.security.assetvulnmanager.domain.ImportStagingAsset;
import dev.notegridx.security.assetvulnmanager.domain.ImportStagingSoftware;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.domain.enums.SoftwareType;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportRunRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportStagingAssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportStagingSoftwareRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;

@Service
public class JsonStagedImportService {

    private final ObjectMapper objectMapper;

    private final ImportRunRepository importRunRepository;
    private final ImportStagingAssetRepository stagingAssetRepository;
    private final ImportStagingSoftwareRepository stagingSoftwareRepository;

    private final AssetRepository assetRepository;
    private final SoftwareInstallRepository softwareInstallRepository;
    private final SoftwareDictionaryValidator softwareDictionaryValidator;

    private final CanonicalBackfillService canonicalBackfillService;

    public JsonStagedImportService(
            ObjectMapper objectMapper,
            ImportRunRepository importRunRepository,
            ImportStagingAssetRepository stagingAssetRepository,
            ImportStagingSoftwareRepository stagingSoftwareRepository,
            AssetRepository assetRepository,
            SoftwareInstallRepository softwareInstallRepository,
            SoftwareDictionaryValidator softwareDictionaryValidator,
            CanonicalBackfillService canonicalBackfillService
    ) {
        this.objectMapper = objectMapper;
        this.importRunRepository = importRunRepository;
        this.stagingAssetRepository = stagingAssetRepository;
        this.stagingSoftwareRepository = stagingSoftwareRepository;
        this.assetRepository = assetRepository;
        this.softwareInstallRepository = softwareInstallRepository;
        this.softwareDictionaryValidator = softwareDictionaryValidator;
        this.canonicalBackfillService = canonicalBackfillService;
    }

    // ===== DTOs (JSON input) =====
    public static class AssetJsonRow {
        public String externalKey;
        public String name;
        public String assetType;
        public String owner;
        public String note;

        public String source;
        public String platform;
        public String osVersion;

        public String systemUuid;
        public String serialNumber;
        public String hardwareVendor;
        public String hardwareModel;
        public String computerName;
        public String localHostname;

        public String cpuBrand;
        public Integer cpuPhysicalCores;
        public Integer cpuLogicalCores;
        public String arch;

        public String osName;
        public String osBuild;
        public Integer osMajor;
        public Integer osMinor;
        public Integer osPatch;

        public String lastSeenAt;
    }

    public static class SoftwareJsonRow {
        public String externalKey;

        public String vendor;
        public String product;
        public String version;

        public String installLocation;
        public String installedAt;
        public String packageIdentifier;
        public String arch;

        public String type;
        public String source;
        public String sourceType;

        public String vendorRaw;
        public String productRaw;
        public String versionRaw;

        public String publisher;
        public String bundleId;
        public String packageManager;
        public String installSource;

        public String edition;
        public String channel;
        public String release;

        public String purl;

        public String lastSeenAt;
    }

    // =========================
    // Stage Assets
    // =========================
    @Transactional
    public ImportRun stageAssets(String originalFilename, byte[] bytes) {
        String sha256 = sha256Hex(bytes);

        ImportRun run = ImportRun.newStaged("JSON_UPLOAD", "JSON_ASSETS", originalFilename, sha256);
        run = importRunRepository.save(run);

        List<AssetJsonRow> rows = parseJsonArray(bytes, new TypeReference<List<AssetJsonRow>>() {
        });
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
                    normNullable(r.computerName),
                    normNullable(r.localHostname),
                    normNullable(r.cpuBrand),
                    r.cpuPhysicalCores,
                    r.cpuLogicalCores,
                    normNullable(r.arch),
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

    // =========================
    // Stage Software
    // =========================
    @Transactional
    public ImportRun stageSoftware(String originalFilename, byte[] bytes) {
        String sha256 = sha256Hex(bytes);

        ImportRun run = ImportRun.newStaged("JSON_UPLOAD", "JSON_SOFTWARE", originalFilename, sha256);
        run = importRunRepository.save(run);

        List<SoftwareJsonRow> rows = parseJsonArray(bytes, new TypeReference<List<SoftwareJsonRow>>() {
        });
        int total = rows.size();
        int valid = 0;
        int invalid = 0;

        List<ImportStagingSoftware> staging = new ArrayList<>();
        for (int i = 0; i < rows.size(); i++) {
            int rowNo = i + 1;
            SoftwareJsonRow r = rows.get(i);

            ImportStagingSoftware s = ImportStagingSoftware.of(run.getId(), rowNo);

            String externalKey = normNullable(r.externalKey);
            String vendor = normNullable(r.vendor);
            String product = normNullable(r.product);
            String version = normNullableAllowEmpty(r.version);

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
                    normNullable(r.vendorRaw),
                    normNullable(r.productRaw),
                    normNullable(r.versionRaw),
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
            } else if (product == null) {
                s.markInvalid("product is required");
            } else {
                if (!assetRepository.existsByExternalKey(externalKey)) {
                    s.markInvalid("asset not found for externalKey=" + externalKey + " (import assets first)");
                }
            }

            if (s.isValid()) valid++;
            else invalid++;
            staging.add(s);
        }

        stagingSoftwareRepository.saveAll(staging);
        run.markCounts(total, valid, invalid);
        return importRunRepository.save(run);
    }

    // =========================
    // Import Assets (upsert)
    // =========================
    @Transactional
    public ImportRun importAssets(Long runId) {
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
                    r.getComputerName(),
                    r.getLocalHostname(),
                    r.getCpuBrand(),
                    r.getCpuPhysicalCores(),
                    r.getCpuLogicalCores(),
                    r.getArch(),
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

    // =========================
    // Import Software (upsert)
    // =========================
    @Transactional
    public ImportRun importSoftware(Long runId) {
        ImportRun run = importRunRepository.findById(runId)
                .orElseThrow(() -> new IllegalArgumentException("import_run not found: " + runId));

        List<ImportStagingSoftware> rows = stagingSoftwareRepository.findByImportRunIdOrderByRowNoAsc(runId);

        int upserted = 0;
        LocalDateTime now = LocalDateTime.now();

        for (ImportStagingSoftware r : rows) {
            if (!r.isValid()) continue;

            String externalKey = normNullable(r.getExternalKey());
            String product = normNullable(r.getProduct());
            if (externalKey == null || product == null) continue;

            Asset asset = assetRepository.findByExternalKey(externalKey).orElse(null);
            if (asset == null) continue;

            String vendor = normEmpty(r.getVendor());
            String version = normEmpty(r.getVersion());

            SoftwareInstall sw = softwareInstallRepository
                    .findByAssetIdAndVendorAndProductAndVersion(asset.getId(), vendor, product, version)
                    .orElse(null);

            if (sw == null) {
                sw = new SoftwareInstall(asset, product);
                sw.updateDetails(vendor, product, version, null);
            } else {
                sw.updateDetails(vendor, product, version, sw.getCpeName());
            }

            // ★ import_run_id を必ず付与（importRunId方式の要）
            sw.attachImportRun(runId);

            String st = normNullable(r.getSourceType());
            String src = normNullable(r.getSource());
            LocalDateTime seenAt = (r.getLastSeenAt() != null) ? r.getLastSeenAt() : now;

            if (src == null) src = "JSON_UPLOAD";
            if (st == null) st = "JSON_UPLOAD";

            trySetSoftwareType(sw, r.getType());

            sw.captureRaw(r.getVendorRaw(), r.getProductRaw(), r.getVersionRaw());

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

            // resolve at import-time (existing behavior)
            String vIn = normNullable(r.getVendorRaw());
            String pIn = normNullable(r.getProductRaw());
            if (vIn == null) vIn = normNullable(vendor);
            if (pIn == null) pIn = normNullable(product);

            var res = softwareDictionaryValidator.resolve(vIn, pIn);
            if (res.hit()) {
                sw.linkCanonical(res.vendorId(), res.productId());
            } else {
                sw.unlinkCanonical();
            }

            softwareInstallRepository.save(sw);
            upserted++;
        }

        // ★ DBに確実に入ったIDを runId で取得して targeted backfill
        List<Long> ids = softwareInstallRepository.findIdsByImportRunId(runId);
        var bf = canonicalBackfillService.backfillForSoftwareIds(ids, false);

        run.markImported(
                0,
                upserted,
                "Software imported: upserted=" + upserted
                        + ", backfill(scanned=" + bf.scanned()
                        + ", linked=" + bf.linked()
                        + ", missed=" + bf.missed()
                        + ") at " + now
        );
        return importRunRepository.save(run);
    }

    // =========================
    // Helpers
    // =========================
    private static void trySetSoftwareType(SoftwareInstall sw, String type) {
        String t = normNullable(type);
        if (t == null) return;
        try {
            sw.setType(SoftwareType.valueOf(t));
        } catch (IllegalArgumentException ex) {
            // ignore unknown values
        }
    }

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

    private static String normNullable(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static String normNullableAllowEmpty(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static String normEmpty(String s) {
        if (s == null) return "";
        String t = s.trim();
        return t.isEmpty() ? "" : t;
    }

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
}