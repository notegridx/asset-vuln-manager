package dev.notegridx.security.assetvulnmanager.service;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
public class CsvStagedImportService {

    private final ImportRunRepository importRunRepository;
    private final ImportStagingAssetRepository stagingAssetRepository;
    private final ImportStagingSoftwareRepository stagingSoftwareRepository;
    private final AssetRepository assetRepository;
    private final SoftwareInstallRepository softwareInstallRepository;
    private final SoftwareDictionaryValidator softwareDictionaryValidator;

    public CsvStagedImportService(
            ImportRunRepository importRunRepository,
            ImportStagingAssetRepository stagingAssetRepository,
            ImportStagingSoftwareRepository stagingSoftwareRepository,
            AssetRepository assetRepository,
            SoftwareInstallRepository softwareInstallRepository,
            SoftwareDictionaryValidator softwareDictionaryValidator
    ) {
        this.importRunRepository = importRunRepository;
        this.stagingAssetRepository = stagingAssetRepository;
        this.stagingSoftwareRepository = stagingSoftwareRepository;
        this.assetRepository = assetRepository;
        this.softwareInstallRepository = softwareInstallRepository;
        this.softwareDictionaryValidator = softwareDictionaryValidator;
    }

    // =========================
    // Stage Assets CSV
    // =========================
    @Transactional
    public ImportRun stageAssets(String originalFilename, byte[] bytes) {
        String sha256 = sha256Hex(bytes);

        ImportRun run = ImportRun.newStaged("CSV_UPLOAD", "CSV_ASSETS", originalFilename, sha256);
        run = importRunRepository.save(run);

        List<Map<String, String>> rows = parseCsv(bytes);
        int total = rows.size();
        int valid = 0;
        int invalid = 0;

        List<ImportStagingAsset> staging = new ArrayList<>();

        for (int i = 0; i < rows.size(); i++) {
            int rowNo = i + 1;
            Map<String, String> r = rows.get(i);

            ImportStagingAsset s = ImportStagingAsset.of(run.getId(), rowNo);

            String externalKey = normNullable(r.get("external_key"));
            String name = normNullable(r.get("name"));

            s.fill(
                    externalKey,
                    name,
                    normNullable(r.get("asset_type")),
                    normNullable(r.get("owner")),
                    r.get("note"),
                    normNullable(r.get("source")) == null ? "CSV_UPLOAD" : normNullable(r.get("source")),
                    normNullable(r.get("platform")),
                    normNullable(r.get("os_version")),
                    normNullable(r.get("system_uuid")),
                    normNullable(r.get("serial_number")),
                    normNullable(r.get("hardware_vendor")),
                    normNullable(r.get("hardware_model")),
                    normNullable(r.get("computer_name")),
                    normNullable(r.get("local_hostname")),
                    normNullable(r.get("cpu_brand")),
                    parseIntNullable(r.get("cpu_physical_cores")),
                    parseIntNullable(r.get("cpu_logical_cores")),
                    normNullable(r.get("arch")),
                    normNullable(r.get("os_name")),
                    normNullable(r.get("os_build")),
                    parseIntNullable(r.get("os_major")),
                    parseIntNullable(r.get("os_minor")),
                    parseIntNullable(r.get("os_patch")),
                    parseDateTimeNullable(r.get("last_seen_at"))
            );

            if (externalKey == null) {
                s.markInvalid("external_key is required");
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
    // Stage Software CSV
    // =========================
    @Transactional
    public ImportRun stageSoftware(String originalFilename, byte[] bytes) {
        String sha256 = sha256Hex(bytes);

        ImportRun run = ImportRun.newStaged("CSV_UPLOAD", "CSV_SOFTWARE", originalFilename, sha256);
        run = importRunRepository.save(run);

        List<Map<String, String>> rows = parseCsv(bytes);
        int total = rows.size();
        int valid = 0;
        int invalid = 0;

        List<ImportStagingSoftware> staging = new ArrayList<>();

        for (int i = 0; i < rows.size(); i++) {
            int rowNo = i + 1;
            Map<String, String> r = rows.get(i);

            ImportStagingSoftware s = ImportStagingSoftware.of(run.getId(), rowNo);

            String externalKey = normNullable(r.get("external_key"));
            String vendor = normNullable(r.get("vendor"));
            String product = normNullable(r.get("product"));
            String version = normNullableAllowEmpty(r.get("version")); // null許容

            LocalDateTime installedAt = parseDateTimeNullable(r.get("installed_at"));

            s.fill(
                    externalKey,
                    vendor,
                    product,
                    version,
                    normNullable(r.get("install_location")),
                    installedAt,
                    normNullable(r.get("package_identifier")),
                    normNullable(r.get("arch")),
                    normNullable(r.get("source_type")) == null ? "CSV_UPLOAD" : normNullable(r.get("source_type")),
                    parseDateTimeNullable(r.get("last_seen_at")),
                    normNullable(r.get("type")),
                    normNullable(r.get("source")),
                    normNullable(r.get("vendor_raw")),
                    normNullable(r.get("product_raw")),
                    normNullable(r.get("version_raw")),
                    normNullable(r.get("publisher")),
                    normNullable(r.get("bundle_id")),
                    normNullable(r.get("package_manager")),
                    normNullable(r.get("install_source")),
                    normNullable(r.get("edition")),
                    normNullable(r.get("channel")),
                    normNullable(r.get("release")),
                    normNullable(r.get("purl"))
            );

            if (externalKey == null) {
                s.markInvalid("external_key is required");
            } else if (product == null) {
                s.markInvalid("product is required");
            } else {
                if (!assetRepository.existsByExternalKey(externalKey)) {
                    s.markInvalid("asset not found for external_key=" + externalKey + " (import assets first)");
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
            asset.setSource(src == null ? "CSV_UPLOAD" : src);

            LocalDateTime seenAt = (r.getLastSeenAt() != null) ? r.getLastSeenAt() : now;
            asset.markSeenAt(asset.getSource(), seenAt);

            assetRepository.save(asset);
            upserted++;
        }

        run.markImported(upserted, 0, "Assets imported (CSV): upserted=" + upserted + " at " + now);
        return importRunRepository.save(run);
    }

    // =========================
    // Import Software (upsert)
    // Key: asset_id + vendor + product + version (DB unique)
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

            // optional: type
            trySetSoftwareType(sw, r.getType());

            // raw values
            sw.captureRaw(r.getVendorRaw(), r.getProductRaw(), r.getVersionRaw());

            // provenance
            String st = normNullable(r.getSourceType());
            String src = normNullable(r.getSource());
            if (src == null) src = "CSV_UPLOAD";
            if (st == null) st = "CSV_UPLOAD";

            LocalDateTime seenAt = (r.getLastSeenAt() != null) ? r.getLastSeenAt() : now;

            sw.setSource(src);

            // extended columns
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

            // =========================================================
            // Resolve canonical IDs at import-time (Top20 vendor guarantee)
            // Prefer raw (vendor_raw/product_raw) if present.
            // =========================================================
            String vIn = normNullable(r.getVendorRaw());
            String pIn = normNullable(r.getProductRaw());
            if (vIn == null) vIn = normNullable(vendor);   // vendor may be "" (normEmpty) -> null here
            if (pIn == null) pIn = normNullable(product);

            var res = softwareDictionaryValidator.resolve(vIn, pIn);
            if (res.hit()) {
                // productId may be null (vendor-only link). That still satisfies KPI1.
                sw.linkCanonical(res.vendorId(), res.productId());
            } else {
                // Safety: avoid leaving stale links when raw changes
                sw.unlinkCanonical();
            }

            softwareInstallRepository.save(sw);
            upserted++;
        }

        run.markImported(0, upserted, "Software imported (CSV): upserted=" + upserted + " at " + now);
        return importRunRepository.save(run);
    }

    // =========================
    // CSV parsing (header -> value)
    // =========================
    private static List<Map<String, String>> parseCsv(byte[] bytes) {
        try (BufferedReader br = new BufferedReader(new InputStreamReader(
                new ByteArrayInputStream(bytes), java.nio.charset.StandardCharsets.UTF_8))) {

            String headerLine = br.readLine();
            if (headerLine == null) return List.of();

            List<String> headers = splitCsvLine(headerLine);
            List<Map<String, String>> out = new ArrayList<>();

            String line;
            while ((line = br.readLine()) != null) {
                if (line.isBlank()) continue;
                List<String> cols = splitCsvLine(line);
                Map<String, String> row = new HashMap<>();
                for (int i = 0; i < headers.size(); i++) {
                    String key = headers.get(i);
                    String val = (i < cols.size()) ? cols.get(i) : null;
                    row.put(key, val);
                }
                out.add(row);
            }
            return out;
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid CSV: " + e.getMessage(), e);
        }
    }

    private static List<String> splitCsvLine(String line) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inQ = false;

        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (inQ) {
                if (c == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        cur.append('"');
                        i++;
                    } else {
                        inQ = false;
                    }
                } else {
                    cur.append(c);
                }
            } else {
                if (c == ',') {
                    out.add(cur.toString());
                    cur.setLength(0);
                } else if (c == '"') {
                    inQ = true;
                } else {
                    cur.append(c);
                }
            }
        }
        out.add(cur.toString());
        return out;
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
            // ignore
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

    private static Integer parseIntNullable(String s) {
        String t = normNullable(s);
        if (t == null) return null;
        try {
            return Integer.valueOf(t);
        } catch (NumberFormatException ex) {
            return null;
        }
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