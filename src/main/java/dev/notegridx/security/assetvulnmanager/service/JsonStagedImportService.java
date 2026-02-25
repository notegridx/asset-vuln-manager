package dev.notegridx.security.assetvulnmanager.service;

import java.io.IOException;
import java.io.InputStream;
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

    public JsonStagedImportService(
            ObjectMapper objectMapper,
            ImportRunRepository importRunRepository,
            ImportStagingAssetRepository stagingAssetRepository,
            ImportStagingSoftwareRepository stagingSoftwareRepository,
            AssetRepository assetRepository,
            SoftwareInstallRepository softwareInstallRepository
    ) {
        this.objectMapper = objectMapper;
        this.importRunRepository = importRunRepository;
        this.stagingAssetRepository = stagingAssetRepository;
        this.stagingSoftwareRepository = stagingSoftwareRepository;
        this.assetRepository = assetRepository;
        this.softwareInstallRepository = softwareInstallRepository;
    }

    // ===== DTOs (JSON input) =====
    public static class AssetJsonRow {
        public String externalKey;
        public String name;
        public String assetType;
        public String owner;
        public String note;
    }

    public static class SoftwareJsonRow {
        public String externalKey;
        public String vendor;
        public String product;
        public String version;

        public String installLocation;
        public String installedAt; // ISO8601 string (optional)
        public String packageIdentifier;
        public String arch;
    }

    // =========================
    // Stage Assets
    // =========================
    @Transactional
    public ImportRun stageAssets(String originalFilename, byte[] bytes) {
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

            s.fill(externalKey, name, normNullable(r.assetType), normNullable(r.owner), r.note);

            // validation: externalKey required, name required
            if (externalKey == null) {
                s.markInvalid("externalKey is required");
            } else if (name == null) {
                s.markInvalid("name is required");
            }

            if (s.isValid()) valid++; else invalid++;
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
            String vendor = normNullable(r.vendor);
            String product = normNullable(r.product);
            String version = normNullableAllowEmpty(r.version); // null許容（運用上空でもOK）

            LocalDateTime installedAt = parseDateTimeNullable(r.installedAt);

            // last_seen_at は Import 時に更新（policy）なので staging では null のままでもOK
            s.fill(
                    externalKey,
                    vendor,
                    product,
                    version,
                    normNullable(r.installLocation),
                    installedAt,
                    normNullable(r.packageIdentifier),
                    normNullable(r.arch),
                    "JSON_UPLOAD",
                    null
            );

            // validation: externalKey required, product required
            if (externalKey == null) {
                s.markInvalid("externalKey is required");
            } else if (product == null) {
                s.markInvalid("product is required");
            } else {
                // 追加バリデーション：assetが存在する前提（Asset/Software分離）
                if (!assetRepository.existsByExternalKey(externalKey)) {
                    s.markInvalid("asset not found for externalKey=" + externalKey + " (import assets first)");
                }
            }

            if (s.isValid()) valid++; else invalid++;
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
            if (externalKey == null || name == null) continue; // safety

            Asset asset = assetRepository.findByExternalKey(externalKey).orElse(null);
            if (asset == null) {
                asset = new Asset(name);
                asset.updateDetails(externalKey, r.getAssetType(), r.getOwner(), r.getNote());
            } else {
                asset.updateName(name);
                asset.updateDetails(externalKey, r.getAssetType(), r.getOwner(), r.getNote());
            }

            // policy: last_seen_at updated at import time; source fixed
            asset.setSource("JSON_UPLOAD");
            asset.markSeen("JSON_UPLOAD"); // sets source + lastSeenAt now internally

            assetRepository.save(asset);
            upserted++;
        }

        run.markImported(upserted, 0, "Assets imported: upserted=" + upserted + " at " + now);
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
            if (asset == null) {
                // stage時点で弾いている想定だが、安全のためスキップ
                continue;
            }

            // vendor/version は空文字運用OK（既存互換）
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

            // policy: last_seen_at updated at import time; source_type fixed JSON_UPLOAD
            sw.updateImportExtended(
                    r.getInstallLocation(),
                    r.getInstalledAt(),
                    r.getPackageIdentifier(),
                    r.getArch(),
                    "JSON_UPLOAD",
                    now
            );

            softwareInstallRepository.save(sw);
            upserted++;
        }

        run.markImported(0, upserted, "Software imported: upserted=" + upserted + " at " + now);
        return importRunRepository.save(run);
    }

    // =========================
    // Helpers
    // =========================
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
        // version は null 許容（空文字運用もOK） → stagingでは nullでもよい
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

        // ISO8601想定: "2026-02-25T01:02:03Z" or "+09:00" etc
        try {
            return OffsetDateTime.parse(t).toLocalDateTime();
        } catch (DateTimeParseException ex) {
            // "2026-02-25T01:02:03" のように offset無しなら LocalDateTime として解釈
            try {
                return LocalDateTime.parse(t);
            } catch (DateTimeParseException ex2) {
                // invalid format -> treat as null (validation対象にしたいならここで例外化してもよい)
                return null;
            }
        }
    }
}