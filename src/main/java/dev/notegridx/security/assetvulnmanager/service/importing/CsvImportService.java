package dev.notegridx.security.assetvulnmanager.service.importing;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.*;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.ImportRun;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportRunRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.repository.UnresolvedMappingRepository;


@Service
public class CsvImportService {

    private static final String SOURCE_CSV = "CSV";

    private final AssetRepository assetRepository;
    private final SoftwareInstallRepository softwareInstallRepository;
    private final ImportRunRepository importRunRepository;
    private final UnresolvedMappingRepository unresolvedMappingRepository;

    private final TransactionTemplate rowTx;

    public CsvImportService(
            AssetRepository assetRepository,
            SoftwareInstallRepository softwareInstallRepository,
            ImportRunRepository importRunRepository,
            UnresolvedMappingRepository unresolvedMappingRepository,
            PlatformTransactionManager txManager
    ) {
        this.assetRepository = assetRepository;
        this.softwareInstallRepository = softwareInstallRepository;
        this.importRunRepository = importRunRepository;
        this.unresolvedMappingRepository = unresolvedMappingRepository;

        TransactionTemplate tt = new TransactionTemplate(txManager);
        tt.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.rowTx = tt;
    }

    // =========================================================
    // Result DTOs (self-contained)
    // =========================================================


    // =========================================================
    // Assets CSV
    // required: external_key,name
    // optional:
    // asset_type,owner,note,
    // platform,os_version,
    // system_uuid,serial_number,
    // hardware_vendor,hardware_model,hardware_version,
    // computer_name,local_hostname,hostname,
    // cpu_brand,cpu_physical_cores,cpu_logical_cores,cpu_sockets,physical_memory,
    // arch,
    // board_vendor,board_model,board_version,board_serial,
    // os_name,os_build,os_major,os_minor,os_patch
    // =========================================================
    public ImportResult importAssetsCsv(InputStream in, boolean commit) throws IOException {
        List<ImportError> errors = new ArrayList<>();

        int linesRead = 0;
        int ok = 0;
        int inserted = 0;
        int updated = 0;
        int skipped = 0;

        ImportRun run = null;
        if (commit) {
            run = startImportRun("CSV_ASSETS");
        }

        try (BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String headerLine = br.readLine();
            if (headerLine == null) {
                errors.add(new ImportError(1, "EMPTY_FILE", "CSV is empty.", ""));
                if (commit && run != null) finishImportRun(run, 0, 0, 0, errors.size(), "EMPTY_FILE");
                return new ImportResult(!commit, 0, 0, 0, 0, 0, errors.size(), errors);
            }

            linesRead++;
            Map<String, Integer> idx = headerIndex(parseCsvLine(headerLine));
            requireColumns(idx, errors, 1, headerLine, "external_key", "name");

            String line;
            int lineNo = 1;
            while ((line = br.readLine()) != null) {
                lineNo++;
                linesRead++;

                if (isBlankLine(line)) {
                    skipped++;
                    continue;
                }

                List<String> cols = parseCsvLine(line);

                String externalKey = normalizeExternalKey(get(cols, idx, "external_key"));
                String name = normalizeNullable(get(cols, idx, "name"));
                String assetType = normalizeNullable(get(cols, idx, "asset_type"));
                String owner = normalizeNullable(get(cols, idx, "owner"));
                String note = normalizeNullable(get(cols, idx, "note"));

                // Optional inventory attributes
                String platform = normalizeNullable(get(cols, idx, "platform"));
                String osVersion = normalizeNullable(get(cols, idx, "os_version"));

                String systemUuid = normalizeNullable(get(cols, idx, "system_uuid"));
                String serialNumber = normalizeNullable(get(cols, idx, "serial_number"));

                String hardwareVendor = normalizeNullable(get(cols, idx, "hardware_vendor"));
                String hardwareModel = normalizeNullable(get(cols, idx, "hardware_model"));
                String hardwareVersion = normalizeNullable(get(cols, idx, "hardware_version"));

                String computerName = normalizeNullable(get(cols, idx, "computer_name"));
                String localHostname = normalizeNullable(get(cols, idx, "local_hostname"));
                String hostname = normalizeNullable(get(cols, idx, "hostname"));

                String cpuBrand = normalizeNullable(get(cols, idx, "cpu_brand"));
                Integer cpuPhysicalCores = parseIntegerNullable(get(cols, idx, "cpu_physical_cores"));
                Integer cpuLogicalCores = parseIntegerNullable(get(cols, idx, "cpu_logical_cores"));
                Integer cpuSockets = parseIntegerNullable(get(cols, idx, "cpu_sockets"));
                Long physicalMemory = parseLongNullable(get(cols, idx, "physical_memory"));

                String arch = normalizeNullable(get(cols, idx, "arch"));

                String boardVendor = normalizeNullable(get(cols, idx, "board_vendor"));
                String boardModel = normalizeNullable(get(cols, idx, "board_model"));
                String boardVersion = normalizeNullable(get(cols, idx, "board_version"));
                String boardSerial = normalizeNullable(get(cols, idx, "board_serial"));

                String osName = normalizeNullable(get(cols, idx, "os_name"));
                String osBuild = normalizeNullable(get(cols, idx, "os_build"));
                Integer osMajor = parseIntegerNullable(get(cols, idx, "os_major"));
                Integer osMinor = parseIntegerNullable(get(cols, idx, "os_minor"));
                Integer osPatch = parseIntegerNullable(get(cols, idx, "os_patch"));

                if (externalKey == null) {
                    errors.add(new ImportError(lineNo, "INVALID_EXTERNAL_KEY",
                            "external_key is required (trim + uppercase).", line));
                    continue;
                }
                if (name == null) {
                    errors.add(new ImportError(lineNo, "INVALID_NAME",
                            "name is required.", line));
                    continue;
                }

                Asset existing = assetRepository.findByExternalKey(externalKey).orElse(null);

                if (!commit) {
                    ok++;
                    if (existing == null) inserted++;
                    else updated++;
                    continue;
                }

                try {
                    final Asset ex = existing;
                    final ImportRun runFinal = run;

                    rowTx.execute(status -> {
                        Asset a;
                        if (ex == null) {
                            a = new Asset(name);
                        } else {
                            a = ex;
                            // Current behavior: do not update name.
                            // If name update is required, add a setter/method in Asset and update here.
                        }

                        a.updateDetails(externalKey, assetType, owner, note);

                        a.updateInventory(
                                platform,
                                osVersion,
                                systemUuid,
                                serialNumber,
                                hardwareVendor,
                                hardwareModel,
                                hardwareVersion,
                                computerName,
                                localHostname,
                                hostname,
                                cpuBrand,
                                cpuPhysicalCores,
                                cpuLogicalCores,
                                cpuSockets,
                                physicalMemory,
                                arch,
                                boardVendor,
                                boardModel,
                                boardVersion,
                                boardSerial,
                                osName,
                                osBuild,
                                osMajor,
                                osMinor,
                                osPatch
                        );

                        // Mark ingestion source
                        a.markSeen(SOURCE_CSV);

                        assetRepository.save(a);

                        // Update run counters
                        runFinal.setAssetsUpserted(runFinal.getAssetsUpserted() + 1);

                        return null;
                    });

                    ok++;
                    if (existing == null) inserted++;
                    else updated++;

                } catch (DataIntegrityViolationException e) {
                    errors.add(new ImportError(lineNo, "DB_CONSTRAINT",
                            "DB constraint violation. " + safeMsg(e), line));
                } catch (Exception e) {
                    errors.add(new ImportError(lineNo, "UNEXPECTED",
                            "Unexpected error. " + safeMsg(e), line));
                }
            }

        } finally {
            if (commit && run != null) {
                finishImportRun(run, inserted, updated, 0, errors.size(), null);
            }
        }

        return new ImportResult(!commit, linesRead, ok, inserted, updated, skipped, errors.size(), errors);
    }

    // =========================================================
    // Software CSV
    // columns: external_key,vendor,product,version,cpe_name
    // =========================================================

    public ImportResult importSoftwareCsv(InputStream in, boolean commit) throws IOException {
        return importSoftwareCsv(in, commit, Collections.emptySet());
    }

    /**
     * overrideLineNos:
     * Allows specific line numbers to be accepted even if normalization/dictionary resolution is incomplete.
     * Currently no rejection logic is implemented; reserved for future extensions.
     */
    public ImportResult importSoftwareCsv(InputStream in, boolean commit, Set<Integer> overrideLineNos) throws IOException {
        List<ImportError> errors = new ArrayList<>();

        int linesRead = 0;
        int ok = 0;
        int inserted = 0;
        int updated = 0;
        int skipped = 0;
        int unresolvedUpserts = 0;

        final Set<Integer> override = (overrideLineNos == null) ? Collections.emptySet() : overrideLineNos;

        ImportRun run = null;
        if (commit) {
            run = startImportRun("CSV_SOFTWARE");
        }

        try (BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String headerLine = br.readLine();
            if (headerLine == null) {
                errors.add(new ImportError(1, "EMPTY_FILE", "CSV is empty.", ""));
                if (commit && run != null) finishImportRun(run, 0, 0, 0, errors.size(), "EMPTY_FILE");
                return new ImportResult(!commit, 0, 0, 0, 0, 0, errors.size(), errors);
            }

            linesRead++;
            Map<String, Integer> idx = headerIndex(parseCsvLine(headerLine));
            requireColumns(idx, errors, 1, headerLine, "external_key", "vendor", "product");

            String line;
            int lineNo = 1;

            while ((line = br.readLine()) != null) {
                lineNo++;
                linesRead++;

                if (isBlankLine(line)) {
                    skipped++;
                    continue;
                }

                List<String> cols = parseCsvLine(line);

                String externalKey = normalizeExternalKey(get(cols, idx, "external_key"));
                String vendor = normalizeToEmpty(get(cols, idx, "vendor"));
                String product = normalizeNullable(get(cols, idx, "product"));
                String version = normalizeToEmpty(get(cols, idx, "version"));
                String cpeName = normalizeNullable(get(cols, idx, "cpe_name"));

                if (externalKey == null) {
                    errors.add(new ImportError(lineNo, "INVALID_EXTERNAL_KEY",
                            "external_key is required (trim + uppercase).", line));
                    continue;
                }
                if (product == null) {
                    errors.add(new ImportError(lineNo, "INVALID_PRODUCT",
                            "product is required.", line));
                    continue;
                }

                // Lookup asset by external_key
                Asset asset = assetRepository.findByExternalKey(externalKey).orElse(null);
                if (asset == null) {
                    errors.add(new ImportError(lineNo, "ASSET_NOT_FOUND",
                            "Asset not found for external_key=" + externalKey, line));
                    continue;
                }

                // Check existing record based on current UNIQUE constraint
                SoftwareInstall existing = softwareInstallRepository
                        .findByAssetIdAndVendorAndProductAndVersion(asset.getId(), vendor, product, version)
                        .orElse(null);

                boolean overrideThisLine = override.contains(lineNo);

                if (!commit) {
                    ok++;
                    if (existing == null) inserted++;
                    else updated++;
                    continue;
                }

                try {
                    final SoftwareInstall ex = existing;
                    final ImportRun runFinal = run;

                    rowTx.execute(status -> {
                        // Mark asset as seen when software is ingested
                        asset.markSeen(SOURCE_CSV);
                        assetRepository.save(asset);

                        SoftwareInstall si;
                        if (ex == null) {
                            si = new SoftwareInstall(asset, product);
                        } else {
                            si = ex;
                        }

                        // Update display and matching keys
                        si.updateDetails(vendor, product, version, cpeName);

                        // Set ingestion metadata
                        si.markSeen(SOURCE_CSV);
                        si.captureRaw(vendor, product, version);
                        if (runFinal != null) {
                            si.attachImportRun(runFinal.getId());
                        }

                        softwareInstallRepository.save(si);

                        // Update run counters
                        runFinal.setSoftwareUpserted(runFinal.getSoftwareUpserted() + 1);

                        // Queue unresolved mapping when canonical link is missing
                        if (shouldQueueUnresolved(si, overrideThisLine)) {
                            upsertUnresolvedMapping(SOURCE_CSV, vendor, product, version);
                            runFinal.setUnresolvedCount(runFinal.getUnresolvedCount() + 1);
                        }

                        return null;
                    });

                    ok++;
                    if (existing == null) inserted++;
                    else updated++;

                    // Count unresolved attempts (actual count tracked in run.unresolvedCount)
                    if (!overrideThisLine && cpeName == null) unresolvedUpserts++;

                } catch (DataIntegrityViolationException e) {
                    errors.add(new ImportError(lineNo, "DB_CONSTRAINT",
                            "DB constraint violation. " + safeMsg(e), line));
                } catch (Exception e) {
                    errors.add(new ImportError(lineNo, "UNEXPECTED",
                            "Unexpected error. " + safeMsg(e), line));
                }
            }

        } finally {
            if (commit && run != null) {
                finishImportRun(run, inserted, updated, unresolvedUpserts, errors.size(), null);
            }
        }

        return new ImportResult(!commit, linesRead, ok, inserted, updated, skipped, errors.size(), errors);
    }

    private static boolean shouldQueueUnresolved(SoftwareInstall si, boolean overrideThisLine) {
        if (overrideThisLine) return true;
        if (si.getCpeName() != null && !si.getCpeName().isBlank()) return false;

        // Queue as unresolved when canonical IDs are not assigned
        return si.getCpeVendorId() == null || si.getCpeProductId() == null;
    }

    // =========================================================
    // ImportRun helpers
    // =========================================================

    private ImportRun startImportRun(String kind) {
        ImportRun run = ImportRun.start("CSV", "CSV_SOFTWARE");
        run = importRunRepository.save(run);
        run.setSource(SOURCE_CSV);
        run.setKind(kind);
        run.setStartedAt(LocalDateTime.now());
        run.setAssetsUpserted(0);
        run.setSoftwareUpserted(0);
        run.setUnresolvedCount(0);
        run.setErrorCount(0);
        return importRunRepository.save(run);
    }

    private void finishImportRun(ImportRun run, int inserted, int updated, int unresolvedUpserts, int errorCount, String summaryNote) {
        run.setFinishedAt(LocalDateTime.now());

        // Error count is finalized here
        run.setErrorCount(errorCount);

        if (summaryNote != null) {
            run.setSummary(summaryNote);
        }

        importRunRepository.save(run);
    }

    // =========================================================
    // UnresolvedMapping upsert
    // =========================================================

    private void upsertUnresolvedMapping(String source, String vendorRaw, String productRaw, String versionRaw) {
        String v = normalizeNullable(vendorRaw);
        String p = normalizeNullable(productRaw);
        String ver = normalizeNullable(versionRaw);
        String src = normalizeNullable(source);
        if (src == null) src = SOURCE_CSV;

        // Logical key for unresolved mapping: vendor_raw + product_raw
        if (v == null || p == null) return;

        LocalDateTime now = LocalDateTime.now();

        Optional<UnresolvedMapping> existing =
                unresolvedMappingRepository.findTopByVendorRawAndProductRaw(v, p);

        if (existing.isPresent()) {
            UnresolvedMapping um = existing.get();
            um.setLastSeenAt(now);
            um.setSource(src);
            um.setVersionRaw(ver);
            unresolvedMappingRepository.save(um);
            return;
        }

        UnresolvedMapping um = UnresolvedMapping.create(src, v, p, ver);
        unresolvedMappingRepository.save(um);
    }

    // =========================================================
    // CSV helpers
    // =========================================================

    private static boolean isBlankLine(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static String safeMsg(Throwable t) {
        String m = t.getMessage();
        return (m == null) ? t.getClass().getSimpleName() : m;
    }

    private static void requireColumns(
            Map<String, Integer> idx,
            List<ImportError> errors,
            int lineNo,
            String raw,
            String... required
    ) {
        for (String r : required) {
            if (!idx.containsKey(r)) {
                errors.add(new ImportError(lineNo, "MISSING_COLUMN",
                        "Required column missing: " + r, raw));
            }
        }
    }

    private static Map<String, Integer> headerIndex(List<String> header) {
        Map<String, Integer> idx = new LinkedHashMap<>();
        for (int i = 0; i < header.size(); i++) {
            String key = normalizeHeader(header.get(i));
            if (key != null && !idx.containsKey(key)) idx.put(key, i);
        }
        return idx;
    }

    private static String normalizeHeader(String s) {
        if (s == null) return null;
        String t = s.trim().toLowerCase(Locale.ROOT);
        return t.isEmpty() ? null : t;
    }

    private static String get(List<String> cols, Map<String, Integer> idx, String key) {
        Integer i = idx.get(key);
        if (i == null) return null;
        if (i < 0 || i >= cols.size()) return null;
        return cols.get(i);
    }

    private static String normalizeNullable(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static String normalizeToEmpty(String s) {
        String t = normalizeNullable(s);
        return (t == null) ? "" : t;
    }

    private static String normalizeExternalKey(String s) {
        String t = normalizeNullable(s);
        if (t == null) return null;
        return t.toUpperCase(Locale.ROOT);
    }

    /**
     * Minimal CSV parser supporting:
     * - comma-separated values
     * - quoted fields with "" escaping
     */
    private static List<String> parseCsvLine(String line) {
        List<String> out = new ArrayList<>();
        if (line == null) return out;

        StringBuilder cur = new StringBuilder();
        boolean inQuotes = false;

        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);

            if (inQuotes) {
                if (c == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        cur.append('"');
                        i++;
                    } else {
                        inQuotes = false;
                    }
                } else {
                    cur.append(c);
                }
            } else {
                if (c == ',') {
                    out.add(cur.toString());
                    cur.setLength(0);
                } else if (c == '"') {
                    inQuotes = true;
                } else {
                    cur.append(c);
                }
            }
        }
        out.add(cur.toString());
        return out;
    }

    private static Integer parseIntegerNullable(String s) {
        String v = normalizeNullable(s);
        if (v == null) return null;
        try {
            return Integer.valueOf(v);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static Long parseLongNullable(String s) {
        String v = normalizeNullable(s);
        if (v == null) return null;
        try {
            return Long.valueOf(v);
        } catch (NumberFormatException e) {
            return null;
        }
    }
}