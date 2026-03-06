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
    // columns: external_key,name,asset_type,owner,note,platform,os_version
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
                // optional
                String platform = get(cols, idx, "platform");
                String osVersion = get(cols, idx, "os_version");

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
                            // 既存方針が「nameは更新しない」ならここは触らない。
                            // nameを更新したい場合は Asset に setter/メソッドを追加してここで更新。
                        }

                        a.updateDetails(externalKey, assetType, owner, note);
                        // optional fields
                        a.setPlatform(platform);
                        a.setOsVersion(osVersion);


                        // ingestion metadata（Asset側に markSeen(String) を実装している前提）
                        a.markSeen(SOURCE_CSV);

                        assetRepository.save(a);

                        // run counts
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
     * overrideLineNos: その行番号は、たとえ辞書/正規化が不完全でも登録を許可したい、などの運用用。
     * （この実装では “落とす” 処理は入れていないので、将来拡張用の入口として保持）
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

                // asset lookup
                Asset asset = assetRepository.findByExternalKey(externalKey).orElse(null);
                if (asset == null) {
                    errors.add(new ImportError(lineNo, "ASSET_NOT_FOUND",
                            "Asset not found for external_key=" + externalKey, line));
                    continue;
                }

                // existing check (current UNIQUE strategy)
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
                        // Asset is also "seen" if software arrives
                        asset.markSeen(SOURCE_CSV);
                        assetRepository.save(asset);

                        SoftwareInstall si;
                        if (ex == null) {
                            si = new SoftwareInstall(asset, product);
                        } else {
                            si = ex;
                        }

                        // display/matching key update (existing behavior)
                        si.updateDetails(vendor, product, version, cpeName);

                        // ingestion metadata (new columns)
                        si.markSeen(SOURCE_CSV);
                        si.captureRaw(vendor, product, version);
                        if (runFinal != null) {
                            si.attachImportRun(runFinal.getId());
                        }

                        softwareInstallRepository.save(si);

                        // run counts
                        runFinal.setSoftwareUpserted(runFinal.getSoftwareUpserted() + 1);

                        // unresolved mapping queue:
                        // 最低限の運用：cpe_name が空、かつ canonical (vendor/product id) が未解決のままならキューへ
                        // （厳密な “辞書miss判定” は後段で resolve ロジックを差し込める）
                        if (shouldQueueUnresolved(si, overrideThisLine)) {
                            upsertUnresolvedMapping(SOURCE_CSV, vendor, product, version);
                            runFinal.setUnresolvedCount(runFinal.getUnresolvedCount() + 1);
                        }

                        return null;
                    });

                    ok++;
                    if (existing == null) inserted++;
                    else updated++;

                    // unresolvedUpserts は“試行回数”として加算（正確な upsert 数は run.unresolvedCount を参照）
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

        // canonical ids が未設定なら unresolved へ
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

        // counts are already incremented inside rowTx; set errorCount here
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

        // 新仕様: unresolved の論理キーは vendor_raw + product_raw
        if (v == null || p == null) return;

        LocalDateTime now = LocalDateTime.now();

        Optional<UnresolvedMapping> existing =
                unresolvedMappingRepository.findTopByVendorRawAndProductRaw(v, p);

        if (existing.isPresent()) {
            UnresolvedMapping um = existing.get();
            um.setLastSeenAt(now);
            um.setSource(src);       // reference only
            um.setVersionRaw(ver);   // reference only
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
     * - comma separated
     * - quoted fields with "" escape
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
}