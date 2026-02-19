package dev.notegridx.security.assetvulnmanager.service.importing;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.service.SoftwareDictionaryValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Service
public class CsvImportService {

    private final AssetRepository assetRepository;
    private final SoftwareInstallRepository softwareInstallRepository;
    private final SoftwareDictionaryValidator dictValidator;

    private final TransactionTemplate rowTx;

    private final DictMode dictMode;

    public enum DictMode { STRICT, LENIENT }

    public CsvImportService(
            AssetRepository assetRepository,
            SoftwareInstallRepository softwareInstallRepository,
            SoftwareDictionaryValidator dictValidator,
            PlatformTransactionManager txManager,
            @Value("${app.software.dict-mode:LENIENT}") String dictMode
    ) {
        this.assetRepository = assetRepository;
        this.softwareInstallRepository = softwareInstallRepository;
        this.dictValidator = dictValidator;

        TransactionTemplate tt = new TransactionTemplate(txManager);
        tt.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.rowTx = tt;

        this.dictMode = parseDictMode(dictMode);
    }

    private static DictMode parseDictMode(String s) {
        if (s == null) return DictMode.LENIENT;
        try {
            return DictMode.valueOf(s.trim().toUpperCase(Locale.ROOT));
        } catch (Exception e) {
            return DictMode.LENIENT;
        }
    }

// =========================
// Asset CSV Import
// =========================

    public ImportResult importAssetsCsv(InputStream in, boolean commit) throws IOException {
        List<ImportError> errors = new ArrayList<>();

        int linesRead = 0;
        int ok = 0;
        int inserted = 0;
        int updated = 0;
        int skipped = 0;

        try (BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String headerLine = br.readLine();
            if (headerLine == null) {
                return new ImportResult(!commit, 0, 0, 0, 0, 0, 1,
                        List.of(new ImportError(1, "EMPTY_FILE", "CSV is empty", "")));
            }

            linesRead++;
            List<String> header = parseCsvLine(headerLine);
            Map<String, Integer> idx = headerIndex(header);

            // required columns
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

                if (externalKey == null) {
                    errors.add(new ImportError(lineNo, "INVALID_EXTERNAL_KEY",
                            "external_key is required (trim+uppercase).", line));
                    continue;
                }
                if (name == null) {
                    errors.add(new ImportError(lineNo, "INVALID_NAME",
                            "name is required.", line));
                    continue;
                }

                // upsert decision
                Asset existing = assetRepository.findByExternalKey(externalKey).orElse(null);

                if (!commit) {
                    ok++;
                    if (existing == null) inserted++;
                    else updated++;
                    continue;
                }

                try {
                    final Asset ex = existing;
                    rowTx.execute(status -> {
                        if (ex == null) {
                            Asset a = new Asset(name);
                            a.updateDetails(externalKey, assetType, owner, note);
                            assetRepository.save(a);
                        } else {
                            ex.updateDetails(externalKey, assetType, owner, note);
                            assetRepository.save(ex);
                        }
                        return null;
                    });

                    ok++;
                    if (existing == null) inserted++;
                    else updated++;

                } catch (DataIntegrityViolationException e) {
                    errors.add(new ImportError(lineNo, "DB_CONSTRAINT", "DB constraint violation. " + safeMsg(e), line));
                } catch (Exception e) {
                    errors.add(new ImportError(lineNo, "UNEXPECTED",
                            "Unexpected error. " + safeMsg(e), line));
                }
            }
        }

        return new ImportResult(!commit, linesRead, ok, inserted, updated, skipped, errors.size(), errors);
    }

    // =========================
    // SoftwareInstall CSV Import
    // =========================
    public ImportResult importSoftwareCsv(InputStream in, boolean commit) throws IOException {
        List<ImportError> errors = new ArrayList<>();

        int linesRead = 0;
        int ok = 0;
        int inserted = 0;
        int updated = 0;
        int skipped = 0;

        try (BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String headerLine = br.readLine();
            if (headerLine == null) {
                return new ImportResult(!commit, 0, 0, 0, 0, 0, 1,
                        List.of(new ImportError(1, "EMPTY_FILE", "CSV is empty", "")));
            }

            linesRead++;
            List<String> header = parseCsvLine(headerLine);
            Map<String, Integer> idx = headerIndex(header);

            // required columns
            if (dictMode == DictMode.STRICT) {
                requireColumns(idx, errors, 1, headerLine, "external_key", "vendor", "product");
            } else {
                requireColumns(idx, errors, 1, headerLine, "external_key", "product");
            }

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
                            "external_key is required (trim+uppercase).", line));
                    continue;
                }
                if (product == null) {
                    errors.add(new ImportError(lineNo, "INVALID_PRODUCT",
                            "product is required.", line));
                    continue;
                }

                // --- dictionary validation (STRICT: must pass / LENIENT: try resolve and link if possible) ---
                SoftwareDictionaryValidator.Resolve dictResolve = dictValidator.resolve(vendor, product);
                if (dictMode == DictMode.STRICT && !dictResolve.hit()) {
                    String code = (dictResolve.code() == null) ? "DICT_VALIDATION_FAILED" : dictResolve.code().name();
                    String msg = (dictResolve.message() == null) ? "Dictionary validation failed." : dictResolve.message();
                    errors.add(new ImportError(lineNo, code, msg, line));
                    continue;
                }

                Asset asset = assetRepository.findByExternalKey(externalKey).orElse(null);
                if (asset == null) {
                    errors.add(new ImportError(lineNo, "ASSET_NOT_FOUND",
                            "Asset not found for external_key=" + externalKey, line));
                    continue;
                }

                Long assetId = asset.getId();
                SoftwareInstall existing = softwareInstallRepository
                        .findByAssetIdAndVendorAndProductAndVersion(assetId, vendor, product, version)
                        .orElse(null);

                if (!commit) {
                    ok++;
                    if (existing == null) inserted++;
                    else updated++;
                    continue;
                }

                try {
                    final SoftwareInstall ex = existing;
                    final SoftwareDictionaryValidator.Resolve rFinal = dictResolve;

                    rowTx.execute(status -> {
                        if (ex == null) {
                            SoftwareInstall si = new SoftwareInstall(asset, product);
                            si.updateDetails(vendor, product, version, cpeName);

                            if (rFinal != null && rFinal.hit()) {
                                si.linkCanonical(rFinal.vendorId(), rFinal.productId());
                            } else {
                                si.unlinkCanonical();
                            }

                            softwareInstallRepository.save(si);

                        } else {
                            ex.updateDetails(vendor, product, version, cpeName);

                            if (rFinal != null && rFinal.hit()) {
                                ex.linkCanonical(rFinal.vendorId(), rFinal.productId());
                            } else {
                                ex.unlinkCanonical();
                            }

                            softwareInstallRepository.save(ex);
                        }
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
        }

        return new ImportResult(!commit, linesRead, ok, inserted, updated, skipped, errors.size(), errors);
    }

// =========================
// Helpers (CSV)
// =========================

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
            String... required) {
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

    /*
      Minimal CSV parser supporting:
      - comma separated
      - quoted fields with "" escape
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
                    // escaped quote?
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
