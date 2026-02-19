package dev.notegridx.security.assetvulnmanager.service.importing;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;


import dev.notegridx.security.assetvulnmanager.service.SoftwareDictionaryValidator;
import dev.notegridx.security.assetvulnmanager.service.importing.ImportError;
import dev.notegridx.security.assetvulnmanager.service.importing.ImportResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.TransactionException;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Service
public class CsvImportService {

    private final AssetRepository assetRepository;
    private final SoftwareInstallRepository softwareInstallRepository;
    private final SoftwareDictionaryValidator dictValidator;

    private final TransactionTemplate rowTx;

    private final DictMode dictMode;

    public enum DictMode {STRICT, LENIENT}

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

    // =========================================================
    // Assets CSV import
    // =========================================================
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
                            // Asset(name) がある前提（あなたのプロジェクトではこれで作っているはず）
                            Asset a = new Asset(name);

                            // external_key / assetType / owner / note の更新は既存仕様に合わせて
                            // updateDetails がある前提（無い場合はここをあなたのAsset実装に合わせて直して）
                            a.updateDetails(externalKey, assetType, owner, note);

                            assetRepository.save(a);
                        } else {
                            // 既存Assetの更新
                            ex.updateDetails(externalKey, assetType, owner, note);

                            // ⚠️ name更新をしたい場合：
                            // - Asset に setName(String) があるなら ex.setName(name);
                            // - nameを変えない設計なら何もしない
                            // ex.setName(name);

                            assetRepository.save(ex);
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

    // =========================================================
    // Software CSV import
    // =========================================================

    // 互換維持：2引数版は残す
    public ImportResult importSoftwareCsv(InputStream in, boolean commit) throws IOException {
        return importSoftwareCsv(in, commit, Collections.emptySet());
    }

    /**
     * overrideLineNos に含まれる行番号は、STRICTでも辞書missを許容してDB登録する。
     * <p>
     * また「すでにDBに存在する行」は、次回のoverride実行で再読込されても
     * DICT_* エラーとして再表示されないようにする（既存行は辞書チェックで落とさない）。
     */
    public ImportResult importSoftwareCsv(InputStream in, boolean commit, Set<Integer> overrideLineNos) throws IOException {
        List<ImportError> errors = new ArrayList<>();

        int linesRead = 0;
        int ok = 0;
        int inserted = 0;
        int updated = 0;
        int skipped = 0;

        final Set<Integer> override = (overrideLineNos == null) ? Collections.emptySet() : overrideLineNos;

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
            // STRICTでも override があるため vendor/product は必須としておく（運用上安全）
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
                            "external_key is required (trim+uppercase).", line));
                    continue;
                }
                if (product == null) {
                    errors.add(new ImportError(lineNo, "INVALID_PRODUCT",
                            "product is required.", line));
                    continue;
                }

                boolean overrideThisLine = override.contains(lineNo);

                // (重要) 先に Asset / existing を確定する
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

                // ---- 辞書チェック方針 ----
                // 1) override行：STRICTでも辞書missを許容（resolveしない = canonicalは触らない/新規はnull）
                // 2) 既存行：次回再実行時に DICT_* でまた落ちて再表示されるのを防ぐため、辞書missで落とさない
                // 3) 新規行＆overrideでない：STRICTなら辞書HIT必須、LENIENTならHIT時のみリンク
                SoftwareDictionaryValidator.Resolve dictResolve = null;
                boolean touchCanonical = false; // canonical を変更するか（勝手にunlinkしないためのガード）

                if (!overrideThisLine && existing == null) {
                    // 新規行：ここでのみ辞書を評価
                    dictResolve = dictValidator.resolve(vendor, product);

                    if (dictMode == DictMode.STRICT && !dictResolve.hit()) {
                        String code = (dictResolve.code() == null) ? "DICT_VALIDATION_FAILED" : dictResolve.code().name();
                        String msg = (dictResolve.message() == null) ? "Dictionary validation failed." : dictResolve.message();
                        errors.add(new ImportError(lineNo, code, msg, line));
                        continue;
                    }

                    // LENIENTでもHITしたならリンクしたいので、触る対象にする
                    if (dictResolve.hit()) {
                        touchCanonical = true;
                    }

                } else if (!overrideThisLine && existing != null) {
                    // 既存行：辞書missで落とさない（再表示防止）
                    // canonical は “触らない” (touchCanonical=false) をデフォルトにして現状維持
                    dictResolve = null;
                    touchCanonical = false;

                } else {
                    // override行：辞書missを許容。canonicalは基本触らない。
                    // 新規 insert の場合 canonical は null のまま。既存 update の場合も現状維持。
                    dictResolve = null;
                    touchCanonical = false;
                }

                if (!commit) {
                    ok++;
                    if (existing == null) inserted++;
                    else updated++;
                    continue;
                }

                try {
                    final SoftwareInstall ex = existing;
                    final SoftwareDictionaryValidator.Resolve rFinal = dictResolve;
                    final boolean touchCanonicalFinal = touchCanonical;

                    rowTx.execute(status -> {
                        if (ex == null) {
                            SoftwareInstall si = new SoftwareInstall(asset, product);
                            si.updateDetails(vendor, product, version, cpeName);

                            // 新規は “HITした場合のみ link”。miss/override は何もしない（= nullのまま）
                            if (touchCanonicalFinal && rFinal != null && rFinal.hit()) {
                                si.linkCanonical(rFinal.vendorId(), rFinal.productId());
                            }
                            softwareInstallRepository.save(si);

                        } else {
                            ex.updateDetails(vendor, product, version, cpeName);

                            // 既存は “触るべき” と判断した時だけ canonical を更新
                            // （dict miss や override で勝手に unlink しない）
                            if (touchCanonicalFinal && rFinal != null && rFinal.hit()) {
                                ex.linkCanonical(rFinal.vendorId(), rFinal.productId());
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

    // =========================================================
    // Helpers
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
