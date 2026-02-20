package dev.notegridx.security.assetvulnmanager.service;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

import dev.notegridx.security.assetvulnmanager.domain.CveSyncState;
import dev.notegridx.security.assetvulnmanager.domain.Vulnerability;
import dev.notegridx.security.assetvulnmanager.domain.VulnerabilityAffectedCpe;
import dev.notegridx.security.assetvulnmanager.infra.nvd.CveFeedMetaParser;
import dev.notegridx.security.assetvulnmanager.infra.nvd.NvdCveFeedClient;
import dev.notegridx.security.assetvulnmanager.repository.CveSyncStateRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityAffectedCpeRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityRepository;

import jakarta.persistence.EntityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * CVE feed sync for NVD JSON 2.0 feeds (modified/recent).
 *
 * Strategy:
 * - fetch meta
 * - compare with cve_sync_state
 * - if changed (or force), download json.gz to temp file
 * - stream-parse JSON and upsert vulnerabilities + affected cpes
 * - update sync_state
 */
@Service
public class CveFeedSyncService {

    private static final Logger log = LoggerFactory.getLogger(CveFeedSyncService.class);

    private static final String SOURCE = "NVD";

    // tuning
    private static final int LOG_EVERY = 5_000;
    private static final int FLUSH_EVERY = 2_000;

    private final NvdCveFeedClient feedClient;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final VulnerabilityAffectedCpeRepository affectedCpeRepository;
    private final CveSyncStateRepository syncStateRepository;
    private final EntityManager em;

    private final TransactionTemplate chunkTx;
    private final CveFeedMetaParser metaParser = new CveFeedMetaParser();

    // prevent JsonParser.close() from closing underlying streams, if you ever wrap layered streams
    private final JsonFactory jsonFactory;

    public CveFeedSyncService(
            NvdCveFeedClient feedClient,
            VulnerabilityRepository vulnerabilityRepository,
            VulnerabilityAffectedCpeRepository affectedCpeRepository,
            CveSyncStateRepository syncStateRepository,
            EntityManager em,
            PlatformTransactionManager txManager
    ) {
        this.feedClient = feedClient;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.affectedCpeRepository = affectedCpeRepository;
        this.syncStateRepository = syncStateRepository;
        this.em = em;

        TransactionTemplate tt = new TransactionTemplate(txManager);
        tt.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.chunkTx = tt;

        this.jsonFactory = new JsonFactory();
        // (optional) jsonFactory.disable(JsonParser.Feature.AUTO_CLOSE_SOURCE);
    }

    public SyncResult sync(NvdCveFeedClient.FeedKind kind, boolean force, int maxItems) throws IOException {
        int safeMax = clamp(maxItems, 1, 5_000_000);
        LocalDateTime now = LocalDateTime.now();

        String feedName = "nvd-cve-2.0-" + kind.name().toLowerCase();

        // 1) META
        CveFeedMetaParser.FeedMeta meta = feedClient.fetchMeta(kind, metaParser);

        // 2) compare
        CveSyncState state = syncStateRepository.findByFeedName(feedName)
                .orElseGet(() -> new CveSyncState(feedName));

        boolean same = state.isSameMeta(meta.sha256(), meta.lastModified(), meta.size());
        if (!force && same) {
            log.info("CVE feed sync skipped (meta unchanged). feedName={}, sha256={}, lastModified={}, size={}",
                    feedName, meta.sha256(), meta.lastModified(), meta.size());
            return SyncResult.skipped(meta.sha256(), meta.lastModified(), meta.size());
        }

        // 3) download json.gz -> temp
        Path tmp = null;
        try {
            tmp = feedClient.downloadJsonGzToTempFile(kind);
            long bytes = Files.size(tmp);
            log.info("CVE feed downloaded: kind={}, file={}, bytes={}, force={}, cap={}", kind, tmp, bytes, force, safeMax);

            // 4) parse + upsert
            ParseResult r;
            try (InputStream fin = Files.newInputStream(tmp);
                 GZIPInputStream gin = new GZIPInputStream(fin)) {

                r = parseAndUpsert(gin, safeMax);
            }

            // 5) update state
            state.updateMeta(meta.sha256(), meta.lastModified(), meta.size(), now);
            syncStateRepository.save(state);

            log.info("CVE feed sync done: kind={}, parsed={}, vulnUpserted={}, affectedInserted={}",
                    kind, r.parsed, r.vulnUpserted, r.affectedInserted);

            return SyncResult.executed(r.vulnUpserted, r.affectedInserted, r.parsed,
                    meta.sha256(), meta.lastModified(), meta.size());

        } finally {
            if (tmp != null) {
                try { Files.deleteIfExists(tmp); } catch (Exception ignore) {}
            }
        }
    }

    private ParseResult parseAndUpsert(InputStream jsonStream, int maxItems) throws IOException {
        int parsed = 0;
        int vulnUpserted = 0;
        int affectedInserted = 0;

        // NOTE: this is a skeleton. We parse streaming and:
        // - pick cve.id
        // - pick description (en)
        // - pick cvss v31/v30 baseScore + version
        // - pick published/lastModified
        // - extract vulnerable cpeMatch.criteria
        //
        // Implementation detail: The feed JSON structure includes nested objects/arrays.
        // In production, you'd implement robust token navigation.
        try (JsonParser p = jsonFactory.createParser(jsonStream)) {

            // very lightweight state machine (best-effort skeleton)
            String currentCveId = null;
            String descEn = null;
            String published = null;
            String lastModified = null;
            String cvssVersion = null;
            java.math.BigDecimal cvssScore = null;
            Set<String> cpes = new LinkedHashSet<>();

            while (p.nextToken() != null) {
                JsonToken t = p.currentToken();

                if (t == JsonToken.FIELD_NAME) {
                    String field = p.currentName();
                    JsonToken v = p.nextToken();

                    // ---- CVE id ----
                    if ("id".equals(field) && v == JsonToken.VALUE_STRING) {
                        // This "id" may appear in many places; in a full implementation
                        // you should confirm path. For skeleton we accept first seen while inside a CVE block.
                        String id = normalize(p.getValueAsString());
                        if (id != null && id.startsWith("CVE-")) {
                            currentCveId = id;
                        }
                    }

                    // ---- description ----
                    // Feed has descriptions[] with lang/value. Skeleton: if we see "lang":"en" then next "value".
                    if ("published".equals(field) && v == JsonToken.VALUE_STRING) {
                        published = p.getValueAsString();
                    }
                    if ("lastModified".equals(field) && v == JsonToken.VALUE_STRING) {
                        lastModified = p.getValueAsString();
                    }

                    if ("lang".equals(field) && v == JsonToken.VALUE_STRING) {
                        String lang = p.getValueAsString();
                        // naive: if "en", try to find a nearby "value"
                        if ("en".equalsIgnoreCase(lang)) {
                            // look ahead a bit (best-effort)
                            String maybeValue = tryFindNextValueField(p, 32);
                            if (maybeValue != null) descEn = maybeValue;
                        }
                    }

                    // ---- CVSS baseScore + version (best-effort) ----
                    if ("baseScore".equals(field) && (v == JsonToken.VALUE_NUMBER_FLOAT || v == JsonToken.VALUE_NUMBER_INT)) {
                        try {
                            cvssScore = p.getDecimalValue();
                        } catch (Exception ignore) {}
                    }
                    if ("version".equals(field) && v == JsonToken.VALUE_STRING) {
                        String ver = normalize(p.getValueAsString());
                        if (ver != null && (ver.startsWith("3.") || ver.startsWith("2.") || ver.startsWith("4."))) {
                            cvssVersion = ver;
                        }
                    }

                    // ---- affected CPE ----
                    // In NVD JSON, vulnerable CPE criteria often appears under configurations nodes cpeMatch criteria.
                    if ("criteria".equals(field) && v == JsonToken.VALUE_STRING) {
                        String cpe = normalize(p.getValueAsString());
                        if (cpe != null && cpe.startsWith("cpe:2.3:")) {
                            // in full impl: also check vulnerable==true for this cpeMatch
                            cpes.add(cpe);
                        }
                    }

                    // ---- crude boundary detection ----
                    // When we detect end of one CVE item, we should flush.
                    // Proper detection requires path-based parsing (e.g., on END_OBJECT at correct depth).
                    // Skeleton trigger: when we see field "cve" start object? (not implemented)
                }

                // Skeleton flush heuristic:
                // If we have a CVE id and have collected some data, and we hit END_OBJECT at depth ~??,
                // we'd flush. Here we provide a very conservative approach:
                // When cpes grows beyond threshold OR parsed count is close to max, we may flush on END_ARRAY etc.
                // For a real impl, replace this with path-aware flush.
                if (currentCveId != null && !cpes.isEmpty() && parsed < maxItems && parsed % 200 == 0) {
                    // no-op
                }

                // In a real implementation, you would flush when finishing each CVE item.
                // This skeleton instead flushes ONLY when it seems "complete enough" and sees next CVE id.
                // (Implemented by looking for another CVE id; handled above by overwriting currentCveId.)
                //
                // For skeleton completeness, we won't actually persist until we detect at least an END_OBJECT
                // AND currentCveId is set; a placeholder approach is to persist at END_OBJECT when currentCveId exists.
                if (t == JsonToken.END_OBJECT && currentCveId != null) {
                    // persist one CVE (best-effort)
                    final String cveIdFinal = currentCveId;
                    final String descFinal = descEn;
                    final String cvssVerFinal = cvssVersion;
                    final java.math.BigDecimal cvssScoreFinal = cvssScore;
                    final LocalDateTime pubFinal = parseNvdDateTime(published);
                    final LocalDateTime lastModFinal = parseNvdDateTime(lastModified);
                    final Set<String> cpesFinal = new LinkedHashSet<>(cpes);

                    // reset accumulators for next item
                    currentCveId = null;
                    descEn = null;
                    published = null;
                    lastModified = null;
                    cvssVersion = null;
                    cvssScore = null;
                    cpes.clear();

                    parsed++;
                    if (parsed > maxItems) break;

                    // per-item tx (safe)
                    ParseDelta d = chunkTx.execute(status -> upsertOne(cveIdFinal, descFinal, cvssVerFinal, cvssScoreFinal, pubFinal, lastModFinal, cpesFinal));
                    if (d != null) {
                        vulnUpserted += d.vulnUpserted;
                        affectedInserted += d.affectedInserted;
                    }

                    if (parsed % LOG_EVERY == 0) {
                        log.info("CVE feed progress: parsed={}, vulnUpserted={}, affectedInserted={}",
                                parsed, vulnUpserted, affectedInserted);
                    }

//                    if (parsed % FLUSH_EVERY == 0) {
//                        em.flush();
//                        em.clear();
//                    }
                }
            }
        }

//        em.flush();
//        em.clear();

        return new ParseResult(parsed, vulnUpserted, affectedInserted);
    }

    private ParseDelta upsertOne(
            String cveId,
            String description,
            String cvssVersion,
            java.math.BigDecimal cvssScore,
            LocalDateTime publishedAt,
            LocalDateTime lastModifiedAt,
            Set<String> cpes
    ) {
        if (cveId == null) return new ParseDelta(0, 0);

        Vulnerability v = vulnerabilityRepository.findBySourceAndExternalId(SOURCE, cveId)
                .orElseGet(() -> new Vulnerability(SOURCE, cveId));

        v.applyNvdDetails(
                null,
                description,
                cvssVersion,
                cvssScore,
                publishedAt,
                lastModifiedAt
        );

        vulnerabilityRepository.save(v);

        int affectedInserted = 0;
        if (cpes != null) {
            for (String cpe : cpes) {
                if (cpe == null || !cpe.startsWith("cpe:2.3:")) continue;

                boolean exists;
                try {
                    exists = affectedCpeRepository.existsByVulnerabilityIdAndCpeName(v.getId(), cpe);
                } catch (Exception ignore) {
                    exists = false;
                }
                if (exists) continue;

                try {
                    affectedCpeRepository.save(new VulnerabilityAffectedCpe(v, cpe));
                    affectedInserted++;
                } catch (DataIntegrityViolationException dup) {
                    // ignore
                }
            }
        }

        return new ParseDelta(1, affectedInserted);
    }

    private static String tryFindNextValueField(JsonParser p, int maxSteps) throws IOException {
        // best-effort lookahead within bounds. Do not rely on this for correctness.
        for (int i = 0; i < maxSteps; i++) {
            JsonToken t = p.nextToken();
            if (t == null) return null;
            if (t == JsonToken.FIELD_NAME && "value".equals(p.currentName())) {
                JsonToken v = p.nextToken();
                if (v == JsonToken.VALUE_STRING) {
                    return normalize(p.getValueAsString());
                }
            }
        }
        return null;
    }

    private static LocalDateTime parseNvdDateTime(String s) {
        String v = normalize(s);
        if (v == null) return null;
        try {
            return OffsetDateTime.parse(v).toLocalDateTime();
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static String normalize(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static int clamp(int v, int min, int max) {
        if (v < min) return min;
        if (v > max) return max;
        return v;
    }

    private record ParseResult(int parsed, int vulnUpserted, int affectedInserted) {}
    private record ParseDelta(int vulnUpserted, int affectedInserted) {}

    public record SyncResult(
            boolean skipped,
            int vulnerabilitiesUpserted,
            int affectedCpesInserted,
            int parsed,
            String metaSha256,
            String metaLastModified,
            Long metaSize
    ) {
        public static SyncResult skipped(String sha256, String lastModified, Long size) {
            return new SyncResult(true, 0, 0, 0, sha256, lastModified, size);
        }

        public static SyncResult executed(int vUp, int aIns, int parsed, String sha256, String lastModified, Long size) {
            return new SyncResult(false, vUp, aIns, parsed, sha256, lastModified, size);
        }
    }
}