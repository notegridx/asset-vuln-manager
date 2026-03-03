package dev.notegridx.security.assetvulnmanager.service;

import java.security.MessageDigest;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import dev.notegridx.security.assetvulnmanager.domain.KevSyncState;
import dev.notegridx.security.assetvulnmanager.domain.Vulnerability;
import dev.notegridx.security.assetvulnmanager.infra.kev.CisaKevClient;
import dev.notegridx.security.assetvulnmanager.infra.kev.dto.CisaKevCatalog;
import dev.notegridx.security.assetvulnmanager.repository.KevSyncStateRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityRepository;
import dev.notegridx.security.assetvulnmanager.utility.DbTime;

@Service
public class KevSyncService {

    private static final String FEED_NAME = "cisa-kev";
    private static final String SOURCE_NVD = "NVD";

    private final CisaKevClient client;
    private final ObjectMapper objectMapper;
    private final KevSyncStateRepository stateRepo;
    private final VulnerabilityRepository vulnRepo;

    public KevSyncService(
            CisaKevClient client,
            ObjectMapper objectMapper,
            KevSyncStateRepository stateRepo,
            VulnerabilityRepository vulnRepo
    ) {
        this.client = client;
        this.objectMapper = objectMapper;
        this.stateRepo = stateRepo;
        this.vulnRepo = vulnRepo;
    }

    public record SyncResult(
            boolean skippedNotModified,
            int catalogEntries,
            int processedEntries,
            int updatedVulns,
            int missingInDb,
            String bodySha256
    ) {}

    @Transactional
    public SyncResult sync(boolean force, int maxItems) {

        int safeMax = Math.max(1, Math.min(maxItems, 50_000)); // KEV全件でも安全に
        LocalDateTime now = DbTime.now();

        KevSyncState state = stateRepo.findByFeedName(FEED_NAME)
                .orElseGet(() -> stateRepo.save(KevSyncState.of(FEED_NAME)));

        String ifNoneMatch = force ? null : state.getEtag();
        String ifModifiedSince = force ? null : state.getLastModified();

        CisaKevClient.FetchResult fetched;
        try {
            fetched = client.fetch(ifNoneMatch, ifModifiedSince);
        } catch (Exception e) {
            throw new IllegalStateException("KEV fetch failed: " + e.getMessage(), e);
        }

        if (!force && fetched.notModified()) {
            return new SyncResult(true, 0, 0, 0, 0, state.getBodySha256());
        }
        if (!fetched.ok() || fetched.body() == null) {
            throw new IllegalStateException("KEV fetch failed: status=" + fetched.statusCode());
        }

        String sha256 = sha256Hex(fetched.body());
        Long size = (long) fetched.body().length;

        // parse
        CisaKevCatalog catalog;
        try {
            catalog = objectMapper.readValue(fetched.body(), CisaKevCatalog.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid KEV JSON: " + e.getMessage(), e);
        }

        List<CisaKevCatalog.KevItem> items = (catalog.vulnerabilities == null) ? List.of() : catalog.vulnerabilities;
        int total = items.size();

        // apply max cap
        List<CisaKevCatalog.KevItem> slice = items.stream().limit(safeMax).toList();

        // build CVE list
        List<String> cveIds = slice.stream()
                .map(i -> normalize(i == null ? null : i.cveID))
                .filter(Objects::nonNull)
                .distinct()
                .toList();

        // batch fetch vulnerabilities from DB
        Map<String, Vulnerability> byCve = fetchVulnsByCveIds(cveIds);

        int updated = 0;
        int missing = 0;

        for (CisaKevCatalog.KevItem it : slice) {
            if (it == null) continue;
            String cve = normalize(it.cveID);
            if (cve == null) continue;

            Vulnerability v = byCve.get(cve);
            if (v == null) {
                missing++;
                continue;
            }

            LocalDate dateAdded = parseDate(it.dateAdded);
            LocalDate dueDate = parseDate(it.dueDate);
            String ransomware = normalize(it.knownRansomwareCampaignUse);

            v.applyKevDetails(dateAdded, dueDate, ransomware);
            vulnRepo.save(v);
            updated++;
        }

        // update sync state meta
        state.updateMeta(fetched.etag(), fetched.lastModified(), sha256, size, now);
        stateRepo.save(state);

        return new SyncResult(false, total, updated, missing, slice.size(), sha256);
    }

    /**
     * 既存Repositoryに依存せず、まずは findBySourceAndExternalId を使う素朴実装ではなく、
     * “IN句でまとめて引く”前提のメソッドを Repository に足すのが理想。
     *
     * ここでは「VulnerabilityRepositoryに findBySourceAndExternalIdIn(...) がある」想定で呼び出す。
     * 無ければ追加してください（下に完全版を添付）。
     */
    private Map<String, Vulnerability> fetchVulnsByCveIds(List<String> cveIds) {
        if (cveIds == null || cveIds.isEmpty()) return new HashMap<>();

        // NOTE: Repository method to add:
        // List<Vulnerability> findBySourceAndExternalIdIn(String source, Collection<String> ids);

        List<Vulnerability> list = vulnRepo.findBySourceAndExternalIdIn(SOURCE_NVD, cveIds);
        Map<String, Vulnerability> m = new HashMap<>(list.size() * 2);
        for (Vulnerability v : list) {
            if (v == null) continue;
            String k = normalize(v.getExternalId());
            if (k != null) m.put(k, v);
        }
        return m;
    }

    private static String normalize(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static LocalDate parseDate(String s) {
        String v = normalize(s);
        if (v == null) return null;
        try {
            return LocalDate.parse(v); // yyyy-MM-dd
        } catch (Exception e) {
            return null;
        }
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest(bytes);
            StringBuilder sb = new StringBuilder(dig.length * 2);
            for (byte b : dig) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("sha256 failed: " + e.getMessage(), e);
        }
    }
}