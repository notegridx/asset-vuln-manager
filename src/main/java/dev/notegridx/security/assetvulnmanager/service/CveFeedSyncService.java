package dev.notegridx.security.assetvulnmanager.service;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import dev.notegridx.security.assetvulnmanager.domain.Vulnerability;
import dev.notegridx.security.assetvulnmanager.domain.VulnerabilityAffectedCpe;
import dev.notegridx.security.assetvulnmanager.infra.nvd.CpeNameParser;
import dev.notegridx.security.assetvulnmanager.infra.nvd.NvdClient;
import dev.notegridx.security.assetvulnmanager.infra.nvd.NvdCveFeedClient; // ★ FeedKind の型
import dev.notegridx.security.assetvulnmanager.infra.nvd.dto.NvdCveResponse;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityAffectedCpeRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityRepository;

/**
 * CVE sync:
 * - 互換のため AdminCveController が呼ぶ sync(FeedKind, force, maxItems) を提供する
 * - 実処理は NvdImportService に寄せる
 */
@Service
public class CveFeedSyncService {

    private static final Logger log = LoggerFactory.getLogger(CveFeedSyncService.class);

    private final NvdClient nvdClient;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final VulnerabilityAffectedCpeRepository affectedCpeRepository;

    private final CpeNameParser cpeNameParser;
    private final VendorProductNormalizer normalizer;
    private final CpeVendorRepository cpeVendorRepository;
    private final CpeProductRepository cpeProductRepository;

    private final NvdImportService nvdImportService;

    public CveFeedSyncService(
            NvdClient nvdClient,
            VulnerabilityRepository vulnerabilityRepository,
            VulnerabilityAffectedCpeRepository affectedCpeRepository,
            CpeNameParser cpeNameParser,
            VendorProductNormalizer normalizer,
            CpeVendorRepository cpeVendorRepository,
            CpeProductRepository cpeProductRepository,
            NvdImportService nvdImportService
    ) {
        this.nvdClient = nvdClient;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.affectedCpeRepository = affectedCpeRepository;
        this.cpeNameParser = cpeNameParser;
        this.normalizer = normalizer;
        this.cpeVendorRepository = cpeVendorRepository;
        this.cpeProductRepository = cpeProductRepository;
        this.nvdImportService = nvdImportService;
    }

    /**
     * ★互換メソッド★
     * AdminCveController が呼んでいるシグネチャを復活させる。
     *
     * NOTE:
     * - “feed kind” によって同期範囲を切り替える（最小限の実装）
     * - force の扱いは、現状の importFromNvd が「lastModified範囲で取得」前提なので
     *   ここでは範囲を広げる方向で吸収する（必要なら cve_sync_state と連携して最適化）
     */
    @Transactional
    public SyncResult sync(NvdCveFeedClient.FeedKind kind, boolean force, int maxItems) {
        // いまの実装は NVD API の lastModifiedRange を使うので、FeedKind を “範囲” に変換する
        // RECENT: 直近（例: 8日）
        // MODIFIED: 直近（例: 8日）だが force=true なら広げる（例: 30日）
        OffsetDateTime end = OffsetDateTime.now();
        OffsetDateTime start = defaultStartFor(kind, force, end);

        int safeMax = Math.max(1, Math.min(maxItems, 2000)); // NVD API運用の安全側
        log.info("CVE sync: kind={}, force={}, range={}..{}, maxItems={}", kind, force, start, end, safeMax);

        var r = nvdImportService.importFromNvd(start, end, safeMax);
        return new SyncResult(r.vulnerabilitiesUpserted(), r.affectedCpesInserted(), r.fetched());
    }

    private static OffsetDateTime defaultStartFor(NvdCveFeedClient.FeedKind kind, boolean force, OffsetDateTime end) {
        // enum名が RECENT/MODIFIED 以外でも落ちないように name() ベースで吸収
        String k = (kind == null) ? "" : kind.name().toUpperCase();

        // “最近”の既定幅（NVDのRECENTが「8日」運用であることが多いので 8日を既定に）
        // ※ここはあなたの運用に合わせて調整してください
        int daysRecent = 8;

        if (k.contains("RECENT")) {
            return end.minusDays(daysRecent);
        }

        if (k.contains("MODIFIED")) {
            // MODIFIED は通常も recent幅でOKだが、force なら広げる（取りこぼし救済）
            return force ? end.minusDays(30) : end.minusDays(daysRecent);
        }

        // 不明なFeedKindは安全側（recent幅）
        return end.minusDays(daysRecent);
    }

    // ---- 既存：lastModifiedRange を明示的に指定して同期したい場合 ----
    @Transactional
    public SyncResult syncByLastModifiedRange(OffsetDateTime start, OffsetDateTime end, int maxResults) {
        var r = nvdImportService.importFromNvd(start, end, maxResults);
        return new SyncResult(r.vulnerabilitiesUpserted(), r.affectedCpesInserted(), r.fetched());
    }

    // ---- 既存：もし旧ロジックが残っている場合の直接同期（残してもOK）----
    @Transactional
    public SyncResult syncDirect(OffsetDateTime start, OffsetDateTime end, int maxResults) {

        List<NvdCveResponse.VulnerabilityItem> items =
                nvdClient.fetchByLastModifiedRange(start, end, Math.max(1, Math.min(maxResults, 2000)));

        int vulnUpserted = 0;
        int affectedInserted = 0;

        for (var item : items) {
            if (item == null || item.cve() == null) continue;

            String cveId = norm(item.cve().id());
            if (cveId == null) continue;

            Vulnerability v = vulnerabilityRepository.findBySourceAndExternalId("NVD", cveId)
                    .orElseGet(() -> new Vulnerability("NVD", cveId));

            vulnerabilityRepository.save(v);
            vulnUpserted++;

            var configs = item.cve().configurations();
            if (configs == null) continue;

            for (var cfg : configs) {
                if (cfg == null || cfg.nodes() == null) continue;
                for (var node : cfg.nodes()) {
                    affectedInserted += collectAndSaveAffected(v, node);
                }
            }
        }

        return new SyncResult(vulnUpserted, affectedInserted, items.size());
    }

    private int collectAndSaveAffected(Vulnerability v, NvdCveResponse.Node node) {
        if (node == null) return 0;
        int inserted = 0;

        if (node.cpeMatch() != null) {
            for (var m : node.cpeMatch()) {
                if (m == null) continue;
                if (Boolean.FALSE.equals(m.vulnerable())) continue;

                String criteria = norm(m.criteria());
                if (criteria == null || !criteria.startsWith("cpe:2.3:")) continue;

                Long vendorId = null;
                Long productId = null;
                String vendorNorm = null;
                String productNorm = null;

                var vpOpt = cpeNameParser.parseVendorProduct(criteria);
                if (vpOpt.isPresent()) {
                    var vp = vpOpt.get();
                    vendorNorm = normalizer.normalizeVendor(vp.vendor());
                    productNorm = normalizer.normalizeProduct(vp.product());

                    if (vendorNorm != null && productNorm != null) {
                        vendorId = cpeVendorRepository.findByNameNorm(vendorNorm).map(x -> x.getId()).orElse(null);
                        if (vendorId != null) {
                            productId = cpeProductRepository.findByVendorIdAndNameNorm(vendorId, productNorm)
                                    .map(x -> x.getId()).orElse(null);
                        }
                    }
                }

                VulnerabilityAffectedCpe vac = new VulnerabilityAffectedCpe(
                        v,
                        criteria,
                        vendorId,
                        productId,
                        vendorNorm,
                        productNorm,
                        norm(m.versionStartIncluding()),
                        norm(m.versionStartExcluding()),
                        norm(m.versionEndIncluding()),
                        norm(m.versionEndExcluding())
                );

                try {
                    affectedCpeRepository.save(vac);
                    inserted++;
                } catch (DataIntegrityViolationException e) {
                    log.debug("VAC duplicate ignored: vulnId={}, criteria={}", v.getId(), criteria);
                }
            }
        }

        if (node.children() != null) {
            for (var c : node.children()) {
                inserted += collectAndSaveAffected(v, c);
            }
        }

        return inserted;
    }

    private static String norm(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    public record SyncResult(int vulnerabilitiesUpserted, int affectedCpesInserted, int fetched) {}
}