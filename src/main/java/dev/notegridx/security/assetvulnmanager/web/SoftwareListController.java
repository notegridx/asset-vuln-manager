package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.service.CanonicalCpeLinkingService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Slf4j
@Controller
public class SoftwareListController {

    private final SoftwareInstallRepository softwareInstallRepository;
    private final AssetRepository assetRepository;
    private final AlertRepository alertRepository;
    private final CanonicalCpeLinkingService canonicalCpeLinkingService;
    private final CpeVendorRepository cpeVendorRepository;
    private final CpeProductRepository cpeProductRepository;

    public SoftwareListController(
            SoftwareInstallRepository softwareInstallRepository,
            AssetRepository assetRepository,
            AlertRepository alertRepository,
            CanonicalCpeLinkingService canonicalCpeLinkingService,
            CpeVendorRepository cpeVendorRepository,
            CpeProductRepository cpeProductRepository
    ) {
        this.softwareInstallRepository = softwareInstallRepository;
        this.assetRepository = assetRepository;
        this.alertRepository = alertRepository;
        this.canonicalCpeLinkingService = canonicalCpeLinkingService;
        this.cpeVendorRepository = cpeVendorRepository;
        this.cpeProductRepository = cpeProductRepository;
    }

    @GetMapping("/software")
    public String list(
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "100") int size,
            @RequestParam(name = "assetId", required = false) Long assetId,
            @RequestParam(name = "q", required = false) String q,
            @RequestParam(name = "linkStatus", required = false) String linkStatus,
            Model model
    ) {
        int safePage = Math.max(0, page);
        int safeSize = clamp(size, 10, 500);

        String keyword = normalizeKeyword(q);
        String effectiveLinkStatus = normalizeLinkStatus(linkStatus);

        // Exact filter for LINKED / NOT_LINKED:
        // base filter -> analyze -> linkStatus filter -> manual paging
        List<SoftwareInstall> baseRows = softwareInstallRepository.findAll(Sort.by(Sort.Direction.DESC, "id"))
                .stream()
                .filter(s -> assetId == null || (s.getAsset() != null && Objects.equals(s.getAsset().getId(), assetId)))
                .filter(s -> keyword == null || containsKeyword(s, keyword))
                .toList();

        Map<Long, CanonicalCpeLinkingService.Analysis> allAnalysisMap = new HashMap<>();
        for (SoftwareInstall si : baseRows) {
            try {
                allAnalysisMap.put(si.getId(), canonicalCpeLinkingService.analyze(si));
            } catch (Exception e) {
                // 画面表示を壊さない（分析だけ落として残りは表示）
                log.warn("Canonical analyze failed: softwareInstallId={} msg={}", si.getId(), e.getMessage());
            }
        }

        List<SoftwareInstall> filteredRows = baseRows.stream()
                .filter(si -> matchesLinkStatus(allAnalysisMap.get(si.getId()), effectiveLinkStatus))
                .toList();

        Pageable pageable = PageRequest.of(safePage, safeSize);
        int fromIndex = Math.min((int) pageable.getOffset(), filteredRows.size());
        int toIndex = Math.min(fromIndex + pageable.getPageSize(), filteredRows.size());
        List<SoftwareInstall> rows = filteredRows.subList(fromIndex, toIndex);
        Page<SoftwareInstall> result = new PageImpl<>(rows, pageable, filteredRows.size());

        List<Long> ids = rows.stream()
                .map(SoftwareInstall::getId)
                .toList();

        // --- alerts count (bulk) ---
        Map<Long, Long> alertCountMap = new HashMap<>();
        if (!ids.isEmpty()) {
            for (Object[] row : alertRepository.countBySoftwareInstallIds(ids)) {
                Long softwareId = (Long) row[0];
                Long count = (Long) row[1];
                alertCountMap.put(softwareId, count);
            }
        }
        model.addAttribute("alertCountMap", alertCountMap);

        // --- mapping analysis (page rows only) ---
        Map<Long, CanonicalCpeLinkingService.Analysis> cpeAnalysisMap = new HashMap<>();
        for (SoftwareInstall si : rows) {
            CanonicalCpeLinkingService.Analysis a = allAnalysisMap.get(si.getId());
            if (a != null) {
                cpeAnalysisMap.put(si.getId(), a);
            }
        }
        model.addAttribute("cpeAnalysisMap", cpeAnalysisMap);

        // テンプレの呼び名揺れ対策（どちらでも参照できるように同じMapを載せる）
        model.addAttribute("linkAnalysisMap", cpeAnalysisMap);

        // --- page summary stats (based on analyze()) ---
        CanonicalCpeLinkingService.MappingStats pageLinkStats = null;
        try {
            pageLinkStats = canonicalCpeLinkingService.stats(rows);
        } catch (Exception e) {
            log.warn("Canonical stats failed: msg={}", e.getMessage());
        }
        model.addAttribute("pageLinkStats", pageLinkStats);

        // --- canonical vendor/product label maps ---
        List<Long> vendorIds = rows.stream()
                .map(SoftwareInstall::getCpeVendorId)
                .filter(Objects::nonNull)
                .distinct()
                .toList();

        List<Long> productIds = rows.stream()
                .map(SoftwareInstall::getCpeProductId)
                .filter(Objects::nonNull)
                .distinct()
                .toList();

        Map<Long, String> vendorNameMap = new HashMap<>();
        for (CpeVendor v : cpeVendorRepository.findAllById(vendorIds)) {
            String label = firstNonBlank(v.getDisplayName(), v.getNameNorm(), "#" + v.getId());
            vendorNameMap.put(v.getId(), label);
        }

        Map<Long, String> productNameMap = new HashMap<>();
        for (CpeProduct p : cpeProductRepository.findAllById(productIds)) {
            String label = firstNonBlank(p.getDisplayName(), p.getNameNorm(), "#" + p.getId());
            productNameMap.put(p.getId(), label);
        }

        model.addAttribute("vendorNameMap", vendorNameMap);
        model.addAttribute("productNameMap", productNameMap);

        model.addAttribute("page", result);

        // filter state（画面にエコーするのは元のq）
        model.addAttribute("assetId", assetId);
        model.addAttribute("q", q == null ? "" : q);
        model.addAttribute("linkStatus", effectiveLinkStatus);

        // asset dropdown
        model.addAttribute("assets", assetRepository.findAll());

        // counts
        model.addAttribute("totalInstalls", softwareInstallRepository.count());

        return "software/list";
    }

    private static boolean matchesLinkStatus(CanonicalCpeLinkingService.Analysis a, String linkStatus) {
        if ("ALL".equals(linkStatus)) {
            return true;
        }
        if (a == null) {
            return false;
        }

        boolean linked =
                a.result() != null
                        && (a.result() == CanonicalCpeLinkingService.ItemResult.LINKED
                        || a.result() == CanonicalCpeLinkingService.ItemResult.STALE)
                        && a.resolve() != null
                        && a.resolve().hit();

        return switch (linkStatus) {
            case "LINKED" -> linked;
            case "NOT_LINKED" -> !linked;
            default -> true;
        };
    }

    private static String normalizeLinkStatus(String linkStatus) {
        if (linkStatus == null) return "ALL";
        String t = linkStatus.trim().toUpperCase();
        if (t.isEmpty()) return "ALL";
        if ("LINKED".equals(t)) return "LINKED";
        if ("NOT_LINKED".equals(t)) return "NOT_LINKED";
        return "ALL";
    }

    private static String normalizeKeyword(String q) {
        if (q == null) return null;
        String t = q.trim();
        return t.isEmpty() ? null : t;
    }

    private static boolean containsKeyword(SoftwareInstall s, String keyword) {
        String q = keyword.toLowerCase();

        return contains(s.getVendorRaw(), q)
                || contains(s.getVendor(), q)
                || contains(s.getNormalizedVendor(), q)
                || contains(s.getProductRaw(), q)
                || contains(s.getProduct(), q)
                || contains(s.getNormalizedProduct(), q)
                || contains(s.getVersionRaw(), q)
                || contains(s.getVersion(), q);
    }

    private static boolean contains(String value, String keywordLower) {
        return value != null && value.toLowerCase().contains(keywordLower);
    }

    private static int clamp(int v, int min, int max) {
        if (v < min) return min;
        if (v > max) return max;
        return v;
    }

    private static String firstNonBlank(String a, String b, String fallback) {
        if (a != null && !a.isBlank()) return a;
        if (b != null && !b.isBlank()) return b;
        return fallback;
    }
}