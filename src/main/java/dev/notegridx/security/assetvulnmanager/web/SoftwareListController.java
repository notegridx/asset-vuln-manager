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
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.ArrayList;
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

        Pageable pageable = PageRequest.of(safePage, safeSize);

        List<SoftwareInstall> rows;
        Page<SoftwareInstall> result;

        // Fast path:
        // ALL / LINKED / NOT_LINKED are filtered and paged in DB first.
        if ("ALL".equals(effectiveLinkStatus)) {
            result = softwareInstallRepository.searchPagedBase(assetId, keyword, pageable);
            rows = result.getContent();

        } else if ("LINKED".equals(effectiveLinkStatus)) {
            result = softwareInstallRepository.searchPagedLinked(assetId, keyword, pageable);
            rows = result.getContent();

        } else if ("NOT_LINKED".equals(effectiveLinkStatus)) {
            result = softwareInstallRepository.searchPagedNotLinked(assetId, keyword, pageable);
            rows = result.getContent();

        } else {
            // Fallback path:
            // keep existing in-memory analysis flow for any future non-DB-filterable statuses
            List<SoftwareInstall> baseRows = softwareInstallRepository.searchPagedBase(
                    assetId,
                    keyword,
                    PageRequest.of(0, Integer.MAX_VALUE)
            ).getContent();

            Map<Long, CanonicalCpeLinkingService.Analysis> allAnalysisMap = new HashMap<>();

            for (SoftwareInstall si : baseRows) {
                try {
                    allAnalysisMap.put(si.getId(), canonicalCpeLinkingService.analyze(si));
                } catch (Exception e) {
                    log.warn("Canonical analyze failed: softwareInstallId={} msg={}", si.getId(), e.getMessage());
                }
            }

            List<SoftwareInstall> filteredRows = baseRows.stream()
                    .filter(si -> matchesLinkStatus(allAnalysisMap.get(si.getId()), effectiveLinkStatus))
                    .toList();

            int fromIndex = Math.min((int) pageable.getOffset(), filteredRows.size());
            int toIndex = Math.min(fromIndex + pageable.getPageSize(), filteredRows.size());
            rows = filteredRows.subList(fromIndex, toIndex);
            result = new PageImpl<>(rows, pageable, filteredRows.size());
        }

        List<Long> ids = rows.stream()
                .map(SoftwareInstall::getId)
                .toList();

        // Bulk alert count lookup
        Map<Long, Long> alertCountMap = new HashMap<>();

        if (!ids.isEmpty()) {
            for (Object[] row : alertRepository.countBySoftwareInstallIds(ids)) {
                Long softwareId = (Long) row[0];
                Long count = (Long) row[1];
                alertCountMap.put(softwareId, count);
            }
        }

        model.addAttribute("alertCountMap", alertCountMap);

        // Run canonical analysis only for rows displayed on the current page
        Map<Long, CanonicalCpeLinkingService.Analysis> cpeAnalysisMap = new HashMap<>();

        for (SoftwareInstall si : rows) {
            try {
                CanonicalCpeLinkingService.Analysis a = canonicalCpeLinkingService.analyze(si);

                if (a != null) {
                    cpeAnalysisMap.put(si.getId(), a);
                }

            } catch (Exception e) {
                log.warn("Canonical analyze failed: softwareInstallId={} msg={}", si.getId(), e.getMessage());
            }
        }

        model.addAttribute("cpeAnalysisMap", cpeAnalysisMap);

        // Support legacy template naming
        model.addAttribute("linkAnalysisMap", cpeAnalysisMap);

        // Compute summary statistics for the page
        CanonicalCpeLinkingService.MappingStats pageLinkStats = null;

        try {
            pageLinkStats = canonicalCpeLinkingService.stats(rows);
        } catch (Exception e) {
            log.warn("Canonical stats failed: msg={}", e.getMessage());
        }

        model.addAttribute("pageLinkStats", pageLinkStats);

        // Resolve canonical vendor labels
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
        model.addAttribute("pagerItems", buildPagerItems(result));

        // Preserve filter state
        model.addAttribute("assetId", assetId);
        model.addAttribute("q", q == null ? "" : q);
        model.addAttribute("linkStatus", effectiveLinkStatus);

        // Populate asset dropdown
        model.addAttribute("assets", assetRepository.findAll());

        // Total install count
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

    private static int clamp(int v, int min, int max) {

        if (v < min) return min;
        if (v > max) return max;

        return v;
    }

    private static List<Integer> buildPagerItems(Page<?> page) {
        List<Integer> items = new ArrayList<>();
        int totalPages = page.getTotalPages();
        if (totalPages <= 1) {
            return items;
        }

        int current = page.getNumber();
        int start = Math.max(0, current - 2);
        int end = Math.min(totalPages - 1, current + 2);

        for (int i = start; i <= end; i++) {
            items.add(i);
        }
        return items;
    }

    private static String firstNonBlank(String a, String b, String fallback) {

        if (a != null && !a.isBlank()) return a;
        if (b != null && !b.isBlank()) return b;

        return fallback;
    }
}