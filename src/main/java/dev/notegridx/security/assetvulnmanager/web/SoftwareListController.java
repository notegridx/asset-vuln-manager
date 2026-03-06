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
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
            @RequestParam(name = "unmappedCpe", required = false) Boolean unmappedCpe,
            Model model
    ) {
        int safePage = Math.max(0, page);
        int safeSize = clamp(size, 10, 500);

        // UI から来る q は空文字になりがちなので、Repository 検索用には trim して空なら null
        String keyword = normalizeKeyword(q);

        Pageable pageable = PageRequest.of(safePage, safeSize);
        Page<SoftwareInstall> result =
                softwareInstallRepository.searchPaged(assetId, keyword, unmappedCpe, pageable);

        List<SoftwareInstall> rows = result.getContent();

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

        // --- mapping analysis (per row) ---
        Map<Long, CanonicalCpeLinkingService.Analysis> cpeAnalysisMap = new HashMap<>();
        for (SoftwareInstall si : rows) {
            try {
                cpeAnalysisMap.put(si.getId(), canonicalCpeLinkingService.analyze(si));
            } catch (Exception e) {
                // 画面表示を壊さない（分析だけ落として残りは表示）
                log.warn("Canonical analyze failed: softwareInstallId={} msg={}", si.getId(), e.getMessage());
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
                .filter(id -> id != null)
                .distinct()
                .toList();

        List<Long> productIds = rows.stream()
                .map(SoftwareInstall::getCpeProductId)
                .filter(id -> id != null)
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
        model.addAttribute("unmappedCpe", unmappedCpe);

        // asset dropdown
        model.addAttribute("assets", assetRepository.findAll());

        // counts (optional but useful)
        model.addAttribute("totalInstalls", softwareInstallRepository.count());
        model.addAttribute("unmappedCount", softwareInstallRepository.countUnmappedCpe());

        return "software/list";
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

    private static String firstNonBlank(String a, String b, String fallback) {
        if (a != null && !a.isBlank()) return a;
        if (b != null && !b.isBlank()) return b;
        return fallback;
    }
}