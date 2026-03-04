package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
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

    public SoftwareListController(
            SoftwareInstallRepository softwareInstallRepository,
            AssetRepository assetRepository,
            AlertRepository alertRepository,
            CanonicalCpeLinkingService canonicalCpeLinkingService
    ) {
        this.softwareInstallRepository = softwareInstallRepository;
        this.assetRepository = assetRepository;
        this.alertRepository = alertRepository;
        this.canonicalCpeLinkingService = canonicalCpeLinkingService;
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
        // stats() は analyze() を呼ぶので、例外が気になるなら try/catch して null でもOK
        CanonicalCpeLinkingService.MappingStats pageLinkStats = null;
        try {
            pageLinkStats = canonicalCpeLinkingService.stats(rows); // checked/linked/resolvable/needsNorm...
        } catch (Exception e) {
            log.warn("Canonical stats failed: msg={}", e.getMessage());
        }
        model.addAttribute("pageLinkStats", pageLinkStats);

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
}