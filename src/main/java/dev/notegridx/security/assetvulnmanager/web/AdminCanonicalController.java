package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.service.CanonicalCpeLinkingService;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;
import java.util.Objects;

@Controller
public class AdminCanonicalController {

    private final AssetRepository assetRepo;
    private final SoftwareInstallRepository softwareRepo;
    private final CanonicalCpeLinkingService linker;

    public AdminCanonicalController(
            AssetRepository assetRepo,
            SoftwareInstallRepository softwareRepo,
            CanonicalCpeLinkingService linker
    ) {
        this.assetRepo = assetRepo;
        this.softwareRepo = softwareRepo;
        this.linker = linker;
    }

    public enum Filter {
        all,

        // SQL link (IDs)
        vendorLinked,
        vendorOnlyLinked,
        fullyLinked,

        // Fully linked quality
        linkedValid,
        linkedStale,

        // Dictionary
        resolvable,
        unresolvable,

        // Other
        needsNormalization;

        static Filter parse(String s) {
            if (s == null || s.isBlank()) return all;
            try {
                return Filter.valueOf(s.trim());
            } catch (Exception e) {
                return all;
            }
        }
    }

    @GetMapping("/admin/canonical")
    public String view(
            @RequestParam(name = "asset", required = false) Long assetId,
            @RequestParam(name = "filter", required = false, defaultValue = "all") String filterRaw,
            @RequestParam(name = "q", required = false) String q,
            @RequestParam(name = "limit", required = false, defaultValue = "200") Integer limit,
            Model model
    ) {
        int safeLimit = clamp(limit == null ? 200 : limit, 1, 2000);
        Filter filter = Filter.parse(filterRaw);
        String keyword = normalizeKeyword(q);

        // (optional) asset dropdownに使うなら
        List<Asset> assets = assetRepo.findAll(Sort.by(Sort.Direction.ASC, "id"));
        model.addAttribute("assets", assets);

        // Base selection (asset + keyword, before filter)
        List<SoftwareInstall> base = softwareRepo.findAll(Sort.by(Sort.Direction.DESC, "id")).stream()
                .filter(s -> assetId == null || (s.getAsset() != null && Objects.equals(s.getAsset().getId(), assetId)))
                .filter(s -> keyword == null || containsKeyword(s, keyword))
                .limit(safeLimit)
                .toList();

        // Stats: “after asset/keyword filter, before filter selection” (あなたの HTML の説明文と一致)
        var stats = linker.stats(base);
        model.addAttribute("stats", stats);

        // Analyze rows
        List<Row> analyzed = base.stream()
                .map(s -> Row.from(s, linker.analyze(s)))
                .toList();

        // Apply filter
        List<Row> rows = analyzed.stream()
                .filter(r -> matchesFilter(r, filter))
                .toList();

        model.addAttribute("rows", rows);

        // Echo states (HTMLのnameと合わせる)
        model.addAttribute("asset", assetId);
        model.addAttribute("filter", filter.name());
        model.addAttribute("q", q);
        model.addAttribute("limit", safeLimit);

        return "admin/canonical";
    }

    private static boolean matchesFilter(Row r, Filter f) {
        var a = r.analysis;
        return switch (f) {
            case all -> true;

            // SQL link (IDs)
            case vendorLinked -> a.vendorLinkedSql();
            case vendorOnlyLinked -> a.vendorLinkedSql() && !a.productLinkedSql();
            case fullyLinked -> a.fullyLinkedSql();

            // Fully linked quality
            case linkedValid -> a.result() == CanonicalCpeLinkingService.ItemResult.LINKED;
            case linkedStale -> a.result() == CanonicalCpeLinkingService.ItemResult.STALE;

            // Dictionary
            case resolvable -> a.resolvable();
            case unresolvable -> !a.resolvable();

            // Other
            case needsNormalization -> a.needsNormalization();
        };
    }

    public record Row(
            Long softwareId,
            Long assetId,
            String assetName,
            String vendor,
            String product,
            String version,
            String normalizedVendor,
            String normalizedProduct,
            CanonicalCpeLinkingService.Analysis analysis
    ) {
        static Row from(SoftwareInstall s, CanonicalCpeLinkingService.Analysis a) {
            return new Row(
                    s.getId(),
                    s.getAsset() != null ? s.getAsset().getId() : null,
                    s.getAsset() != null ? s.getAsset().getName() : null,
                    s.getVendorRaw(),
                    s.getProductRaw(),
                    s.getVersionRaw(),
                    s.getNormalizedVendor(),
                    s.getNormalizedProduct(),
                    a
            );
        }
    }

    private static boolean containsKeyword(SoftwareInstall s, String keywordLower) {
        String hay = (safe(s.getVendorRaw()) + " " +
                safe(s.getProductRaw()) + " " +
                safe(s.getVersionRaw()) + " " +
                safe(s.getNormalizedVendor()) + " " +
                safe(s.getNormalizedProduct()))
                .toLowerCase();
        return hay.contains(keywordLower);
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }

    private static String normalizeKeyword(String q) {
        if (q == null) return null;
        String t = q.trim();
        if (t.isEmpty()) return null;
        return t.toLowerCase();
    }

    private static int clamp(int v, int min, int max) {
        if (v < min) return min;
        if (v > max) return max;
        return v;
    }
}