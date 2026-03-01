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
import java.util.Locale;
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

    /**
     * Filter vocabulary MUST match Summary keys:
     * linked / linkedValid / linkedStale / resolvable / unresolvable / needsNormalization
     */
    public enum Filter {
        ALL,
        LINKED,              // linked = linkedValid + linkedStale
        LINKED_VALID,        // linkedValid
        LINKED_STALE,        // linkedStale
        RESOLVABLE,          // resolvable
        UNRESOLVABLE,        // unresolvable
        NEEDS_NORMALIZATION; // needsNormalization

        static Filter parse(String s) {
            if (s == null) return ALL;
            try {
                return Filter.valueOf(s.trim().toUpperCase(Locale.ROOT));
            } catch (Exception e) {
                return ALL;
            }
        }
    }

    @GetMapping("/admin/canonical")
    public String view(
            @RequestParam(name = "assetId", required = false) Long assetId,
            @RequestParam(name = "filter", required = false, defaultValue = "ALL") String filterRaw,
            @RequestParam(name = "q", required = false) String q,
            @RequestParam(name = "limit", required = false, defaultValue = "200") Integer limit,
            Model model
    ) {
        int safeLimit = clamp(limit == null ? 200 : limit, 1, 2000);
        Filter filter = Filter.parse(filterRaw);
        String keyword = normalizeKeyword(q);

        // Assets dropdown
        List<Asset> assets = assetRepo.findAll(Sort.by(Sort.Direction.ASC, "id"));
        model.addAttribute("assets", assets);

        // Overall stats (first N rows; keep approximate, consistent with UI text)
        var overall = linker.statsOverall(5000);
        model.addAttribute("summaryOverall", overall);

        // Base selection (asset + keyword, before filter)
        List<SoftwareInstall> base = softwareRepo.findAll(Sort.by(Sort.Direction.DESC, "id")).stream()
                .filter(s -> assetId == null || (s.getAsset() != null && Objects.equals(s.getAsset().getId(), assetId)))
                .filter(s -> keyword == null || containsKeyword(s, keyword))
                .limit(safeLimit)
                .toList();

        // Analyze rows
        List<Row> analyzed = base.stream()
                .map(s -> Row.from(s, linker.analyze(s)))
                .toList();

        // Apply filter
        List<Row> rows = analyzed.stream()
                .filter(r -> matchesFilter(r, filter))
                .toList();

        // Current selection stats = after filter (what you see)
        var current = linker.stats(rows.stream().map(Row::software).toList());
        model.addAttribute("summaryCurrent", current);

        model.addAttribute("rows", rows);

        // Echo states
        model.addAttribute("assetId", assetId);
        model.addAttribute("filter", filter.name());
        model.addAttribute("q", q);
        model.addAttribute("limit", safeLimit);

        return "admin/canonical";
    }

    private static boolean matchesFilter(Row r, Filter f) {
        var res = r.analysis.result();
        return switch (f) {
            case ALL -> true;

            // linked = linkedValid + linkedStale
            case LINKED -> (res == CanonicalCpeLinkingService.ItemResult.LINKED
                    || res == CanonicalCpeLinkingService.ItemResult.STALE);

            case LINKED_VALID -> res == CanonicalCpeLinkingService.ItemResult.LINKED;
            case LINKED_STALE -> res == CanonicalCpeLinkingService.ItemResult.STALE;

            // MUST match Summary semantics:
            // resolvable/unresolvable are dictionary-resolution flags regardless of SQL link state.
            case RESOLVABLE -> r.analysis.resolvable();
            case UNRESOLVABLE -> !r.analysis.resolvable();

            case NEEDS_NORMALIZATION -> r.analysis.needsNormalization();
        };
    }

    private static boolean containsKeyword(SoftwareInstall s, String kw) {
        String v = safeLower(s.getVendor());
        String p = safeLower(s.getProduct());
        String ver = safeLower(s.getVersion());
        String nv = safeLower(s.getNormalizedVendor());
        String np = safeLower(s.getNormalizedProduct());
        return v.contains(kw) || p.contains(kw) || ver.contains(kw) || nv.contains(kw) || np.contains(kw);
    }

    private static String normalizeKeyword(String q) {
        if (q == null) return null;
        String t = q.trim().toLowerCase(Locale.ROOT);
        return t.isEmpty() ? null : t;
    }

    private static String safeLower(String s) {
        if (s == null) return "";
        return s.toLowerCase(Locale.ROOT);
    }

    private static int clamp(int v, int min, int max) {
        if (v < min) return min;
        if (v > max) return max;
        return v;
    }

    public record Row(
            SoftwareInstall software,
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
            Long aid = (s.getAsset() == null ? null : s.getAsset().getId());
            String an = (s.getAsset() == null ? "-" : s.getAsset().getName());
            return new Row(
                    s,
                    s.getId(),
                    aid,
                    an,
                    s.getVendor(),
                    s.getProduct(),
                    s.getVersion(),
                    s.getNormalizedVendor(),
                    s.getNormalizedProduct(),
                    a
            );
        }
    }
}