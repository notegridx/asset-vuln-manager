package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.service.AdminCanonicalBackfillService;
import dev.notegridx.security.assetvulnmanager.service.AdminJobAlreadyRunningException;
import dev.notegridx.security.assetvulnmanager.service.CanonicalCpeLinkingService;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;

@Controller
public class AdminCanonicalController {

    private final AssetRepository assetRepo;
    private final SoftwareInstallRepository softwareRepo;
    private final CanonicalCpeLinkingService linker;
    private final AdminCanonicalBackfillService adminCanonicalBackfillService;

    public AdminCanonicalController(
            AssetRepository assetRepo,
            SoftwareInstallRepository softwareRepo,
            CanonicalCpeLinkingService linker,
            AdminCanonicalBackfillService adminCanonicalBackfillService
    ) {
        this.assetRepo = assetRepo;
        this.softwareRepo = softwareRepo;
        this.linker = linker;
        this.adminCanonicalBackfillService = adminCanonicalBackfillService;
    }

    public enum Filter {
        all,

        // SQL link (IDs)
        fullyLinked,
        vendorOnlyLinked,
        notLinked,

        // Fully linked quality
        linkedValid,
        linkedStale,

        // Dictionary (ONLY for notLinked)
        fullyResolvable,
        vendorResolvableOnly,
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

        List<Asset> assets = assetRepo.findAll(Sort.by(Sort.Direction.ASC, "id"));
        model.addAttribute("assets", assets);

        List<SoftwareInstall> base = softwareRepo.findAll(Sort.by(Sort.Direction.DESC, "id")).stream()
                .filter(s -> assetId == null || (s.getAsset() != null && Objects.equals(s.getAsset().getId(), assetId)))
                .filter(s -> keyword == null || containsKeyword(s, keyword))
                .limit(safeLimit)
                .toList();

        var stats = linker.stats(base);
        model.addAttribute("stats", stats);

        List<Row> analyzed = base.stream()
                .map(s -> Row.from(s, linker.analyze(s)))
                .toList();

        List<Row> rows = analyzed.stream()
                .filter(r -> matchesFilter(r, filter))
                .toList();

        model.addAttribute("rows", rows);

        model.addAttribute("asset", assetId);
        model.addAttribute("filter", filter.name());
        model.addAttribute("q", q);
        model.addAttribute("limit", safeLimit);

        String currentQuery = buildCurrentQuery(assetId, filter.name(), q, safeLimit);
        model.addAttribute("currentQuery", currentQuery);

        return "admin/canonical";
    }

    /**
     * Run Linking (Run Canonical Backfill)
     * - relink=false: 未リンクのみ
     * - relink=true : 既リンクも含めて再リンク（forceRebuild）
     */
    @PostMapping("/admin/canonical/link")
    public String runLinking(
            @RequestParam(name = "relink", defaultValue = "false") boolean relink,
            @RequestParam(name = "maxRows", defaultValue = "5000000") int maxRows,
            @RequestParam(name = "redirect", required = false) String redirect,
            RedirectAttributes ra
    ) {
        try {
            var result = adminCanonicalBackfillService.runBackfill(maxRows, relink);
            ra.addFlashAttribute("backfillResult", result);
        } catch (AdminJobAlreadyRunningException ex) {
            ra.addFlashAttribute("error", ex.getMessage());
        }

        return safeRedirectOrDefault(redirect, "/admin/canonical");
    }

    @PostMapping("/admin/canonical/link-disabled")
    public String setLinkDisabled(
            @RequestParam("softwareId") Long softwareId,
            @RequestParam("disabled") boolean disabled,
            @RequestParam(name = "redirect", required = false) String redirect,
            RedirectAttributes ra
    ) {
        SoftwareInstall s = softwareRepo.findById(softwareId).orElse(null);
        if (s == null) {
            ra.addFlashAttribute("error", "SoftwareInstall not found: id=" + softwareId);
            return safeRedirectOrDefault(redirect, "/admin/canonical");
        }

        s.setCanonicalLinkDisabled(disabled);
        softwareRepo.save(s);

        ra.addFlashAttribute(
                "success",
                disabled
                        ? "Auto product link disabled for softwareId=" + softwareId
                        : "Auto product link enabled for softwareId=" + softwareId
        );

        return safeRedirectOrDefault(redirect, "/admin/canonical");
    }

    private static String safeRedirectOrDefault(String redirect, String fallback) {
        if (redirect == null || redirect.isBlank()) return "redirect:" + fallback;
        String t = redirect.trim();

        if (!t.startsWith("/")) return "redirect:" + fallback;
        if (t.startsWith("//")) return "redirect:" + fallback;
        if (t.contains("://")) return "redirect:" + fallback;

        return "redirect:" + t;
    }

    private static boolean matchesFilter(Row r, Filter f) {
        var a = r.analysis;
        return switch (f) {
            case all -> true;

            case fullyLinked -> a.fullyLinkedSql();
            case vendorOnlyLinked -> a.vendorOnlyLinkedSql();
            case notLinked -> a.notLinkedSql();

            case linkedValid -> a.result() == CanonicalCpeLinkingService.ItemResult.LINKED;
            case linkedStale -> a.result() == CanonicalCpeLinkingService.ItemResult.STALE;

            case fullyResolvable -> a.dictFullyResolvable();
            case vendorResolvableOnly -> a.dictVendorResolvableOnly();
            case unresolvable -> a.dictUnresolvable();

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
            boolean canonicalLinkDisabled,
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
                    s.isCanonicalLinkDisabled(),
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

    private static String buildCurrentQuery(Long assetId, String filter, String q, Integer limit) {
        StringBuilder sb = new StringBuilder();

        appendQueryParam(sb, "asset", assetId);
        appendQueryParam(sb, "filter", safeParam(filter));
        appendQueryParam(sb, "q", safeParam(q));
        appendQueryParam(sb, "limit", limit);

        return sb.isEmpty() ? "" : "?" + sb;
    }

    private static void appendQueryParam(StringBuilder sb, String key, Object value) {
        if (value == null) return;

        String s = String.valueOf(value).trim();
        if (s.isEmpty()) return;

        if (!sb.isEmpty()) sb.append("&");
        sb.append(URLEncoder.encode(key, StandardCharsets.UTF_8));
        sb.append("=");
        sb.append(URLEncoder.encode(s, StandardCharsets.UTF_8));
    }

    private static String safeParam(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }
}