package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.service.AdminCanonicalBackfillService;
import dev.notegridx.security.assetvulnmanager.service.AdminJobAlreadyRunningException;
import dev.notegridx.security.assetvulnmanager.service.CanonicalCpeLinkingService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
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
            @RequestParam(name = "page", required = false, defaultValue = "0") Integer page,
            @RequestParam(name = "size", required = false, defaultValue = "50") Integer size,
            Model model
    ) {
        int safePage = Math.max(page == null ? 0 : page, 0);
        int safeSize = normalizePageSize(size);
        Filter filter = Filter.parse(filterRaw);
        String keyword = normalizeKeyword(q);

        List<Asset> assets = assetRepo.findAll(Sort.by(Sort.Direction.ASC, "id"));
        model.addAttribute("assets", assets);

        // ===== Global stats: ignore asset/filter/q/page/size and count entire software_installs =====
        List<SoftwareInstall> allSoftware = softwareRepo.findAll();
        var stats = linker.stats(allSoftware);
        model.addAttribute("stats", stats);

        // ===== Filter base rows first =====
        List<SoftwareInstall> base = softwareRepo.findAll(Sort.by(Sort.Direction.DESC, "id")).stream()
                .filter(s -> assetId == null || (s.getAsset() != null && Objects.equals(s.getAsset().getId(), assetId)))
                .filter(s -> keyword == null || containsKeyword(s, keyword))
                .toList();

        List<Row> analyzed = base.stream()
                .map(s -> Row.from(s, linker.analyze(s)))
                .toList();

        List<Row> filteredRows = analyzed.stream()
                .filter(r -> matchesFilter(r, filter))
                .toList();

        Pageable pageable = PageRequest.of(safePage, safeSize);
        int fromIndex = Math.min((int) pageable.getOffset(), filteredRows.size());
        int toIndex = Math.min(fromIndex + pageable.getPageSize(), filteredRows.size());

        Page<Row> rowPage = new PageImpl<>(
                filteredRows.subList(fromIndex, toIndex),
                pageable,
                filteredRows.size()
        );

        model.addAttribute("rows", rowPage.getContent());
        model.addAttribute("rowPage", rowPage);

        model.addAttribute("asset", assetId);
        model.addAttribute("filter", filter.name());
        model.addAttribute("q", q);
        model.addAttribute("page", safePage);
        model.addAttribute("size", safeSize);
        model.addAttribute("sizeOptions", List.of(50, 100, 200, 500));

        model.addAttribute("totalFilteredRows", filteredRows.size());
        model.addAttribute("pageRowStart", filteredRows.isEmpty() ? 0 : fromIndex + 1);
        model.addAttribute("pageRowEnd", toIndex);

        String currentQuery = buildCurrentQuery(assetId, filter.name(), q, safePage, safeSize);
        model.addAttribute("currentQuery", currentQuery);

        return "admin/canonical";
    }

    /**
     * Run Linking (Run Canonical Backfill)
     * - relink=false: not linked only
     * - relink=true : include already linked rows (force rebuild)
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

    private static int normalizePageSize(Integer size) {
        int v = size == null ? 50 : size;
        if (v <= 50) return 50;
        if (v <= 100) return 100;
        if (v <= 200) return 200;
        return 500;
    }

    private static String buildCurrentQuery(Long assetId, String filter, String q, Integer page, Integer size) {
        StringBuilder sb = new StringBuilder();

        appendQueryParam(sb, "asset", assetId);
        appendQueryParam(sb, "filter", safeParam(filter));
        appendQueryParam(sb, "q", safeParam(q));
        appendQueryParam(sb, "page", page);
        appendQueryParam(sb, "size", size);

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