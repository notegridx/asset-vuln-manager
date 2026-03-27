package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.service.*;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@Controller
public class AdminCanonicalController {

    private static final long STATS_CACHE_MILLIS = 30_000L;
    private static final long ASSETS_CACHE_MILLIS = 30_000L;
    private static final String UNUSED_ASSET_NAME = null;
    private static final List<Integer> SIZE_OPTIONS = List.of(50, 100, 200, 500);

    private final AssetRepository assetRepo;
    private final SoftwareInstallRepository softwareRepo;
    private final CanonicalCpeLinkingService linker;
    private final AdminCanonicalBackfillService adminCanonicalBackfillService;
    private final DemoModeService demoModeService;
    private final CpeVendorRepository cpeVendorRepository;
    private final CpeProductRepository cpeProductRepository;

    private volatile CanonicalCpeLinkingService.MappingStats cachedStats;
    private volatile long cachedStatsAtMillis;

    private volatile List<Asset> cachedAssets;
    private volatile long cachedAssetsAtMillis;

    private final AdminRunRecorder adminRunRecorder;

    public AdminCanonicalController(
            AssetRepository assetRepo,
            SoftwareInstallRepository softwareRepo,
            CanonicalCpeLinkingService linker,
            AdminCanonicalBackfillService adminCanonicalBackfillService,
            DemoModeService demoModeService,
            CpeVendorRepository cpeVendorRepository,
            CpeProductRepository cpeProductRepository,
            AdminRunRecorder adminRunRecorder
    ) {
        this.assetRepo = assetRepo;
        this.softwareRepo = softwareRepo;
        this.linker = linker;
        this.adminCanonicalBackfillService = adminCanonicalBackfillService;
        this.demoModeService = demoModeService;
        this.cpeVendorRepository = cpeVendorRepository;
        this.cpeProductRepository = cpeProductRepository;
        this.adminRunRecorder = adminRunRecorder;
    }

    public enum Filter {
        all("all"),

        fullyLinked("fullyLinked"),
        vendorOnlyLinked("vendorOnlyLinked"),
        notLinked("notLinked"),

        linkedValid("linkedValid"),
        linkedStale("linkedStale"),

        fullyResolvable("fullyResolvable"),
        vendorResolvableOnly("vendorResolvableOnly"),
        unresolvable("unresolvable"),

        needsNormalization("needsNormalization");

        private final String paramValue;

        Filter(String paramValue) {
            this.paramValue = paramValue;
        }

        public String paramValue() {
            return paramValue;
        }

        static Filter parse(String s) {
            if (s == null || s.isBlank()) {
                return all;
            }

            String raw = s.trim();
            String normalized = raw.toLowerCase(Locale.ROOT);

            return switch (normalized) {
                case "all" -> all;

                // Existing filter names
                case "fullylinked" -> fullyLinked;
                case "vendoronlylinked" -> vendorOnlyLinked;
                case "notlinked" -> notLinked;

                case "linkedvalid" -> linkedValid;
                case "linkedstale" -> linkedStale;

                case "fullyresolvable" -> fullyResolvable;
                case "vendorresolvableonly" -> vendorResolvableOnly;
                case "unresolvable" -> unresolvable;

                case "needsnormalization" -> needsNormalization;

                // Stats button aliases
                case "fullylinkedsql" -> fullyLinked;
                case "vendoronlylinkedsql" -> vendorOnlyLinked;
                case "notlinkedsql" -> notLinked;

                default -> {
                    try {
                        yield Filter.valueOf(raw);
                    } catch (Exception e) {
                        yield all;
                    }
                }
            };
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
        populateViewModel(assetId, filterRaw, q, page, size, model);
        model.addAttribute(
                "linkingRunning",
                adminRunRecorder.isRunning(AdminJobType.CANONICAL_BACKFILL)
        );
        return "admin/canonical";
    }

    @GetMapping("/admin/canonical/table")
    public String table(
            @RequestParam(name = "asset", required = false) Long assetId,
            @RequestParam(name = "filter", required = false, defaultValue = "all") String filterRaw,
            @RequestParam(name = "q", required = false) String q,
            @RequestParam(name = "page", required = false, defaultValue = "0") Integer page,
            @RequestParam(name = "size", required = false, defaultValue = "50") Integer size,
            Model model
    ) {
        populateViewModel(assetId, filterRaw, q, page, size, model);
        return "admin/fragments/canonical_table :: canonicalTable";
    }

    private void populateViewModel(
            Long assetId,
            String filterRaw,
            String q,
            Integer page,
            Integer size,
            Model model
    ) {
        int safePage = Math.max(page == null ? 0 : page, 0);
        int safeSize = normalizePageSize(size);
        Filter filter = Filter.parse(filterRaw);
        String keyword = normalizeKeyword(q);

        model.addAttribute("assets", getCachedAssets());
        model.addAttribute("stats", getCachedStats());

        Pageable pageable = PageRequest.of(safePage, safeSize);
        Page<Row> rowPage;

        if (isSqlPageableFilter(filter)) {
            Page<SoftwareInstall> softwarePage =
                    softwareRepo.findCanonicalSqlPage(
                            assetId,
                            UNUSED_ASSET_NAME,
                            keyword,
                            filter.name(),
                            pageable
                    );

            List<Row> rows = toRows(softwarePage.getContent());
            rowPage = new PageImpl<>(rows, pageable, softwarePage.getTotalElements());
        } else {
            rowPage = findCanonicalAnalyzedPage(assetId, keyword, filter, pageable);
        }

        int pageRowStart = rowPage.getNumberOfElements() == 0 ? 0 : (int) pageable.getOffset() + 1;
        int pageRowEnd = rowPage.getNumberOfElements() == 0 ? 0 : (int) pageable.getOffset() + rowPage.getNumberOfElements();

        model.addAttribute("rows", rowPage.getContent());
        model.addAttribute("rowPage", rowPage);
        model.addAttribute("pagerItems", buildPagerItems(rowPage));

        model.addAttribute("asset", assetId);

        // Keep the existing model attribute for backward compatibility with the current template.
        model.addAttribute("filter", filter.name());

        // Additional attribute for template-side link/highlight handling.
        model.addAttribute("selectedFilterParam", filter.paramValue());

        model.addAttribute("q", q);
        model.addAttribute("page", safePage);
        model.addAttribute("size", safeSize);
        model.addAttribute("sizeOptions", SIZE_OPTIONS);

        model.addAttribute("totalFilteredRows", rowPage.getTotalElements());
        model.addAttribute("pageRowStart", pageRowStart);
        model.addAttribute("pageRowEnd", pageRowEnd);

        String currentQuery = buildCurrentQuery(assetId, filter.paramValue(), q, safePage, safeSize);
        model.addAttribute("currentQuery", currentQuery);
    }

    @PostMapping("/admin/canonical/link")
    public String runLinking(
            @RequestParam(name = "relink", defaultValue = "false") boolean relink,
            @RequestParam(name = "maxRows", defaultValue = "5000000") int maxRows,
            @RequestParam(name = "redirect", required = false) String redirect,
            RedirectAttributes ra
    ) {
        demoModeService.assertWritable();

        try {
            var result = adminCanonicalBackfillService.runBackfill(maxRows, relink);
            invalidateCaches();
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
            @RequestParam(name = "asset", required = false) Long assetId,
            @RequestParam(name = "filter", required = false, defaultValue = "all") String filterRaw,
            @RequestParam(name = "q", required = false) String q,
            @RequestParam(name = "page", required = false, defaultValue = "0") Integer page,
            @RequestParam(name = "size", required = false, defaultValue = "50") Integer size,
            @RequestHeader(value = "HX-Request", required = false) String hxRequest,
            Model model,
            RedirectAttributes ra
    ) {
        demoModeService.assertWritable();

        SoftwareInstall s = softwareRepo.findById(softwareId).orElse(null);
        if (s == null) {
            if (isHtmxRequest(hxRequest)) {
                populateViewModel(assetId, filterRaw, q, page, size, model);
                model.addAttribute("error", "SoftwareInstall not found: id=" + softwareId);
                return "admin/fragments/canonical_table :: canonicalTable";
            }

            ra.addFlashAttribute("error", "SoftwareInstall not found: id=" + softwareId);
            return safeRedirectOrDefault(redirect, "/admin/canonical");
        }

        if (disabled) {
            s.disableCanonicalLink();
        } else {
            s.enableCanonicalLink();
        }

        softwareRepo.save(s);
        invalidateStatsCache();

        if (isHtmxRequest(hxRequest)) {
            populateViewModel(assetId, filterRaw, q, page, size, model);
            return "admin/fragments/canonical_table :: canonicalTable";
        }

        ra.addFlashAttribute(
                "success",
                disabled
                        ? "Auto product link disabled for softwareId=" + softwareId
                        : "Auto product link enabled for softwareId=" + softwareId
        );

        return safeRedirectOrDefault(redirect, "/admin/canonical");
    }

    private Page<Row> findCanonicalAnalyzedPage(
            Long assetId,
            String keyword,
            Filter filter,
            Pageable pageable
    ) {
        int batchSize = Math.max(200, pageable.getPageSize() * 4);
        long offset = pageable.getOffset();

        long matchedCount = 0;
        int batchPage = 0;
        List<SoftwareInstall> pageInstalls = new ArrayList<>(pageable.getPageSize());
        List<CanonicalCpeLinkingService.Analysis> pageAnalyses = new ArrayList<>(pageable.getPageSize());

        while (true) {
            Page<SoftwareInstall> batch = softwareRepo.findCanonicalBasePage(
                    assetId,
                    UNUSED_ASSET_NAME,
                    keyword,
                    PageRequest.of(batchPage, batchSize)
            );

            if (batch.isEmpty()) {
                break;
            }

            for (SoftwareInstall s : batch.getContent()) {
                CanonicalCpeLinkingService.Analysis analysis = linker.analyze(s);
                Row row = Row.from(
                        s,
                        analysis,
                        s.getCpeVendorId(),
                        s.getCpeProductId(),
                        null,
                        null
                );
                if (!matchesFilter(row, filter)) {
                    continue;
                }

                if (matchedCount >= offset && pageInstalls.size() < pageable.getPageSize()) {
                    pageInstalls.add(s);
                    pageAnalyses.add(analysis);
                }
                matchedCount++;
            }

            if (!batch.hasNext()) {
                break;
            }
            batchPage++;
        }

        List<Row> pageRows = toRows(pageInstalls, pageAnalyses);
        return new PageImpl<>(pageRows, pageable, matchedCount);
    }

    private List<Row> toRows(List<SoftwareInstall> installs) {
        List<CanonicalCpeLinkingService.Analysis> analyses = installs.stream()
                .map(linker::analyze)
                .toList();
        return toRows(installs, analyses);
    }

    private List<Row> toRows(
            List<SoftwareInstall> installs,
            List<CanonicalCpeLinkingService.Analysis> analyses
    ) {
        Map<Long, String> vendorLabelMap = resolveVendorLabelMap(installs);
        Map<Long, String> productLabelMap = resolveProductLabelMap(installs);

        List<Row> rows = new ArrayList<>(installs.size());
        for (int i = 0; i < installs.size(); i++) {
            SoftwareInstall s = installs.get(i);
            CanonicalCpeLinkingService.Analysis analysis = analyses.get(i);

            String canonicalVendorLabel = s.getCpeVendorId() == null
                    ? null
                    : vendorLabelMap.get(s.getCpeVendorId());

            String canonicalProductLabel = s.getCpeProductId() == null
                    ? null
                    : productLabelMap.get(s.getCpeProductId());

            rows.add(Row.from(
                    s,
                    analysis,
                    s.getCpeVendorId(),
                    s.getCpeProductId(),
                    canonicalVendorLabel,
                    canonicalProductLabel
            ));
        }
        return rows;
    }

    private Map<Long, String> resolveVendorLabelMap(List<SoftwareInstall> installs) {
        List<Long> vendorIds = installs.stream()
                .map(SoftwareInstall::getCpeVendorId)
                .filter(id -> id != null)
                .distinct()
                .toList();

        Map<Long, String> out = new HashMap<>();
        for (CpeVendor v : cpeVendorRepository.findAllById(vendorIds)) {
            out.put(v.getId(), firstNonBlank(v.getDisplayName(), v.getNameNorm(), "#" + v.getId()));
        }
        return out;
    }

    private Map<Long, String> resolveProductLabelMap(List<SoftwareInstall> installs) {
        List<Long> productIds = installs.stream()
                .map(SoftwareInstall::getCpeProductId)
                .filter(id -> id != null)
                .distinct()
                .toList();

        Map<Long, String> out = new HashMap<>();
        for (CpeProduct p : cpeProductRepository.findAllById(productIds)) {
            out.put(p.getId(), firstNonBlank(p.getDisplayName(), p.getNameNorm(), "#" + p.getId()));
        }
        return out;
    }

    private CanonicalCpeLinkingService.MappingStats getCachedStats() {
        long now = System.currentTimeMillis();
        CanonicalCpeLinkingService.MappingStats local = cachedStats;

        if (local != null && (now - cachedStatsAtMillis) < STATS_CACHE_MILLIS) {
            return local;
        }

        synchronized (this) {
            now = System.currentTimeMillis();
            local = cachedStats;

            if (local != null && (now - cachedStatsAtMillis) < STATS_CACHE_MILLIS) {
                return local;
            }

            CanonicalCpeLinkingService.MappingStats refreshed = linker.statsOverall(5000);
            cachedStats = refreshed;
            cachedStatsAtMillis = now;
            return refreshed;
        }
    }

    private List<Asset> getCachedAssets() {
        long now = System.currentTimeMillis();
        List<Asset> local = cachedAssets;

        if (local != null && (now - cachedAssetsAtMillis) < ASSETS_CACHE_MILLIS) {
            return local;
        }

        synchronized (this) {
            now = System.currentTimeMillis();
            local = cachedAssets;

            if (local != null && (now - cachedAssetsAtMillis) < ASSETS_CACHE_MILLIS) {
                return local;
            }

            List<Asset> refreshed = assetRepo.findAll(Sort.by(Sort.Direction.ASC, "id"));
            cachedAssets = refreshed;
            cachedAssetsAtMillis = now;
            return refreshed;
        }
    }

    private void invalidateCaches() {
        invalidateStatsCache();
        invalidateAssetsCache();
    }

    private void invalidateStatsCache() {
        cachedStats = null;
        cachedStatsAtMillis = 0L;
    }

    private void invalidateAssetsCache() {
        cachedAssets = null;
        cachedAssetsAtMillis = 0L;
    }

    private static boolean isSqlPageableFilter(Filter filter) {
        return switch (filter) {
            case all, fullyLinked, vendorOnlyLinked, notLinked -> true;
            default -> false;
        };
    }

    private static boolean isHtmxRequest(String hxRequest) {
        return "true".equalsIgnoreCase(hxRequest);
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
            case unresolvable -> a.dictUnresolvable() && !a.needsNormalization();
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
            Long canonicalVendorId,
            Long canonicalProductId,
            String canonicalVendorLabel,
            String canonicalProductLabel,
            CanonicalCpeLinkingService.Analysis analysis
    ) {
        static Row from(
                SoftwareInstall s,
                CanonicalCpeLinkingService.Analysis a,
                Long canonicalVendorId,
                Long canonicalProductId,
                String canonicalVendorLabel,
                String canonicalProductLabel
        ) {
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
                    canonicalVendorId,
                    canonicalProductId,
                    canonicalVendorLabel,
                    canonicalProductLabel,
                    a
            );
        }
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

    private static String buildCurrentQuery(
            Long assetId,
            String filter,
            String q,
            Integer page,
            Integer size
    ) {
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

    private static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null) {
                String trimmed = value.trim();
                if (!trimmed.isEmpty()) {
                    return trimmed;
                }
            }
        }
        return null;
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

        if (start > 0) {
            items.add(0);
        }

        if (start > 1) {
            items.add(-1);
        }

        for (int i = start; i <= end; i++) {
            items.add(i);
        }

        if (end < totalPages - 2) {
            items.add(-1);
        }

        if (end < totalPages - 1) {
            items.add(totalPages - 1);
        }

        return items;
    }
}