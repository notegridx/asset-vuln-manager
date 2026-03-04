package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeProductAlias;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendorAlias;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductAliasRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorAliasRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.service.SynonymService;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@Controller
public class AdminSynonymsController {

    private static final int LIMIT = 500;

    private final CpeVendorAliasRepository vendorAliasRepo;
    private final CpeProductAliasRepository productAliasRepo;
    private final CpeVendorRepository vendorRepo;
    private final CpeProductRepository productRepo;
    private final SynonymService synonymService;

    public AdminSynonymsController(
            CpeVendorAliasRepository vendorAliasRepo,
            CpeProductAliasRepository productAliasRepo,
            CpeVendorRepository vendorRepo,
            CpeProductRepository productRepo,
            SynonymService synonymService
    ) {
        this.vendorAliasRepo = vendorAliasRepo;
        this.productAliasRepo = productAliasRepo;
        this.vendorRepo = vendorRepo;
        this.productRepo = productRepo;
        this.synonymService = synonymService;
    }

    // =========================================================
    // Workspace (single page)
    // =========================================================

    @GetMapping("/admin/synonyms/vendors")
    public String workspace(
            @RequestParam(name = "vendorId", required = false) Long vendorId,
            @RequestParam(name = "tab", required = false) String tab,
            // vendor alias search
            @RequestParam(name = "q", required = false) String q,
            @RequestParam(name = "status", required = false) String status,
            // product alias search (scoped)
            @RequestParam(name = "qP", required = false) String qP,
            @RequestParam(name = "statusP", required = false) String statusP,
            Model model
    ) {
        String safeTab = normalizeTab(tab);

        // vendor aliases list (global)
        List<CpeVendorAlias> rows = vendorAliasRepo.search(
                safe(q),
                safe(status),
                PageRequest.of(0, LIMIT)
        );

        Map<Long, String> vendorLabels = loadVendorLabels(
                rows.stream().map(CpeVendorAlias::getCpeVendorId)
                        .filter(Objects::nonNull)
                        .collect(Collectors.toSet())
        );

        // selected vendor label (workspace header)
        String selectedVendorLabel = null;
        if (vendorId != null) {
            selectedVendorLabel = vendorRepo.findById(vendorId)
                    .map(v -> (v.getDisplayName() == null || v.getDisplayName().isBlank())
                            ? v.getNameNorm()
                            : v.getDisplayName())
                    .orElse(null);
        }

        // product aliases list (vendor scoped) - only when products tab + vendor selected
        List<CpeProductAlias> productRows = List.of();
        Map<Long, String> productLabels = Map.of();

        if ("products".equals(safeTab) && vendorId != null) {
            productRows = productAliasRepo.search(
                    vendorId,
                    safe(qP),
                    safe(statusP),
                    PageRequest.of(0, LIMIT)
            );

            Set<Long> productIds = productRows.stream()
                    .map(CpeProductAlias::getCpeProductId)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toSet());

            productLabels = loadProductLabels(productIds);
        }

        String currentQuery = buildCurrentQuery(vendorId, safeTab, safe(q), safe(status), safe(qP), safe(statusP));

        model.addAttribute("tab", safeTab);
        model.addAttribute("vendorId", vendorId);
        model.addAttribute("selectedVendorLabel", selectedVendorLabel);

        model.addAttribute("rows", rows);
        model.addAttribute("vendorLabels", vendorLabels);

        model.addAttribute("productRows", productRows);
        model.addAttribute("productLabels", productLabels);

        model.addAttribute("q", safe(q));
        model.addAttribute("status", safe(status));
        model.addAttribute("qP", safe(qP));
        model.addAttribute("statusP", safe(statusP));

        model.addAttribute("limit", LIMIT);
        model.addAttribute("currentQuery", currentQuery);

        return "admin/synonyms_vendors";
    }

    // Optional: backward compatible endpoint -> redirect to workspace
    @GetMapping("/admin/synonyms/products")
    public String productsCompat(@RequestParam(name = "vendorId", required = false) Long vendorId) {
        if (vendorId != null) {
            return "redirect:/admin/synonyms/vendors?vendorId=" + vendorId + "&tab=products";
        }
        return "redirect:/admin/synonyms/vendors?tab=products";
    }

    // =========================================================
    // Toggle endpoints (keep)
    // =========================================================

    @PostMapping("/admin/synonyms/vendors/toggle")
    public String toggleVendor(@RequestParam("id") Long id,
                               @RequestParam(name = "redirect", required = false) String redirect) {

        vendorAliasRepo.findById(id).ifPresent(a -> {
            a.setStatus(toggle(a.getStatus()));
            vendorAliasRepo.save(a);
            synonymService.clearCaches();
        });

        return safeRedirectOrDefault(redirect, "/admin/synonyms/vendors");
    }

    @PostMapping("/admin/synonyms/products/toggle")
    public String toggleProduct(@RequestParam("id") Long id,
                                @RequestParam(name = "redirect", required = false) String redirect) {

        productAliasRepo.findById(id).ifPresent(a -> {
            a.setStatus(toggle(a.getStatus()));
            productAliasRepo.save(a);
            synonymService.clearCaches();
        });

        return safeRedirectOrDefault(redirect, "/admin/synonyms/vendors?tab=products");
    }

    // =========================================================
    // Helpers
    // =========================================================

    private Map<Long, String> loadVendorLabels(Set<Long> ids) {
        if (ids == null || ids.isEmpty()) return Map.of();
        List<CpeVendor> list = vendorRepo.findAllById(ids);
        Map<Long, String> map = new HashMap<>();
        for (CpeVendor v : list) {
            String label = (v.getDisplayName() == null || v.getDisplayName().isBlank())
                    ? v.getNameNorm()
                    : v.getDisplayName();
            map.put(v.getId(), label);
        }
        return map;
    }

    private Map<Long, String> loadProductLabels(Set<Long> ids) {
        if (ids == null || ids.isEmpty()) return Map.of();
        List<CpeProduct> list = productRepo.findAllById(ids);
        Map<Long, String> map = new HashMap<>();
        for (CpeProduct p : list) {
            String label = (p.getDisplayName() == null || p.getDisplayName().isBlank())
                    ? p.getNameNorm()
                    : p.getDisplayName();
            map.put(p.getId(), label);
        }
        return map;
    }

    private static String safe(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static String toggle(String status) {
        if (status == null) return "ACTIVE";
        String s = status.trim().toUpperCase(Locale.ROOT);
        return "ACTIVE".equals(s) ? "INACTIVE" : "ACTIVE";
    }

    private static String normalizeTab(String tab) {
        if (tab == null) return "vendors";
        String t = tab.trim().toLowerCase(Locale.ROOT);
        return ("products".equals(t) || "vendors".equals(t)) ? t : "vendors";
    }

    private static String safeRedirectOrDefault(String redirect, String defaultPath) {
        if (redirect != null && redirect.startsWith("/")) return "redirect:" + redirect;
        return "redirect:" + defaultPath;
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String buildCurrentQuery(Long vendorId, String tab, String q, String status, String qP, String statusP) {
        List<String> parts = new ArrayList<>();

        if (vendorId != null) parts.add("vendorId=" + vendorId);
        if (tab != null) parts.add("tab=" + enc(tab));

        if (q != null) parts.add("q=" + enc(q));
        if (status != null) parts.add("status=" + enc(status));

        if (qP != null) parts.add("qP=" + enc(qP));
        if (statusP != null) parts.add("statusP=" + enc(statusP));

        if (parts.isEmpty()) return "";
        return "?" + String.join("&", parts);
    }
}