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
    // Vendors
    // =========================================================

    @GetMapping("/admin/synonyms/vendors")
    public String vendors(
            @RequestParam(name = "q", required = false) String q,
            @RequestParam(name = "status", required = false) String status,
            Model model
    ) {
        List<CpeVendorAlias> rows = vendorAliasRepo.search(
                safe(q),
                safe(status),
                PageRequest.of(0, LIMIT)
        );

        Map<Long, String> vendorLabels = loadVendorLabels(
                rows.stream().map(CpeVendorAlias::getCpeVendorId).filter(Objects::nonNull).collect(Collectors.toSet())
        );

        model.addAttribute("rows", rows);
        model.addAttribute("vendorLabels", vendorLabels);
        model.addAttribute("q", safe(q));
        model.addAttribute("status", safe(status));
        model.addAttribute("limit", LIMIT);
        return "admin/synonyms_vendors";
    }

    @PostMapping("/admin/synonyms/vendors/toggle")
    public String toggleVendor(@RequestParam("id") Long id,
                               @RequestParam(name = "redirect", required = false) String redirect) {
        vendorAliasRepo.findById(id).ifPresent(a -> {
            a.setStatus(toggle(a.getStatus()));
            vendorAliasRepo.save(a);
            synonymService.clearCaches();
        });

        if (redirect != null && redirect.startsWith("/")) return "redirect:" + redirect;
        return "redirect:/admin/synonyms/vendors";
    }

    // =========================================================
    // Products
    // =========================================================

    @GetMapping("/admin/synonyms/products")
    public String products(
            @RequestParam(name = "vendorId", required = false) Long vendorId,
            @RequestParam(name = "q", required = false) String q,
            @RequestParam(name = "status", required = false) String status,
            Model model
    ) {
        List<CpeProductAlias> rows = productAliasRepo.search(
                vendorId,
                safe(q),
                safe(status),
                PageRequest.of(0, LIMIT)
        );

        Set<Long> vendorIds = rows.stream().map(CpeProductAlias::getCpeVendorId).filter(Objects::nonNull).collect(Collectors.toSet());
        Set<Long> productIds = rows.stream().map(CpeProductAlias::getCpeProductId).filter(Objects::nonNull).collect(Collectors.toSet());

        Map<Long, String> vendorLabels = loadVendorLabels(vendorIds);
        Map<Long, String> productLabels = loadProductLabels(productIds);

        model.addAttribute("rows", rows);
        model.addAttribute("vendorLabels", vendorLabels);
        model.addAttribute("productLabels", productLabels);
        model.addAttribute("vendorId", vendorId);
        model.addAttribute("q", safe(q));
        model.addAttribute("status", safe(status));
        model.addAttribute("limit", LIMIT);
        return "admin/synonyms_products";
    }

    @PostMapping("/admin/synonyms/products/toggle")
    public String toggleProduct(@RequestParam("id") Long id,
                                @RequestParam(name = "redirect", required = false) String redirect) {
        productAliasRepo.findById(id).ifPresent(a -> {
            a.setStatus(toggle(a.getStatus()));
            productAliasRepo.save(a);
            synonymService.clearCaches();
        });

        if (redirect != null && redirect.startsWith("/")) return "redirect:" + redirect;
        return "redirect:/admin/synonyms/products";
    }

    // =========================================================
    // Helpers
    // =========================================================

    private Map<Long, String> loadVendorLabels(Set<Long> ids) {
        if (ids == null || ids.isEmpty()) return Map.of();
        List<CpeVendor> list = vendorRepo.findAllById(ids);
        Map<Long, String> map = new HashMap<>();
        for (CpeVendor v : list) {
            String label = (v.getDisplayName() == null || v.getDisplayName().isBlank()) ? v.getNameNorm() : v.getDisplayName();
            map.put(v.getId(), label);
        }
        return map;
    }

    private Map<Long, String> loadProductLabels(Set<Long> ids) {
        if (ids == null || ids.isEmpty()) return Map.of();
        List<CpeProduct> list = productRepo.findAllById(ids);
        Map<Long, String> map = new HashMap<>();
        for (CpeProduct p : list) {
            String label = (p.getDisplayName() == null || p.getDisplayName().isBlank()) ? p.getNameNorm() : p.getDisplayName();
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
}