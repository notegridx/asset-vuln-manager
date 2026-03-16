package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.repository.UnresolvedMappingRepository;
import dev.notegridx.security.assetvulnmanager.service.AdminInventoryReadService;
import dev.notegridx.security.assetvulnmanager.service.UnresolvedQuickAddService;
import dev.notegridx.security.assetvulnmanager.service.UnresolvedResolutionService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Controller
public class AdminInventoryController {

    private final AdminInventoryReadService adminInventoryReadService;
    private final UnresolvedMappingRepository unresolvedMappingRepository;
    private final UnresolvedResolutionService unresolvedResolutionService;
    private final UnresolvedQuickAddService unresolvedQuickAddService;

    public AdminInventoryController(
            AdminInventoryReadService adminInventoryReadService,
            UnresolvedMappingRepository unresolvedMappingRepository,
            UnresolvedResolutionService unresolvedResolutionService,
            UnresolvedQuickAddService unresolvedQuickAddService
    ) {
        this.adminInventoryReadService = adminInventoryReadService;
        this.unresolvedMappingRepository = unresolvedMappingRepository;
        this.unresolvedResolutionService = unresolvedResolutionService;
        this.unresolvedQuickAddService = unresolvedQuickAddService;
    }

    @GetMapping("/admin/import-runs")
    public String importRuns(Model model) {
        model.addAttribute("runs", adminInventoryReadService.findImportRuns());
        return "admin/import_runs";
    }

    @GetMapping("/admin/unresolved")
    public String unresolved(
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "runId", required = false) Long runId,
            @RequestParam(name = "activeOnly", required = false) Boolean activeOnly,
            @RequestParam(name = "activeOnlyPresent", required = false) String activeOnlyPresent,
            @RequestParam(name = "id", required = false) Long id,
            Model model
    ) {
        var view = adminInventoryReadService.findUnresolvedMappings(
                status,
                runId,
                activeOnly,
                activeOnlyPresent,
                id
        );

        model.addAttribute("mappings", view.mappings());
        model.addAttribute("status", view.status());
        model.addAttribute("runId", view.runId());
        model.addAttribute("activeOnly", view.activeOnly());
        model.addAttribute("activeOnlyPresent", view.activeOnlyPresent());
        model.addAttribute("id", view.id());

        return "admin/unresolved";
    }

    // =========================================================
    // Apply resolution
    // =========================================================

    @PostMapping("/admin/unresolved/apply")
    public String applyUnresolved(
            @RequestParam("mappingId") String mappingIdRaw,
            @RequestParam(name = "cpeVendorId", required = false) String cpeVendorIdRaw,
            @RequestParam(name = "cpeProductId", required = false) String cpeProductIdRaw,
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "runId", required = false) Long runId,
            @RequestParam(name = "activeOnly", required = false) Boolean activeOnly,
            @RequestParam(name = "activeOnlyPresent", required = false) String activeOnlyPresent,
            @RequestParam(name = "id", required = false) Long id,
            RedirectAttributes ra
    ) {
        Long mappingId = parseLong(mappingIdRaw);
        Long vendorId = parseLongNullable(cpeVendorIdRaw);
        Long productId = parseLongNullable(cpeProductIdRaw);

        boolean active = effectiveActiveOnly(activeOnly, activeOnlyPresent);

        if (mappingId == null) {
            ra.addFlashAttribute("error", "Invalid mappingId.");
            return "redirect:/admin/unresolved" + redirectQuery(status, runId, active, true, id);
        }
        if (vendorId == null) {
            ra.addFlashAttribute("error", "Vendor ID is required. Please select from candidates (chips).");
            return "redirect:/admin/unresolved" + redirectQuery(status, runId, active, true, id);
        }

        try {
            var result = unresolvedResolutionService.apply(mappingId, vendorId, productId);
            ra.addFlashAttribute("success",
                    "Applied: mappingId=" + result.mappingId()
                            + " vendorId=" + result.vendorId()
                            + (result.productId() == null ? "" : (" productId=" + result.productId()))
                            + " affectedSoftware=" + result.affectedSoftwareRows()
                            + " status=" + result.status()
                            + " | vendorAlias=" + result.vendorAliasOutcome()
                            + " productAlias=" + result.productAliasOutcome()
            );
        } catch (Exception e) {
            ra.addFlashAttribute("error", "Apply failed: " + safeMsg(e));
        }

        return "redirect:/admin/unresolved" + redirectQuery(status, runId, active, true, id);
    }

    /**
     * Checkbox behavior:
     *
     * - When checked, activeOnly=true is sent.
     * - When unchecked, activeOnly is not sent at all.
     *
     * To distinguish this, the form always sends activeOnlyPresent=1.
     * If activeOnlyPresent exists but activeOnly is missing,
     * it means the checkbox was unchecked.
     */
    private static boolean effectiveActiveOnly(Boolean activeOnly, String activeOnlyPresent) {
        // Initial access (no activeOnlyPresent): default true
        if (activeOnlyPresent == null) {
            return (activeOnly == null) ? true : activeOnly;
        }

        // After filter submit: missing activeOnly means unchecked
        return Boolean.TRUE.equals(activeOnly);
    }

    private static String redirectQuery(
            String status,
            Long runId,
            boolean activeOnly,
            boolean includeActiveOnlyPresent,
            Long id
    ) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;

        if (status != null && !status.isBlank()) {
            sb.append(first ? "?" : "&").append("status=").append(url(status));
            first = false;
        }
        if (runId != null) {
            sb.append(first ? "?" : "&").append("runId=").append(runId);
            first = false;
        }
        if (id != null) {
            sb.append(first ? "?" : "&").append("id=").append(id);
            first = false;
        }

        // Always explicitly include activeOnly to avoid state drift
        sb.append(first ? "?" : "&").append("activeOnly=").append(activeOnly);
        first = false;

        // Including this keeps filter state stable after redirect
        if (includeActiveOnlyPresent) {
            sb.append(first ? "?" : "&").append("activeOnlyPresent=1");
        }

        return sb.toString();
    }

    private static String url(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static Long parseLongNullable(String s) {
        if (s == null) return null;
        String t = s.trim();
        if (t.isEmpty()) return null;
        try {
            return Long.parseLong(t);
        } catch (Exception e) {
            return null;
        }
    }

    private static Long parseLong(String s) {
        return parseLongNullable(s);
    }

    private static String safeMsg(Exception e) {
        String m = e.getMessage();
        if (m == null || m.isBlank()) return e.getClass().getSimpleName();
        return m;
    }

    @PostMapping("/admin/unresolved/quick-add")
    public String quickAddAndApply(
            @RequestParam("mappingId") String mappingIdRaw,
            @RequestParam(name = "cpeVendorId", required = false) String cpeVendorIdRaw,
            @RequestParam(name = "cpeProductId", required = false) String cpeProductIdRaw,
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "runId", required = false) Long runId,
            @RequestParam(name = "activeOnly", required = false) Boolean activeOnly,
            @RequestParam(name = "activeOnlyPresent", required = false) String activeOnlyPresent,
            @RequestParam(name = "id", required = false) Long id,
            RedirectAttributes ra
    ) {
        Long mappingId = parseLong(mappingIdRaw);
        Long vendorId = parseLongNullable(cpeVendorIdRaw);
        Long productId = parseLongNullable(cpeProductIdRaw);

        boolean active = effectiveActiveOnly(activeOnly, activeOnlyPresent);

        if (mappingId == null) {
            ra.addFlashAttribute("error", "Invalid mappingId.");
            return "redirect:/admin/unresolved" + redirectQuery(status, runId, active, true, id);
        }
        if (vendorId == null) {
            ra.addFlashAttribute("error", "Vendor ID is required. Please select from candidates.");
            return "redirect:/admin/unresolved" + redirectQuery(status, runId, active, true, id);
        }

        try {
            var result = unresolvedQuickAddService.quickAddAndApply(mappingId, vendorId, productId);

            ra.addFlashAttribute("success",
                    "QuickAdd+Applied: mappingId=" + result.apply().mappingId()
                            + " vendorId=" + result.apply().vendorId()
                            + (result.apply().productId() == null ? "" : (" productId=" + result.apply().productId()))
                            + " affectedSoftware=" + result.apply().affectedSoftwareRows()
                            + " status=" + result.apply().status()
                            + " | vendorAlias=" + result.vendorAliasOutcome()
                            + " productAlias=" + result.productAliasOutcome()
            );
        } catch (Exception e) {
            ra.addFlashAttribute("error", "QuickAdd failed: " + safeMsg(e));
        }

        return "redirect:/admin/unresolved" + redirectQuery(status, runId, active, true, id);
    }
}