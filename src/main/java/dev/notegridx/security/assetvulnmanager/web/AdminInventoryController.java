package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.ImportRun;
import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;
import dev.notegridx.security.assetvulnmanager.repository.ImportRunRepository;
import dev.notegridx.security.assetvulnmanager.repository.UnresolvedMappingRepository;
import dev.notegridx.security.assetvulnmanager.service.UnresolvedResolutionService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@Controller
public class AdminInventoryController {

    private final ImportRunRepository importRunRepository;
    private final UnresolvedMappingRepository unresolvedMappingRepository;
    private final UnresolvedResolutionService unresolvedResolutionService;

    public AdminInventoryController(
            ImportRunRepository importRunRepository,
            UnresolvedMappingRepository unresolvedMappingRepository,
            UnresolvedResolutionService unresolvedResolutionService
    ) {
        this.importRunRepository = importRunRepository;
        this.unresolvedMappingRepository = unresolvedMappingRepository;
        this.unresolvedResolutionService = unresolvedResolutionService;
    }

    @GetMapping("/admin/import-runs")
    public String importRuns(Model model) {
        List<ImportRun> runs = importRunRepository.findAll();
        runs.sort((a, b) -> {
            if (a.getId() == null && b.getId() == null) return 0;
            if (a.getId() == null) return 1;
            if (b.getId() == null) return -1;
            return Long.compare(b.getId(), a.getId());
        });

        model.addAttribute("runs", runs);
        return "admin/import_runs";
    }

    @GetMapping("/admin/unresolved")
    public String unresolved(
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "runId", required = false) Long runId,
            @RequestParam(name = "activeOnly", required = false) Boolean activeOnly,
            Model model
    ) {
        // default: true
        boolean active = (activeOnly == null) ? true : activeOnly;

        List<UnresolvedMapping> list = active
                ? unresolvedMappingRepository.findAllActive()
                : unresolvedMappingRepository.findAll();

        if (status != null && !status.isBlank()) {
            String s = status.trim();
            list.removeIf(m -> m.getStatus() == null || !m.getStatus().equalsIgnoreCase(s));
        }

        // NOTE: runId filtering is not implemented in the current code base,
        // so keep behavior consistent (the UI passes runId for future extension).
        // If you want, we can later add repo-level filtering by runId once data model is confirmed.

        list.sort((a, b) -> {
            if (a.getId() == null && b.getId() == null) return 0;
            if (a.getId() == null) return 1;
            if (b.getId() == null) return -1;
            return Long.compare(b.getId(), a.getId());
        });

        model.addAttribute("mappings", list);
        model.addAttribute("status", (status == null || status.isBlank()) ? null : status.trim().toUpperCase());
        model.addAttribute("runId", runId);
        model.addAttribute("activeOnly", active);
        return "admin/unresolved";
    }

    // =========================================================
    // Apply resolution (NO 400 on parse failure)
    // =========================================================

    @PostMapping("/admin/unresolved/apply")
    public String applyUnresolved(
            @RequestParam("mappingId") String mappingIdRaw,
            @RequestParam(name = "cpeVendorId", required = false) String cpeVendorIdRaw,
            @RequestParam(name = "cpeProductId", required = false) String cpeProductIdRaw,
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "runId", required = false) Long runId,
            @RequestParam(name = "activeOnly", required = false) Boolean activeOnly,
            RedirectAttributes ra
    ) {
        Long mappingId = parseLong(mappingIdRaw);
        Long vendorId = parseLongNullable(cpeVendorIdRaw);
        Long productId = parseLongNullable(cpeProductIdRaw);

        boolean active = (activeOnly == null) ? true : activeOnly;

        if (mappingId == null) {
            ra.addFlashAttribute("error", "Invalid mappingId.");
            return "redirect:/admin/unresolved" + redirectQuery(status, runId, active);
        }
        if (vendorId == null) {
            ra.addFlashAttribute("error", "Vendor ID is required. Please select from candidates (chips).");
            return "redirect:/admin/unresolved" + redirectQuery(status, runId, active);
        }

        try {
            var result = unresolvedResolutionService.apply(mappingId, vendorId, productId);
            ra.addFlashAttribute("success",
                    "Applied: mappingId=" + result.mappingId()
                            + " vendorId=" + result.vendorId()
                            + (result.productId() == null ? "" : (" productId=" + result.productId()))
                            + " → affectedSoftware=" + result.affectedSoftwareRows()
                            + " status=" + result.status()
            );
        } catch (Exception e) {
            ra.addFlashAttribute("error", "Apply failed: " + safeMsg(e));
        }

        return "redirect:/admin/unresolved" + redirectQuery(status, runId, active);
    }

    private static String redirectQuery(String status, Long runId, boolean activeOnly) {
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
        // Always keep it explicit, so reloads/redirects are stable.
        sb.append(first ? "?" : "&").append("activeOnly=").append(activeOnly);

        return sb.toString();
    }

    private static String url(String s) {
        // minimal (safe enough for status like NEW/RESOLVED)
        return s.replace(" ", "%20");
    }

    private static Long parseLong(String s) {
        if (s == null) return null;
        String t = s.trim();
        if (t.isEmpty()) return null;
        try {
            return Long.parseLong(t);
        } catch (Exception e) {
            return null;
        }
    }

    private static Long parseLongNullable(String s) {
        if (s == null) return null;
        String t = s.trim();
        if (t.isEmpty()) return null;
        // 数字以外が入った場合は null 扱いにして 400 を出さない
        try {
            return Long.parseLong(t);
        } catch (Exception e) {
            return null;
        }
    }

    private static String safeMsg(Throwable t) {
        String m = t.getMessage();
        return (m == null) ? t.getClass().getSimpleName() : m;
    }
}