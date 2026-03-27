package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.service.AdminInventoryReadService;
import dev.notegridx.security.assetvulnmanager.service.DemoModeService;
import dev.notegridx.security.assetvulnmanager.service.UnresolvedQuickAddService;
import dev.notegridx.security.assetvulnmanager.service.UnresolvedResolutionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
    private final UnresolvedResolutionService unresolvedResolutionService;
    private final UnresolvedQuickAddService unresolvedQuickAddService;
    private final DemoModeService demoModeService;

    public AdminInventoryController(
            AdminInventoryReadService adminInventoryReadService,
            UnresolvedResolutionService unresolvedResolutionService,
            UnresolvedQuickAddService unresolvedQuickAddService,
            DemoModeService demoModeService
    ) {
        this.adminInventoryReadService = adminInventoryReadService;
        this.unresolvedResolutionService = unresolvedResolutionService;
        this.unresolvedQuickAddService = unresolvedQuickAddService;
        this.demoModeService = demoModeService;
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
            @RequestParam(name = "q", required = false) String q,
            @RequestParam(name = "activeOnly", required = false) Boolean activeOnly,
            @RequestParam(name = "activeOnlyPresent", required = false) String activeOnlyPresent,
            @RequestParam(name = "id", required = false) Long id,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "50") int size,
            Model model
    ) {
        String effectiveStatus = (status == null || status.isBlank()) ? "all" : status;

        var view = adminInventoryReadService.findUnresolvedMappings(
                effectiveStatus,
                runId,
                q,
                null,
                null,
                id,
                page,
                size
        );

        model.addAttribute("mappings", view.mappings());
        model.addAttribute("status", view.status());
        model.addAttribute("runId", view.runId());
        model.addAttribute("q", view.q());
        model.addAttribute("activeOnly", null);
        model.addAttribute("activeOnlyPresent", null);
        model.addAttribute("id", view.id());

        model.addAttribute("page", view.pageNumber());
        model.addAttribute("size", view.pageSize());
        model.addAttribute("totalPages", view.totalPages());
        model.addAttribute("totalElements", view.totalElements());
        model.addAttribute("pagerItems", view.pagerItems());

        return "admin/unresolved";
    }

    @PostMapping("/admin/unresolved/apply")
    public Object applyUnresolved(
            @RequestParam("mappingId") String mappingIdRaw,
            @RequestParam(name = "cpeVendorId", required = false) String cpeVendorIdRaw,
            @RequestParam(name = "cpeProductId", required = false) String cpeProductIdRaw,
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "runId", required = false) Long runId,
            @RequestParam(name = "q", required = false) String q,
            @RequestParam(name = "activeOnly", required = false) Boolean activeOnly,
            @RequestParam(name = "activeOnlyPresent", required = false) String activeOnlyPresent,
            @RequestParam(name = "id", required = false) Long id,
            RedirectAttributes ra,
            HttpServletRequest request,
            Model model
    ) {
        demoModeService.assertWritable();

        Long mappingId = parseLong(mappingIdRaw);
        Long vendorId = parseLongNullable(cpeVendorIdRaw);
        Long productId = parseLongNullable(cpeProductIdRaw);

        boolean htmx = isHtmx(request);

        if (mappingId == null) {
            if (htmx) {
                return htmxError("Invalid mappingId.");
            }
            ra.addFlashAttribute("error", "Invalid mappingId.");
            return "redirect:/admin/unresolved" + redirectQuery(status, runId, q, id);
        }

        if (vendorId == null) {
            if (htmx) {
                return htmxError("Vendor ID is required. Please select from candidates (chips).");
            }
            ra.addFlashAttribute("error", "Vendor ID is required. Please select from candidates (chips).");
            return "redirect:/admin/unresolved" + redirectQuery(status, runId, q, id);
        }

        try {
            var result = unresolvedResolutionService.apply(mappingId, vendorId, productId);

            String successMessage =
                    "Applied: mappingId=" + result.mappingId()
                            + " vendorId=" + result.vendorId()
                            + (result.productId() == null ? "" : (" productId=" + result.productId()))
                            + " affectedSoftware=" + result.affectedSoftwareRows()
                            + " status=" + result.status()
                            + " | vendorAlias=" + result.vendorAliasOutcome()
                            + " productAlias=" + result.productAliasOutcome();

            if (htmx) {
                return buildHtmxSuccessResponse(
                        mappingId,
                        status,
                        runId,
                        q,
                        id,
                        successMessage,
                        model
                );
            }

            ra.addFlashAttribute("success", successMessage);
        } catch (Exception e) {
            String errorMessage = "Apply failed: " + safeMsg(e);

            if (htmx) {
                return htmxError(errorMessage);
            }

            ra.addFlashAttribute("error", errorMessage);
        }

        return "redirect:/admin/unresolved" + redirectQuery(status, runId, q, id);
    }

    private static String redirectQuery(
            String status,
            Long runId,
            String q,
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
        if (q != null && !q.isBlank()) {
            sb.append(first ? "?" : "&").append("q=").append(url(q));
            first = false;
        }
        if (id != null) {
            sb.append(first ? "?" : "&").append("id=").append(id);
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
    public Object quickAddAndApply(
            @RequestParam("mappingId") String mappingIdRaw,
            @RequestParam(name = "cpeVendorId", required = false) String cpeVendorIdRaw,
            @RequestParam(name = "cpeProductId", required = false) String cpeProductIdRaw,
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "runId", required = false) Long runId,
            @RequestParam(name = "q", required = false) String q,
            @RequestParam(name = "activeOnly", required = false) Boolean activeOnly,
            @RequestParam(name = "activeOnlyPresent", required = false) String activeOnlyPresent,
            @RequestParam(name = "id", required = false) Long id,
            RedirectAttributes ra,
            HttpServletRequest request,
            Model model
    ) {
        demoModeService.assertWritable();

        Long mappingId = parseLong(mappingIdRaw);
        Long vendorId = parseLongNullable(cpeVendorIdRaw);
        Long productId = parseLongNullable(cpeProductIdRaw);

        boolean htmx = isHtmx(request);

        if (mappingId == null) {
            if (htmx) {
                return htmxError("Invalid mappingId.");
            }
            ra.addFlashAttribute("error", "Invalid mappingId.");
            return "redirect:/admin/unresolved" + redirectQuery(status, runId, q, id);
        }

        if (vendorId == null) {
            if (htmx) {
                return htmxError("Vendor ID is required. Please select from candidates.");
            }
            ra.addFlashAttribute("error", "Vendor ID is required. Please select from candidates.");
            return "redirect:/admin/unresolved" + redirectQuery(status, runId, q, id);
        }

        try {
            var result = unresolvedQuickAddService.quickAddAndApply(mappingId, vendorId, productId);

            String successMessage =
                    "QuickAdd+Applied: mappingId=" + result.apply().mappingId()
                            + " vendorId=" + result.apply().vendorId()
                            + (result.apply().productId() == null ? "" : (" productId=" + result.apply().productId()))
                            + " affectedSoftware=" + result.apply().affectedSoftwareRows()
                            + " status=" + result.apply().status()
                            + " | vendorAlias=" + result.vendorAliasOutcome()
                            + " productAlias=" + result.productAliasOutcome();

            if (htmx) {
                return buildHtmxSuccessResponse(
                        mappingId,
                        status,
                        runId,
                        q,
                        id,
                        successMessage,
                        model
                );
            }

            ra.addFlashAttribute("success", successMessage);
        } catch (Exception e) {
            String errorMessage = "QuickAdd failed: " + safeMsg(e);

            if (htmx) {
                return htmxError(errorMessage);
            }

            ra.addFlashAttribute("error", errorMessage);
        }

        return "redirect:/admin/unresolved" + redirectQuery(status, runId, q, id);
    }

    private Object buildHtmxSuccessResponse(
            Long mappingId,
            String status,
            Long runId,
            String q,
            Long id,
            String successMessage,
            Model model
    ) {
        if (shouldRemoveRowForHtmx(status)) {
            return htmxSuccess(successMessage);
        }

        var rowView = adminInventoryReadService.findUnresolvedMappings(
                status,
                runId,
                q,
                null,
                null,
                mappingId,
                0,
                1
        );

        if (rowView.mappings().isEmpty()) {
            return htmxSuccess(successMessage);
        }

        model.addAttribute("r", rowView.mappings().get(0));
        model.addAttribute("status", rowView.status());
        model.addAttribute("runId", rowView.runId());
        model.addAttribute("q", rowView.q());
        model.addAttribute("activeOnly", null);
        model.addAttribute("activeOnlyPresent", null);
        model.addAttribute("id", rowView.id());

        return "admin/fragments/unresolved_row :: row";
    }

    private static boolean shouldRemoveRowForHtmx(String status) {
        return "NEW".equalsIgnoreCase(trimToEmpty(status));
    }

    private static boolean isHtmx(HttpServletRequest request) {
        String hxRequest = request.getHeader("HX-Request");
        return hxRequest != null && "true".equalsIgnoreCase(hxRequest);
    }

    /**
     * Return an empty body for hx-target + outerHTML replacement so the resolved row disappears
     * only when the current filter is NEW.
     */
    private static ResponseEntity<String> htmxSuccess(String message) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("HX-Trigger", "{\"unresolvedApplySuccess\":{\"message\":\"" + escapeJson(message) + "\"}}");
        return new ResponseEntity<>("", headers, HttpStatus.OK);
    }

    /**
     * Preserve non-HTMX redirect behavior, but let HTMX callers handle errors without a full reload.
     * The current row remains unchanged because the response is an error status.
     */
    private static ResponseEntity<String> htmxError(String message) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("HX-Trigger", "{\"unresolvedApplyError\":{\"message\":\"" + escapeJson(message) + "\"}}");
        return new ResponseEntity<>("", headers, HttpStatus.BAD_REQUEST);
    }

    private static String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        return s
                .replace("\\", "\\\\")
                .replace("\"", "\\\"");
    }

    private static String trimToEmpty(String s) {
        return s == null ? "" : s.trim();
    }
}