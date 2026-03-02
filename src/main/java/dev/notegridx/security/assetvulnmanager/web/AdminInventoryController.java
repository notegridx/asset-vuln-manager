package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.ImportRun;
import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;
import dev.notegridx.security.assetvulnmanager.repository.ImportRunRepository;
import dev.notegridx.security.assetvulnmanager.repository.UnresolvedMappingRepository;
import dev.notegridx.security.assetvulnmanager.service.UnresolvedResolutionService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
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
            // ★ unchecked のとき activeOnly が飛んでこない問題を判定するフラグ
            @RequestParam(name = "activeOnlyPresent", required = false) String activeOnlyPresent,
            Model model
    ) {
        boolean active = effectiveActiveOnly(activeOnly, activeOnlyPresent);

        List<UnresolvedMapping> list = active
                ? unresolvedMappingRepository.findAllActive()
                : unresolvedMappingRepository.findAll();

        if (status != null && !status.isBlank()) {
            String s = status.trim();
            list.removeIf(m -> m.getStatus() == null || !m.getStatus().equalsIgnoreCase(s));
        }

        // NOTE: runId filtering is not implemented in the current code base.
        // Keep runId as "UI state" only (passes through).
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

        // hidden input の値固定に使う（未使用でもOKだが置いとくとデバッグしやすい）
        model.addAttribute("activeOnlyPresent", activeOnlyPresent);

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
            // ここは未送信でも redirectQuery が activeOnly を必ず付けるので実害なし
            @RequestParam(name = "activeOnlyPresent", required = false) String activeOnlyPresent,
            RedirectAttributes ra
    ) {
        Long mappingId = parseLong(mappingIdRaw);
        Long vendorId = parseLongNullable(cpeVendorIdRaw);
        Long productId = parseLongNullable(cpeProductIdRaw);

        boolean active = effectiveActiveOnly(activeOnly, activeOnlyPresent);

        if (mappingId == null) {
            ra.addFlashAttribute("error", "Invalid mappingId.");
            return "redirect:/admin/unresolved" + redirectQuery(status, runId, active, true);
        }
        if (vendorId == null) {
            ra.addFlashAttribute("error", "Vendor ID is required. Please select from candidates (chips).");
            return "redirect:/admin/unresolved" + redirectQuery(status, runId, active, true);
        }

        try {
            var result = unresolvedResolutionService.apply(mappingId, vendorId, productId); // :contentReference[oaicite:1]{index=1}
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

        return "redirect:/admin/unresolved" + redirectQuery(status, runId, active, true);
    }

    /**
     * checkbox の仕様：
     * - checked の時だけ activeOnly=true が飛ぶ
     * - unchecked の時は activeOnly 自体が飛ばない
     *
     * そこで、form側で activeOnlyPresent=1 を常に送るようにして、
     * 「Filter押下の結果 activeOnly が無い」= unchecked と判断する。
     */
    private static boolean effectiveActiveOnly(Boolean activeOnly, String activeOnlyPresent) {
        // 初回アクセス（activeOnlyPresent が無い）ではデフォルト true
        if (activeOnlyPresent == null) {
            return (activeOnly == null) ? true : activeOnly;
        }
        // Filter 押下（activeOnlyPresent がある）では
        // activeOnly が null なら unchecked 扱い（false）
        return Boolean.TRUE.equals(activeOnly);
    }

    private static String redirectQuery(String status, Long runId, boolean activeOnly, boolean includeActiveOnlyPresent) {
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

        // redirect 後も状態がブレないように常に明示
        sb.append(first ? "?" : "&").append("activeOnly=").append(activeOnly);
        first = false;

        // Filterフォームの設計に合わせて、付けておくと次のGETでも判定が安定する
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
}