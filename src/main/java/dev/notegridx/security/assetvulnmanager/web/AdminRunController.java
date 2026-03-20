package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.service.AdminRunReadService;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Controller
public class AdminRunController {

    private static final int DEFAULT_SIZE = 50;
    private static final int MAX_SIZE = 200;
    private static final int DEFAULT_RECENT_LIMIT = 200;

    private final AdminRunReadService adminRunReadService;

    public AdminRunController(AdminRunReadService adminRunReadService) {
        this.adminRunReadService = adminRunReadService;
    }

    @GetMapping("/admin/runs")
    public String runs(
            @RequestParam(name = "jobType", required = false) String jobType,
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "q", required = false) String q,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", required = false) Integer size,
            Model model
    ) {
        String normalizedJobType = normalize(jobType);
        String normalizedStatus = normalize(status);
        String normalizedQ = normalize(q);

        boolean filtering =
                normalizedJobType != null ||
                        normalizedStatus != null ||
                        normalizedQ != null ||
                        page > 0 ||
                        size != null;

        int safePage = Math.max(page, 0);
        int safeSize = normalizeSize(size);

        if (!filtering) {
            List<AdminRunReadService.AdminRunRow> runs = adminRunReadService.findRecentRuns(DEFAULT_RECENT_LIMIT);

            model.addAttribute("runs", runs);
            model.addAttribute("jobType", null);
            model.addAttribute("status", null);
            model.addAttribute("q", null);
            model.addAttribute("page", 0);
            model.addAttribute("size", DEFAULT_SIZE);
            model.addAttribute("totalElements", runs.size());
            model.addAttribute("totalPages", 1);
            model.addAttribute("hasPrevious", false);
            model.addAttribute("hasNext", false);

            return "admin/runs";
        }

        Page<AdminRunReadService.AdminRunRow> runsPage =
                adminRunReadService.searchRuns(normalizedJobType, normalizedStatus, normalizedQ, safePage, safeSize);

        model.addAttribute("runs", runsPage.getContent());
        model.addAttribute("jobType", normalizedJobType);
        model.addAttribute("status", normalizedStatus);
        model.addAttribute("q", normalizedQ);
        model.addAttribute("page", runsPage.getNumber());
        model.addAttribute("size", runsPage.getSize());
        model.addAttribute("totalElements", runsPage.getTotalElements());
        model.addAttribute("totalPages", runsPage.getTotalPages());
        model.addAttribute("hasPrevious", runsPage.hasPrevious());
        model.addAttribute("hasNext", runsPage.hasNext());

        return "admin/runs";
    }

    private static int normalizeSize(Integer size) {
        if (size == null || size <= 0) {
            return DEFAULT_SIZE;
        }
        return Math.min(size, MAX_SIZE);
    }

    private static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}