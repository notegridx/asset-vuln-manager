package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.infra.nvd.NvdCveFeedClient;
import dev.notegridx.security.assetvulnmanager.service.AdminCveFeedSyncService;
import dev.notegridx.security.assetvulnmanager.service.AdminJobAlreadyRunningException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

@Controller
public class AdminCveController {

    private final AdminCveFeedSyncService adminCveFeedSyncService;

    public AdminCveController(AdminCveFeedSyncService adminCveFeedSyncService) {
        this.adminCveFeedSyncService = adminCveFeedSyncService;
    }

    @GetMapping("/admin/cve/sync")
    public String view() {
        return "admin/cve_sync";
    }

    @PostMapping("/admin/cve/sync")
    public String run(
            @RequestParam(name = "kind", defaultValue = "MODIFIED") String kind,
            @RequestParam(name = "year", required = false) Integer year,
            @RequestParam(name = "force", defaultValue = "false") boolean force,
            @RequestParam(name = "maxItems", defaultValue = "2000000") int maxItems,
            Model model
    ) throws IOException {

        NvdCveFeedClient.FeedKind k;
        try {
            k = NvdCveFeedClient.FeedKind.valueOf(kind.trim().toUpperCase());
        } catch (Exception e) {
            k = NvdCveFeedClient.FeedKind.MODIFIED;
        }

        model.addAttribute("kind", k.name());
        model.addAttribute("year", year);
        model.addAttribute("force", force);
        model.addAttribute("maxItems", maxItems);

        if (k == NvdCveFeedClient.FeedKind.YEAR && year == null) {
            model.addAttribute("error", "Year is required when selecting YEAR feed.");
            return "admin/cve_sync";
        }

        try {
            var result = adminCveFeedSyncService.runSync(k, year, force, maxItems);
            model.addAttribute("result", result);
        } catch (AdminJobAlreadyRunningException ex) {
            model.addAttribute("error", ex.getMessage());
        }

        return "admin/cve_sync";
    }
}