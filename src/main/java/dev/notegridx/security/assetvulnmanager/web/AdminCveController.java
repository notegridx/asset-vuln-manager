package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.infra.nvd.NvdCveFeedClient;
import dev.notegridx.security.assetvulnmanager.service.CveFeedSyncService;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

@Controller
public class AdminCveController {

    private final CveFeedSyncService cveFeedSyncService;

    public AdminCveController(CveFeedSyncService cveFeedSyncService) {
        this.cveFeedSyncService = cveFeedSyncService;
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

        // YEARのときはyear必須
        if (k == NvdCveFeedClient.FeedKind.YEAR && year == null) {
            model.addAttribute("kind", kind);
            model.addAttribute("year", null);
            model.addAttribute("force", force);
            model.addAttribute("maxItems", maxItems);
            model.addAttribute("error", "Year is required when selecting YEAR feed.");
            return "admin/cve_sync";
        }

        var result = cveFeedSyncService.sync(k, year, force, maxItems);

        model.addAttribute("kind", k.name());
        model.addAttribute("year", year);
        model.addAttribute("force", force);
        model.addAttribute("maxItems", maxItems);
        model.addAttribute("result", result);
        return "admin/cve_sync";
    }

}