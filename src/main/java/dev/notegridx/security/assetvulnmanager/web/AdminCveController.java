package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import dev.notegridx.security.assetvulnmanager.infra.nvd.NvdCveFeedClient;
import dev.notegridx.security.assetvulnmanager.service.AdminCveFeedSyncService;
import dev.notegridx.security.assetvulnmanager.service.AdminJobAlreadyRunningException;
import dev.notegridx.security.assetvulnmanager.service.AdminRunReadService;
import dev.notegridx.security.assetvulnmanager.service.DemoModeService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

@Controller
public class AdminCveController {

    private final AdminCveFeedSyncService adminCveFeedSyncService;
    private final AdminRunReadService adminRunReadService;
    private final DemoModeService demoModeService;

    public AdminCveController(
            AdminCveFeedSyncService adminCveFeedSyncService,
            AdminRunReadService adminRunReadService,
            DemoModeService demoModeService
    ) {
        this.adminCveFeedSyncService = adminCveFeedSyncService;
        this.adminRunReadService = adminRunReadService;
        this.demoModeService = demoModeService;
    }

    @GetMapping("/admin/cve/sync")
    public String view(Model model) {
        adminRunReadService.bindLastRun(
                model,
                AdminJobType.CVE_FEED_SYNC,
                AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW
        );

        model.addAttribute("kind", NvdCveFeedClient.FeedKind.MODIFIED.name());
        model.addAttribute("year", null);
        model.addAttribute("force", false);
        model.addAttribute("maxItems", 2_000_000);

        return "admin/cve_sync";
    }

    @PostMapping("/admin/cve/sync")
    public String run(
            @RequestParam(name = "kind", defaultValue = "MODIFIED") String kind,
            @RequestParam(name = "year", required = false) Integer year,
            @RequestParam(name = "force", defaultValue = "false") boolean force,
            @RequestParam(name = "maxItems", defaultValue = "2000000") int maxItems,
            Model model
    ) {

        demoModeService.assertWritable();

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

        if (k == NvdCveFeedClient.FeedKind.YEAR) {
            if (year == null) {
                adminRunReadService.bindLastRun(
                        model,
                        AdminJobType.CVE_FEED_SYNC,
                        AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW
                );
                model.addAttribute("error", "Year is required when selecting YEAR feed.");
                return "admin/cve_sync";
            }

            if (year < 2002) {
                adminRunReadService.bindLastRun(
                        model,
                        AdminJobType.CVE_FEED_SYNC,
                        AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW
                );
                model.addAttribute(
                        "error",
                        "Selected YEAR feed is out of range. Enter a year of 2002 or later."
                );
                return "admin/cve_sync";
            }
        }

        try {
            var result = adminCveFeedSyncService.runSync(k, year, force, maxItems);
            model.addAttribute("result", result);
        } catch (AdminJobAlreadyRunningException ex) {
            model.addAttribute("error", ex.getMessage());
        } catch (IOException ex) {
            if (k == NvdCveFeedClient.FeedKind.YEAR && year != null) {
                model.addAttribute("error", "No CVE feed is available for the selected year: " + year);
            } else {
                model.addAttribute("error", ex.getMessage());
            }
        }

        adminRunReadService.bindLastRun(
                model,
                AdminJobType.CVE_FEED_SYNC,
                AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW
        );
        return "admin/cve_sync";
    }
}