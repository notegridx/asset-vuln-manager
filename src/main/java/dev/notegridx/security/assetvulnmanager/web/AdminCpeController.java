package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.service.AdminCpeSyncService;
import dev.notegridx.security.assetvulnmanager.service.AdminJobAlreadyRunningException;
import dev.notegridx.security.assetvulnmanager.service.CpeFeedSyncService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

@Controller
public class AdminCpeController {

    private final CpeFeedSyncService cpeFeedSyncService;
    private final AdminCpeSyncService adminCpeSyncService;

    public AdminCpeController(CpeFeedSyncService cpeFeedSyncService,
                              AdminCpeSyncService adminCpeSyncService) {
        this.cpeFeedSyncService = cpeFeedSyncService;
        this.adminCpeSyncService = adminCpeSyncService;
    }

    @GetMapping("/admin/cpe/sync")
    public String view() {
        return "admin/cpe_sync";
    }

    @PostMapping("/admin/cpe/sync")
    public String run(
            @RequestParam(name = "force", defaultValue = "false") boolean force,
            @RequestParam(name = "maxItems", defaultValue = "2000000") int maxItems,
            Model model
    ) throws IOException {

        try {
            var result = adminCpeSyncService.runSync(force, maxItems);
            model.addAttribute("result", result);

        } catch (AdminJobAlreadyRunningException ex) {
            model.addAttribute("error", ex.getMessage());
        }

        model.addAttribute("force", force);
        model.addAttribute("maxItems", maxItems);

        return "admin/cpe_sync";
    }
}