package dev.notegridx.security.assetvulnmanager.web;

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

    public AdminCpeController(CpeFeedSyncService cpeFeedSyncService) {
        this.cpeFeedSyncService = cpeFeedSyncService;
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

        var result = cpeFeedSyncService.sync(force, maxItems);
        model.addAttribute("result", result);
        model.addAttribute("force", force);
        model.addAttribute("maxItems", maxItems);
        return "admin/cpe_sync";
    }
}
