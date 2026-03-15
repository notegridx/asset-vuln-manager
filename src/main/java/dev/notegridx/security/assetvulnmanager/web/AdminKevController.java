package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import dev.notegridx.security.assetvulnmanager.service.AdminJobAlreadyRunningException;
import dev.notegridx.security.assetvulnmanager.service.AdminKevSyncService;
import dev.notegridx.security.assetvulnmanager.service.AdminRunReadService;
import dev.notegridx.security.assetvulnmanager.service.KevSyncService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AdminKevController {

    private final AdminKevSyncService adminKevSyncService;
    private final AdminRunReadService adminRunReadService;

    public AdminKevController(
            AdminKevSyncService adminKevSyncService,
            AdminRunReadService adminRunReadService
    ) {
        this.adminKevSyncService = adminKevSyncService;
        this.adminRunReadService = adminRunReadService;
    }

    @GetMapping("/admin/kev/sync")
    public String page(Model model) {
        bindLastRun(model);

        model.addAttribute("force", false);
        model.addAttribute("maxItems", 50000);

        return "admin/kev_sync";
    }

    @PostMapping("/admin/kev/sync")
    public String run(
            @RequestParam(name = "force", defaultValue = "false") boolean force,
            @RequestParam(name = "maxItems", defaultValue = "50000") int maxItems,
            Model model
    ) {
        try {
            KevSyncService.SyncResult result = adminKevSyncService.run(force, maxItems);
            model.addAttribute("result", result);
        } catch (AdminJobAlreadyRunningException ex) {
            model.addAttribute("error", ex.getMessage());
        }

        bindLastRun(model);

        model.addAttribute("force", force);
        model.addAttribute("maxItems", maxItems);

        return "admin/kev_sync";
    }

    private void bindLastRun(Model model) {
        AdminRunReadService.LastRunView last = adminRunReadService.findLastRun(
                AdminJobType.KEV_SYNC,
                AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW
        );

        if (last == null) {
            model.addAttribute("lastRun", null);
            model.addAttribute("lastParams", null);
            model.addAttribute("lastResult", null);
            return;
        }

        model.addAttribute("lastRun", last.run());
        model.addAttribute("lastParams", last.params());
        model.addAttribute("lastResult", last.result());
    }
}