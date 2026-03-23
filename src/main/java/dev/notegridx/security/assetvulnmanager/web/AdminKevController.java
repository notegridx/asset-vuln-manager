package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import dev.notegridx.security.assetvulnmanager.service.AdminJobAlreadyRunningException;
import dev.notegridx.security.assetvulnmanager.service.AdminKevSyncService;
import dev.notegridx.security.assetvulnmanager.service.AdminRunReadService;
import dev.notegridx.security.assetvulnmanager.service.DemoModeService;
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
    private final DemoModeService demoModeService;

    public AdminKevController(
            AdminKevSyncService adminKevSyncService,
            AdminRunReadService adminRunReadService,
            DemoModeService demoModeService
    ) {
        this.adminKevSyncService = adminKevSyncService;
        this.adminRunReadService = adminRunReadService;
        this.demoModeService = demoModeService;
    }

    @GetMapping("/admin/kev/sync")
    public String page(Model model) {
        adminRunReadService.bindLastRun(
                model,
                AdminJobType.KEV_SYNC,
                AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW
        );

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
        demoModeService.assertWritable();

        try {
            KevSyncService.SyncResult result = adminKevSyncService.run(force, maxItems);
            model.addAttribute("result", result);
        } catch (AdminJobAlreadyRunningException ex) {
            model.addAttribute("error", ex.getMessage());
        }

        adminRunReadService.bindLastRun(
                model,
                AdminJobType.KEV_SYNC,
                AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW
        );

        model.addAttribute("force", force);
        model.addAttribute("maxItems", maxItems);

        return "admin/kev_sync";
    }
}