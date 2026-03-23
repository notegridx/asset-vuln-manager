package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.service.DemoModeService;
import dev.notegridx.security.assetvulnmanager.service.SynonymService;
import dev.notegridx.security.assetvulnmanager.service.seed.AliasSeedImportService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AdminAliasSeedController {

    private final AliasSeedImportService seedImportService;
    private final SynonymService synonymService;
    private final DemoModeService demoModeService;

    public AdminAliasSeedController(
            AliasSeedImportService seedImportService,
            SynonymService synonymService,
            DemoModeService demoModeService
    ) {
        this.seedImportService = seedImportService;
        this.synonymService = synonymService;
        this.demoModeService = demoModeService;
    }

    @GetMapping("/admin/aliases/seed/import")
    public String form(Model model) {
        model.addAttribute("json", "");
        return "admin/aliases_seed_import";
    }

    @PostMapping("/admin/aliases/seed/import")
    public String run(
            @RequestParam("json") String json,
            Model model
    ) {
        demoModeService.assertWritable();

        var report = seedImportService.importFromJson(json);

        synonymService.clearCaches();

        model.addAttribute("json", json);
        model.addAttribute("result", report);
        return "admin/aliases_seed_import";
    }
}