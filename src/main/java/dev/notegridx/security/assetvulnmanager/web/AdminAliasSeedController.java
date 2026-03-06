package dev.notegridx.security.assetvulnmanager.web;

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

    public AdminAliasSeedController(
            AliasSeedImportService seedImportService,
            SynonymService synonymService
    ) {
        this.seedImportService = seedImportService;
        this.synonymService = synonymService;
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
        var report = seedImportService.importFromJson(json);

        // seed 投入直後に解決へ反映（キャッシュがあるなら必須）
        synonymService.clearCaches();

        model.addAttribute("json", json);
        model.addAttribute("result", report);
        return "admin/aliases_seed_import";
    }
}