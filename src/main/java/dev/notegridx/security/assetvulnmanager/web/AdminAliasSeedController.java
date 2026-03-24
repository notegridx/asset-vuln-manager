package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.service.DemoModeService;
import dev.notegridx.security.assetvulnmanager.service.SynonymService;
import dev.notegridx.security.assetvulnmanager.service.seed.AliasSeedExportService;
import dev.notegridx.security.assetvulnmanager.service.seed.AliasSeedImportService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.nio.charset.StandardCharsets;
import java.time.LocalDate;

@Controller
public class AdminAliasSeedController {

    private final AliasSeedImportService seedImportService;
    private final AliasSeedExportService seedExportService;
    private final SynonymService synonymService;
    private final DemoModeService demoModeService;

    public AdminAliasSeedController(
            AliasSeedImportService seedImportService,
            AliasSeedExportService seedExportService,
            SynonymService synonymService,
            DemoModeService demoModeService
    ) {
        this.seedImportService = seedImportService;
        this.seedExportService = seedExportService;
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

    @GetMapping("/admin/aliases/seed/export")
    public ResponseEntity<byte[]> export() {
        String json = seedExportService.exportJson();
        String filename = "alias-seed-" + LocalDate.now() + ".json";

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .contentType(new MediaType("application", "json", StandardCharsets.UTF_8))
                .body(json.getBytes(StandardCharsets.UTF_8));
    }
}