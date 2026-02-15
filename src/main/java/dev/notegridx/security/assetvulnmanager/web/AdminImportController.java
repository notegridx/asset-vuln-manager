package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.service.MatchingService;
import dev.notegridx.security.assetvulnmanager.service.importing.CsvImportService;
import dev.notegridx.security.assetvulnmanager.service.importing.ImportError;
import dev.notegridx.security.assetvulnmanager.service.importing.ImportResult;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@Controller
public class AdminImportController {

    private final CsvImportService csvImportService;
    private final MatchingService matchingService;

    public AdminImportController(CsvImportService csvImportService, MatchingService matchingService) {
        this.csvImportService = csvImportService;
        this.matchingService = matchingService;
    }

    @GetMapping("/admin/import")
    public String view() {
        return "admin/import";
    }

    @PostMapping("/admin/import/assets")
    public String importAssets(
            @RequestParam("file") MultipartFile file,
            @RequestParam(name = "commit", defaultValue = "false") boolean commit,
            Model model) throws IOException {

        ImportResult assetResult = csvImportService.importAssetsCsv(file.getInputStream(), commit);
        model.addAttribute("assetResult", assetResult);
        return "admin/import";
    }

    @PostMapping("/admin/import/software")
    public String importSoftware(
            @RequestParam("file") MultipartFile file,
            @RequestParam(name = "commit", defaultValue = "false") boolean commit,
            @RequestParam(name = "recalc", defaultValue = "false") boolean recalc,
            Model model) throws IOException {

        ImportResult softwareResult = csvImportService.importSoftwareCsv(file.getInputStream(), commit);
        model.addAttribute("softwareResult", softwareResult);

        if (commit && recalc && !softwareResult.hasErrors()) {
            var matchResult = matchingService.matchAndUpsertAlerts();
            model.addAttribute("matchResult", matchResult);
        } else if (commit && recalc && softwareResult.hasErrors()) {
            model.addAttribute("matchSkippedMessage",
                    "Recalculation skipped because import has errors. (safety-first)");
        }

        return "admin/import";
    }
}
