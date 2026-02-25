package dev.notegridx.security.assetvulnmanager.web;

import java.io.IOException;
import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import dev.notegridx.security.assetvulnmanager.domain.ImportRun;
import dev.notegridx.security.assetvulnmanager.domain.ImportStagingAsset;
import dev.notegridx.security.assetvulnmanager.domain.ImportStagingSoftware;
import dev.notegridx.security.assetvulnmanager.repository.ImportRunRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportStagingAssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportStagingSoftwareRepository;
import dev.notegridx.security.assetvulnmanager.service.JsonStagedImportService;

@Controller
public class AdminJsonImportController {

    private final JsonStagedImportService jsonStagedImportService;

    private final ImportRunRepository importRunRepository;
    private final ImportStagingAssetRepository stagingAssetRepository;
    private final ImportStagingSoftwareRepository stagingSoftwareRepository;

    public AdminJsonImportController(
            JsonStagedImportService jsonStagedImportService,
            ImportRunRepository importRunRepository,
            ImportStagingAssetRepository stagingAssetRepository,
            ImportStagingSoftwareRepository stagingSoftwareRepository
    ) {
        this.jsonStagedImportService = jsonStagedImportService;
        this.importRunRepository = importRunRepository;
        this.stagingAssetRepository = stagingAssetRepository;
        this.stagingSoftwareRepository = stagingSoftwareRepository;
    }

    @GetMapping("/admin/import/json")
    public String view() {
        return "admin/json_import";
    }

    // ===== Assets =====
    @PostMapping("/admin/import/json/assets/upload")
    public String uploadAssets(@RequestParam("file") MultipartFile file) throws IOException {
        byte[] bytes = file.getBytes();
        ImportRun run = jsonStagedImportService.stageAssets(file.getOriginalFilename(), bytes);
        return "redirect:/admin/import/json/assets/" + run.getId() + "/preview";
    }

    @GetMapping("/admin/import/json/assets/{runId}/preview")
    public String previewAssets(@PathVariable("runId") Long runId, Model model) {
        ImportRun run = importRunRepository.findById(runId)
                .orElseThrow(() -> new IllegalArgumentException("import_run not found: " + runId));

        List<ImportStagingAsset> rows = stagingAssetRepository.findByImportRunIdOrderByRowNoAsc(runId);

        model.addAttribute("run", run);
        model.addAttribute("rows", rows);
        return "admin/json_import_assets_preview";
    }

    @PostMapping("/admin/import/json/assets/{runId}/import")
    public String importAssets(@PathVariable("runId") Long runId) {
        jsonStagedImportService.importAssets(runId);
        return "redirect:/admin/import/json/result/" + runId;
    }

    // ===== Software =====
    @PostMapping("/admin/import/json/software/upload")
    public String uploadSoftware(@RequestParam("file") MultipartFile file) throws IOException {
        byte[] bytes = file.getBytes();
        ImportRun run = jsonStagedImportService.stageSoftware(file.getOriginalFilename(), bytes);
        return "redirect:/admin/import/json/software/" + run.getId() + "/preview";
    }

    @GetMapping("/admin/import/json/software/{runId}/preview")
    public String previewSoftware(@PathVariable("runId") Long runId, Model model) {
        ImportRun run = importRunRepository.findById(runId)
                .orElseThrow(() -> new IllegalArgumentException("import_run not found: " + runId));

        List<ImportStagingSoftware> rows = stagingSoftwareRepository.findByImportRunIdOrderByRowNoAsc(runId);

        model.addAttribute("run", run);
        model.addAttribute("rows", rows);
        return "admin/json_import_software_preview";
    }

    @PostMapping("/admin/import/json/software/{runId}/import")
    public String importSoftware(@PathVariable("runId") Long runId) {
        jsonStagedImportService.importSoftware(runId);
        return "redirect:/admin/import/json/result/" + runId;
    }

    // ===== Result =====
    @GetMapping("/admin/import/json/result/{runId}")
    public String result(@PathVariable("runId") Long runId, Model model) {
        ImportRun run = importRunRepository.findById(runId)
                .orElseThrow(() -> new IllegalArgumentException("import_run not found: " + runId));

        model.addAttribute("run", run);
        return "admin/json_import_result";
    }
}