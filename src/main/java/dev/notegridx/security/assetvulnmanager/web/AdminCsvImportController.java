package dev.notegridx.security.assetvulnmanager.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import dev.notegridx.security.assetvulnmanager.domain.ImportRun;
import dev.notegridx.security.assetvulnmanager.domain.enums.SoftwareImportMode;
import dev.notegridx.security.assetvulnmanager.repository.ImportRunRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportStagingAssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportStagingSoftwareRepository;
import dev.notegridx.security.assetvulnmanager.service.CsvStagedImportService;

@Controller
@RequestMapping("/admin/import/csv")
public class AdminCsvImportController {

    private final CsvStagedImportService csvStagedImportService;
    private final ImportRunRepository importRunRepository;
    private final ImportStagingAssetRepository stagingAssetRepository;
    private final ImportStagingSoftwareRepository stagingSoftwareRepository;

    public AdminCsvImportController(
            CsvStagedImportService csvStagedImportService,
            ImportRunRepository importRunRepository,
            ImportStagingAssetRepository stagingAssetRepository,
            ImportStagingSoftwareRepository stagingSoftwareRepository
    ) {
        this.csvStagedImportService = csvStagedImportService;
        this.importRunRepository = importRunRepository;
        this.stagingAssetRepository = stagingAssetRepository;
        this.stagingSoftwareRepository = stagingSoftwareRepository;
    }

    @GetMapping
    public String index() {
        return "admin/csv_import";
    }

    // ---------- Assets ----------
    @PostMapping("/assets/stage")
    public String stageAssets(@RequestParam("file") MultipartFile file) throws Exception {
        ImportRun run = csvStagedImportService.stageAssets(file.getOriginalFilename(), file.getBytes());
        return "redirect:/admin/import/csv/assets/" + run.getId();
    }

    @GetMapping("/assets/{runId}")
    public String previewAssets(@PathVariable Long runId, Model model) {
        ImportRun run = importRunRepository.findById(runId).orElseThrow();
        model.addAttribute("run", run);
        model.addAttribute("rows", stagingAssetRepository.findByImportRunIdOrderByRowNoAsc(runId));
        return "admin/csv_import_assets_preview";
    }

    @PostMapping("/assets/{runId}/import")
    public String importAssets(@PathVariable Long runId) {
        csvStagedImportService.importAssets(runId);
        return "redirect:/admin/import-runs";
    }

    // ---------- Software ----------
    @PostMapping("/software/stage")
    public String stageSoftware(@RequestParam("file") MultipartFile file) throws Exception {
        ImportRun run = csvStagedImportService.stageSoftware(file.getOriginalFilename(), file.getBytes());
        return "redirect:/admin/import/csv/software/" + run.getId();
    }

    @GetMapping("/software/{runId}")
    public String previewSoftware(@PathVariable Long runId, Model model) {
        ImportRun run = importRunRepository.findById(runId).orElseThrow();
        model.addAttribute("run", run);
        model.addAttribute("rows", stagingSoftwareRepository.findByImportRunIdOrderByRowNoAsc(runId));
        model.addAttribute("defaultMode", SoftwareImportMode.REPLACE_ASSET_SOFTWARE.name());
        return "admin/csv_import_software_preview";
    }

    @PostMapping("/software/{runId}/import")
    public String importSoftware(
            @PathVariable Long runId,
            @RequestParam(name = "mode", defaultValue = "REPLACE_ASSET_SOFTWARE") String mode
    ) {
        csvStagedImportService.importSoftware(runId, parseMode(mode));
        return "redirect:/admin/import-runs";
    }

    private SoftwareImportMode parseMode(String mode) {
        if (mode == null || mode.isBlank()) {
            return SoftwareImportMode.REPLACE_ASSET_SOFTWARE;
        }
        try {
            return SoftwareImportMode.valueOf(mode);
        } catch (IllegalArgumentException ex) {
            return SoftwareImportMode.REPLACE_ASSET_SOFTWARE;
        }
    }
}