package dev.notegridx.security.assetvulnmanager.web;

import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import dev.notegridx.security.assetvulnmanager.domain.ImportRun;
import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;
import dev.notegridx.security.assetvulnmanager.repository.ImportRunRepository;
import dev.notegridx.security.assetvulnmanager.repository.UnresolvedMappingRepository;

@Controller
public class AdminInventoryController {

    private final ImportRunRepository importRunRepository;
    private final UnresolvedMappingRepository unresolvedMappingRepository;

    public AdminInventoryController(
            ImportRunRepository importRunRepository,
            UnresolvedMappingRepository unresolvedMappingRepository
    ) {
        this.importRunRepository = importRunRepository;
        this.unresolvedMappingRepository = unresolvedMappingRepository;
    }

    @GetMapping("/admin/import-runs")
    public String importRuns(Model model) {
        // 新しい順（Repositoryにメソッドが無い場合は一旦 findAll() でもOK）
        List<ImportRun> runs = importRunRepository.findAll();
        runs.sort((a, b) -> {
            if (a.getId() == null && b.getId() == null) return 0;
            if (a.getId() == null) return 1;
            if (b.getId() == null) return -1;
            return Long.compare(b.getId(), a.getId());
        });

        model.addAttribute("runs", runs);
        return "admin/import_runs";
    }

    @GetMapping("/admin/unresolved")
    public String unresolved(
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "runId", required = false) Long runId,
            Model model
    ) {
        List<UnresolvedMapping> list = unresolvedMappingRepository.findAll();
        // 軽いフィルタ（まず動かす。後でQuery最適化）
        if (status != null && !status.isBlank()) {
            String s = status.trim();
            list.removeIf(m -> m.getStatus() == null || !m.getStatus().equalsIgnoreCase(s));
        }
        // runId フィルタは現状 UnresolvedMapping に runId を持ってない想定なので、一旦無視
        // （必要なら UnresolvedMapping に importRunId を追加してから対応）

        list.sort((a, b) -> {
            if (a.getId() == null && b.getId() == null) return 0;
            if (a.getId() == null) return 1;
            if (b.getId() == null) return -1;
            return Long.compare(b.getId(), a.getId());
        });

        model.addAttribute("mappings", list);
        model.addAttribute("status", (status == null || status.isBlank()) ? null : status.trim().toUpperCase());
        model.addAttribute("runId", runId);
        return "admin/unresolved";
    }
}