package dev.notegridx.security.assetvulnmanager.web;


import dev.notegridx.security.assetvulnmanager.service.ImportSessionStore;
import dev.notegridx.security.assetvulnmanager.service.MatchingService;


import dev.notegridx.security.assetvulnmanager.service.importing.CsvImportService;
import dev.notegridx.security.assetvulnmanager.service.importing.ImportResult;
import dev.notegridx.security.assetvulnmanager.service.importing.ImportError;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Controller
public class AdminImportController {

    private final CsvImportService csvImportService;
    private final MatchingService matchingService;
    private final ImportSessionStore importSessionStore;

    public AdminImportController(
            CsvImportService csvImportService,
            MatchingService matchingService,
            ImportSessionStore importSessionStore
    ) {
        this.csvImportService = csvImportService;
        this.matchingService = matchingService;
        this.importSessionStore = importSessionStore;
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

        // (A) sessionId を作ってCSVを一時保存（エラー行チェック→再Submit用）
        String sessionId = importSessionStore.save(file);
        model.addAttribute("importSessionId", sessionId);

        ImportResult softwareResult = csvImportService.importSoftwareCsv(file.getInputStream(), commit);
        model.addAttribute("softwareResult", softwareResult);

        if (commit && recalc && !softwareResult.hasErrors()) {
            var matchResult = matchingService.matchAndUpsertAlerts();
            model.addAttribute("matchResult", matchResult);

            // 成功して再実行不要なら消してOK（任意）
            importSessionStore.delete(sessionId);

        } else if (commit && recalc && softwareResult.hasErrors()) {
            model.addAttribute("matchSkippedMessage",
                    "Recalculation skipped because import has errors. (safety-first)");
        }

        return "admin/import";
    }

    /**
     * エラー一覧のチェックボックスで選ばれた行だけ、
     * CPE辞書に無くても import できるようにする（Commit固定）
     */
    @PostMapping("/admin/import/software/override")
    public String importSoftwareOverride(
            @RequestParam("sessionId") String sessionId,
            @RequestParam(name = "overrideLines", required = false) List<Integer> overrideLines,
            @RequestParam(name = "recalc", defaultValue = "false") boolean recalc,
            Model model) throws IOException {

        model.addAttribute("importSessionId", sessionId);

        // override は DB 登録が目的なので commit 固定
        boolean commit = true;

        Set<Integer> overrideSet = (overrideLines == null)
                ? Set.of()
                : new LinkedHashSet<>(overrideLines);

        ImportResult softwareResult;
        try (var in = importSessionStore.open(sessionId)) {
            softwareResult = csvImportService.importSoftwareCsv(in, commit, overrideSet);
        } catch (Exception e) {
            // session期限切れ/ファイル無しなど
            model.addAttribute("softwareResult",
                    new ImportResult(false, 0, 0, 0, 0, 0, 1,
                            List.of(new ImportError(
                                    1,
                                    "SESSION_EXPIRED",
                                    "Import session not found/expired. Please upload CSV again. (" + e.getMessage() + ")",
                                    ""
                            ))));
            return "admin/import";
        }

        model.addAttribute("softwareResult", softwareResult);

        if (recalc && !softwareResult.hasErrors()) {
            var matchResult = matchingService.matchAndUpsertAlerts();
            model.addAttribute("matchResult", matchResult);
            importSessionStore.delete(sessionId);
        } else if (recalc && softwareResult.hasErrors()) {
            model.addAttribute("matchSkippedMessage",
                    "Recalculation skipped because import has errors. (safety-first)");
        }

        return "admin/import";
    }
}
