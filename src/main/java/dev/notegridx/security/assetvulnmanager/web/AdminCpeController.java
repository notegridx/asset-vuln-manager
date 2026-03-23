package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.service.AdminCpeSyncService;
import dev.notegridx.security.assetvulnmanager.service.AdminJobAlreadyRunningException;
import dev.notegridx.security.assetvulnmanager.service.CpeFeedSyncService;
import dev.notegridx.security.assetvulnmanager.service.DemoModeService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@Controller
public class AdminCpeController {

    private final AdminCpeSyncService adminCpeSyncService;
    private final DemoModeService demoModeService;

    public AdminCpeController(
            AdminCpeSyncService adminCpeSyncService,
            DemoModeService demoModeService
    ) {
        this.adminCpeSyncService = adminCpeSyncService;
        this.demoModeService = demoModeService;
    }

    @GetMapping("/admin/cpe/sync")
    public String view(Model model) {
        model.addAttribute("mode", "DOWNLOAD");
        model.addAttribute("force", false);
        model.addAttribute("maxItems", 2_000_000);
        return "admin/cpe_sync";
    }

    @PostMapping("/admin/cpe/sync")
    public String run(
            @RequestParam(name = "mode", defaultValue = "DOWNLOAD") String mode,
            @RequestParam(name = "force", defaultValue = "false") boolean force,
            @RequestParam(name = "maxItems", defaultValue = "2000000") int maxItems,
            @RequestParam(name = "file", required = false) MultipartFile file,
            Model model
    ) throws IOException {

        demoModeService.assertWritable();

        String safeMode = normalizeMode(mode);

        try {
            if ("UPLOAD".equals(safeMode)) {
                CpeFeedSyncService.SyncResult result = adminCpeSyncService.runSyncFromUpload(file, maxItems);
                model.addAttribute("result", result);
                model.addAttribute("success", buildUploadSuccessMessage(file, result));
            } else {
                CpeFeedSyncService.SyncResult result = adminCpeSyncService.runSync(force, maxItems);
                model.addAttribute("result", result);
                model.addAttribute("success", buildDownloadSuccessMessage(force, result));
            }

        } catch (AdminJobAlreadyRunningException | IllegalArgumentException ex) {
            model.addAttribute("error", ex.getMessage());
        }

        model.addAttribute("mode", safeMode);
        model.addAttribute("force", force);
        model.addAttribute("maxItems", maxItems);

        return "admin/cpe_sync";
    }

    private static String normalizeMode(String mode) {
        if (mode == null) {
            return "DOWNLOAD";
        }
        String t = mode.trim().toUpperCase();
        return "UPLOAD".equals(t) ? "UPLOAD" : "DOWNLOAD";
    }

    private static String buildDownloadSuccessMessage(boolean force, CpeFeedSyncService.SyncResult result) {
        StringBuilder sb = new StringBuilder();

        if (result.skipped()) {
            sb.append("Product dictionary is already up to date. No download was needed. ");
        } else {
            sb.append("Latest NVD CPE archive downloaded and product dictionary updated successfully. ");
            if (force) {
                sb.append("(Forced refresh) ");
            }
        }

        appendCommonStats(sb, result);
        appendDownloadMeta(sb, result);
        return sb.toString().trim();
    }

    private static String buildUploadSuccessMessage(MultipartFile file, CpeFeedSyncService.SyncResult result) {
        String filename = "uploaded archive";

        String originalFilename = (file == null) ? null : file.getOriginalFilename();
        String sourceFilename = (result == null) ? null : result.sourceFilename();

        if (originalFilename != null && !originalFilename.isBlank()) {
            filename = originalFilename.trim();
        } else if (sourceFilename != null && !sourceFilename.isBlank()) {
            filename = sourceFilename.trim();
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Uploaded archive processed and product dictionary updated successfully. ");
        sb.append("File: ").append(filename).append(". ");

        if (result != null) {
            appendCommonStats(sb, result);
        }

        return sb.toString().trim();
    }

    private static void appendCommonStats(StringBuilder sb, CpeFeedSyncService.SyncResult result) {
        sb.append("Parsed ")
                .append(result.cpeParsed())
                .append(" CPE entries, inserted ")
                .append(result.vendorsInserted())
                .append(" vendors and ")
                .append(result.productsInserted())
                .append(" products");

        sb.append(" in ").append(result.elapsedSec()).append(" sec");
        sb.append(" (").append(result.rowsPerSec()).append(" rows/sec)");

        sb.append(". ");
    }

    private static void appendDownloadMeta(StringBuilder sb, CpeFeedSyncService.SyncResult result) {
        boolean hasAnyMeta =
                result.metaSha256() != null ||
                        result.metaLastModified() != null ||
                        result.metaSize() != null;

        if (!hasAnyMeta) {
            return;
        }

        sb.append("Meta: ");

        boolean appended = false;

        if (result.metaLastModified() != null) {
            sb.append("lastModified=").append(result.metaLastModified());
            appended = true;
        }

        if (result.metaSize() != null) {
            if (appended) {
                sb.append(", ");
            }
            sb.append("size=").append(result.metaSize());
            appended = true;
        }

        if (result.metaSha256() != null) {
            if (appended) {
                sb.append(", ");
            }
            sb.append("sha256=").append(result.metaSha256());
        }

        sb.append(". ");
    }
}