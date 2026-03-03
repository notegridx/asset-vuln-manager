package dev.notegridx.security.assetvulnmanager.web;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.notegridx.security.assetvulnmanager.domain.AdminRun;
import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import dev.notegridx.security.assetvulnmanager.repository.AdminRunRepository;
import dev.notegridx.security.assetvulnmanager.service.AdminKevSyncService;
import dev.notegridx.security.assetvulnmanager.service.KevSyncService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@Controller
public class AdminKevController {

    private final AdminKevSyncService adminKevSyncService;
    private final AdminRunRepository adminRunRepository;
    private final ObjectMapper objectMapper;

    public AdminKevController(
            AdminKevSyncService adminKevSyncService,
            AdminRunRepository adminRunRepository,
            ObjectMapper objectMapper
    ) {
        this.adminKevSyncService = adminKevSyncService;
        this.adminRunRepository = adminRunRepository;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/admin/kev/sync")
    public String page(Model model) {
        AdminRun last = findLast();
        bindLastRun(model, last);

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
        KevSyncService.SyncResult result = adminKevSyncService.run(force, maxItems);
        model.addAttribute("result", result);

        AdminRun last = findLast();
        bindLastRun(model, last);

        model.addAttribute("force", force);
        model.addAttribute("maxItems", maxItems);

        return "admin/kev_sync";
    }

    private AdminRun findLast() {
        return adminRunRepository
                .findTop1ByJobTypeOrderByStartedAtDescIdDesc(AdminJobType.KEV_SYNC)
                .orElse(null);
    }

    private void bindLastRun(Model model, AdminRun lastRun) {
        model.addAttribute("lastRun", lastRun);
        if (lastRun == null) return;

        model.addAttribute("lastParams", parseJsonToMap(lastRun.getParamsJson()));
        model.addAttribute("lastResult", parseJsonToMap(lastRun.getResultJson()));
    }

    private Map<String, Object> parseJsonToMap(String json) {
        if (json == null || json.isBlank()) return null;
        try {
            return objectMapper.readValue(json, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("_parseError", e.getMessage());
            m.put("_raw", json);
            return m;
        }
    }
}