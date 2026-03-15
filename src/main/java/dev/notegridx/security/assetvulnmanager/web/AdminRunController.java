package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.service.AdminRunReadService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AdminRunController {

    private final AdminRunReadService adminRunReadService;

    public AdminRunController(AdminRunReadService adminRunReadService) {
        this.adminRunReadService = adminRunReadService;
    }

    @GetMapping("/admin/runs")
    public String runs(Model model) {
        model.addAttribute("runs", adminRunReadService.findRecentRuns(200));
        return "admin/runs";
    }
}