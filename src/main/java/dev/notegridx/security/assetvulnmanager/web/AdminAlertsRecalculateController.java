package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.service.MatchingService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class AdminAlertsRecalculateController {

    private final MatchingService matchingService;

    public AdminAlertsRecalculateController(MatchingService matchingService) {
        this.matchingService = matchingService;
    }

    @GetMapping("/admin/alerts/recalculate")
    public String view() {
        return "admin/alerts_recalculate";
    }

    @PostMapping("/admin/alerts/recalculate")
    public String run(Model model) {
        var matchResult = matchingService.matchAndUpsertAlerts();
        model.addAttribute("matchResult", matchResult);
        return "admin/alerts_recalculate";
    }
}