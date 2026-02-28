package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.service.CanonicalBackfillService;
import dev.notegridx.security.assetvulnmanager.service.MatchingService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class AdminAlertsRecalculateController {

    private final CanonicalBackfillService canonicalBackfillService;
    private final MatchingService matchingService;

    public AdminAlertsRecalculateController(
            CanonicalBackfillService canonicalBackfillService,
            MatchingService matchingService
    ) {
        this.canonicalBackfillService = canonicalBackfillService;
        this.matchingService = matchingService;
    }

    @GetMapping("/admin/alerts/recalculate")
    public String view() {
        return "admin/alerts_recalculate";
    }

    @PostMapping("/admin/alerts/recalculate")
    public String run(Model model) {

        // 1) CanonicalBackfill（force=false：既にリンク済みはskip）:contentReference[oaicite:4]{index=4}
        var backfillResult = canonicalBackfillService.backfill(5_000_000, false);

        // 2) Matching & Upsert alerts
        var matchResult = matchingService.matchAndUpsertAlerts();

        model.addAttribute("backfillResult", backfillResult);
        model.addAttribute("matchResult", matchResult);
        return "admin/alerts_recalculate";
    }
}