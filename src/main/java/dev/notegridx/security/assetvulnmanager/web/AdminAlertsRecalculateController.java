package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.service.AdminAlertsRecalculateService;
import dev.notegridx.security.assetvulnmanager.service.AdminJobAlreadyRunningException;
import dev.notegridx.security.assetvulnmanager.service.DemoModeService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.List;

@Controller
public class AdminAlertsRecalculateController {

    private final AdminAlertsRecalculateService adminAlertsRecalculateService;
    private final SoftwareInstallRepository softwareInstallRepository;
    private final DemoModeService demoModeService;

    public AdminAlertsRecalculateController(
            AdminAlertsRecalculateService adminAlertsRecalculateService,
            SoftwareInstallRepository softwareInstallRepository,
            DemoModeService demoModeService
    ) {
        this.adminAlertsRecalculateService = adminAlertsRecalculateService;
        this.softwareInstallRepository = softwareInstallRepository;
        this.demoModeService = demoModeService;
    }

    @GetMapping("/admin/alerts/recalculate")
    public String view(Model model) {
        addCanonicalStats(model);
        return "admin/alerts_recalculate";
    }

    @PostMapping("/admin/alerts/recalculate")
    public String run(Model model) {

        demoModeService.assertWritable();

        try {
            var matchResult = adminAlertsRecalculateService.runRecalculate();
            model.addAttribute("matchResult", matchResult);
        } catch (AdminJobAlreadyRunningException ex) {
            model.addAttribute("error", ex.getMessage());
        }

        addCanonicalStats(model);
        return "admin/alerts_recalculate";
    }

    private void addCanonicalStats(Model model) {
        List<SoftwareInstall> rows = softwareInstallRepository.findAll();

        long fullyLinked = 0;
        long vendorOnlyLinked = 0;
        long notLinked = 0;

        for (SoftwareInstall s : rows) {
            boolean hasVendor = s.getCpeVendorId() != null;
            boolean hasProduct = s.getCpeProductId() != null;

            if (hasVendor && hasProduct) {
                fullyLinked++;
            } else if (hasVendor) {
                vendorOnlyLinked++;
            } else {
                notLinked++;
            }
        }

        model.addAttribute("fullyLinkedCount", fullyLinked);
        model.addAttribute("vendorOnlyLinkedCount", vendorOnlyLinked);
        model.addAttribute("notLinkedCount", notLinked);
        model.addAttribute("hasIncompleteCanonicalLinks", (vendorOnlyLinked + notLinked) > 0);
    }
}