package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.Vulnerability;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertCertainty;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus;
import dev.notegridx.security.assetvulnmanager.domain.enums.Severity;
import dev.notegridx.security.assetvulnmanager.repository.*;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;

@Controller
public class DashboardController {

    private final AssetRepository assetRepository;
    private final SoftwareInstallRepository softwareInstallRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final AlertRepository alertRepository;
    private final CpeVendorRepository cpeVendorRepository;
    private final CpeProductRepository cpeProductRepository;

    public DashboardController(
            AssetRepository assetRepository,
            SoftwareInstallRepository softwareInstallRepository,
            VulnerabilityRepository vulnerabilityRepository,
            AlertRepository alertRepository,
            CpeVendorRepository cpeVendorRepository,
            CpeProductRepository cpeProductRepository
    ) {
        this.assetRepository = assetRepository;
        this.softwareInstallRepository = softwareInstallRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.alertRepository = alertRepository;
        this.cpeVendorRepository = cpeVendorRepository;
        this.cpeProductRepository = cpeProductRepository;
    }

    @GetMapping("/")
    public String root() {
        return "redirect:/dashboard";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model) {
        long assets = assetRepository.count();
        long installs = softwareInstallRepository.count();
        long vulns = vulnerabilityRepository.count();

        long openAlerts = alertRepository.countByStatus(AlertStatus.OPEN);
        long openAlertsConfirmed = alertRepository.countByStatusAndCertainty(AlertStatus.OPEN, AlertCertainty.CONFIRMED);
        long openAlertsUnconfirmed = alertRepository.countByStatusAndCertainty(AlertStatus.OPEN, AlertCertainty.UNCONFIRMED);

        // Per severity (NONEは除外)
        long openAlertsCriticalConfirmed = alertRepository.countByStatusAndVulnerability_SeverityAndCertainty(AlertStatus.OPEN, Severity.CRITICAL, AlertCertainty.CONFIRMED);
        long openAlertsCriticalUnconfirmed = alertRepository.countByStatusAndVulnerability_SeverityAndCertainty(AlertStatus.OPEN, Severity.CRITICAL, AlertCertainty.UNCONFIRMED);
        long openAlertsCritical = openAlertsCriticalConfirmed + openAlertsCriticalUnconfirmed;

        long openAlertsHighConfirmed = alertRepository.countByStatusAndVulnerability_SeverityAndCertainty(AlertStatus.OPEN, Severity.HIGH, AlertCertainty.CONFIRMED);
        long openAlertsHighUnconfirmed = alertRepository.countByStatusAndVulnerability_SeverityAndCertainty(AlertStatus.OPEN, Severity.HIGH, AlertCertainty.UNCONFIRMED);
        long openAlertsHigh = openAlertsHighConfirmed + openAlertsHighUnconfirmed;

        long openAlertsMediumConfirmed = alertRepository.countByStatusAndVulnerability_SeverityAndCertainty(AlertStatus.OPEN, Severity.MEDIUM, AlertCertainty.CONFIRMED);
        long openAlertsMediumUnconfirmed = alertRepository.countByStatusAndVulnerability_SeverityAndCertainty(AlertStatus.OPEN, Severity.MEDIUM, AlertCertainty.UNCONFIRMED);
        long openAlertsMedium = openAlertsMediumConfirmed + openAlertsMediumUnconfirmed;

        long openAlertsLowConfirmed = alertRepository.countByStatusAndVulnerability_SeverityAndCertainty(AlertStatus.OPEN, Severity.LOW, AlertCertainty.CONFIRMED);
        long openAlertsLowUnconfirmed = alertRepository.countByStatusAndVulnerability_SeverityAndCertainty(AlertStatus.OPEN, Severity.LOW, AlertCertainty.UNCONFIRMED);
        long openAlertsLow = openAlertsLowConfirmed + openAlertsLowUnconfirmed;

        // “UNMAPPED (CPE)” の件数（Alerts一覧の判定と揃える）
        long unmappedInstalls = softwareInstallRepository.countUnmappedCpe();

        long cpeVendors = cpeVendorRepository.count();
        long cpeProducts = cpeProductRepository.count();

        // First-Time Setup を出すかどうか（初期データが揃っていない間だけ true）
        boolean needsSetup =
                (assets == 0) || (vulns == 0) || (cpeVendors == 0);

        model.addAttribute("assets", assets);
        model.addAttribute("installs", installs);
        model.addAttribute("vulns", vulns);

        model.addAttribute("openAlerts", openAlerts);
        model.addAttribute("openAlertsConfirmed", openAlertsConfirmed);
        model.addAttribute("openAlertsUnconfirmed", openAlertsUnconfirmed);

        model.addAttribute("openAlertsCritical", openAlertsCritical);
        model.addAttribute("openAlertsCriticalConfirmed", openAlertsCriticalConfirmed);
        model.addAttribute("openAlertsCriticalUnconfirmed", openAlertsCriticalUnconfirmed);

        model.addAttribute("openAlertsHigh", openAlertsHigh);
        model.addAttribute("openAlertsHighConfirmed", openAlertsHighConfirmed);
        model.addAttribute("openAlertsHighUnconfirmed", openAlertsHighUnconfirmed);

        model.addAttribute("openAlertsMedium", openAlertsMedium);
        model.addAttribute("openAlertsMediumConfirmed", openAlertsMediumConfirmed);
        model.addAttribute("openAlertsMediumUnconfirmed", openAlertsMediumUnconfirmed);

        model.addAttribute("openAlertsLow", openAlertsLow);
        model.addAttribute("openAlertsLowConfirmed", openAlertsLowConfirmed);
        model.addAttribute("openAlertsLowUnconfirmed", openAlertsLowUnconfirmed);

        model.addAttribute("unmappedInstalls", unmappedInstalls);
        model.addAttribute("cpeVendors", cpeVendors);
        model.addAttribute("cpeProducts", cpeProducts);
        model.addAttribute("needsSetup", needsSetup);

        long criticalNoCpeCount = vulnerabilityRepository.countCriticalWithoutAffectedCpes();
        List<Vulnerability> criticalNoCpe = vulnerabilityRepository
                .findCriticalWithoutAffectedCpes(PageRequest.of(0, 20))
                .getContent();

        model.addAttribute("criticalNoCpeCount", criticalNoCpeCount);
        model.addAttribute("criticalNoCpe", criticalNoCpe);

        return "dashboard";
    }
}