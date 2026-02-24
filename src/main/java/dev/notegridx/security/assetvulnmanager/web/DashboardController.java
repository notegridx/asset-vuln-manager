package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.Alert;
import dev.notegridx.security.assetvulnmanager.domain.Vulnerability;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus;
import dev.notegridx.security.assetvulnmanager.domain.enums.Severity;
import dev.notegridx.security.assetvulnmanager.repository.*;
import dev.notegridx.security.assetvulnmanager.service.AlertService;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
public class DashboardController {

    private final AssetRepository assetRepository;
    private final SoftwareInstallRepository softwareInstallRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final AlertRepository alertRepository;
    private final CpeVendorRepository cpeVendorRepository;
    private final CpeProductRepository cpeProductRepository;
    private final AlertService alertService;

    public DashboardController(
            AssetRepository assetRepository,
            SoftwareInstallRepository softwareInstallRepository,
            VulnerabilityRepository vulnerabilityRepository,
            AlertRepository alertRepository,
            CpeVendorRepository cpeVendorRepository,
            CpeProductRepository cpeProductRepository,
            AlertService alertService
    ) {
        this.assetRepository = assetRepository;
        this.softwareInstallRepository = softwareInstallRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.alertRepository = alertRepository;
        this.cpeVendorRepository = cpeVendorRepository;
        this.cpeProductRepository = cpeProductRepository;
        this.alertService = alertService;
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

        long openAlertsCritical = alertRepository.countByStatusAndVulnerability_Severity(AlertStatus.OPEN, Severity.CRITICAL);
        long openAlertsHigh = alertRepository.countByStatusAndVulnerability_Severity(AlertStatus.OPEN, Severity.HIGH);
        long openAlertsMedium = alertRepository.countByStatusAndVulnerability_Severity(AlertStatus.OPEN, Severity.MEDIUM);
        long openAlertsLow = alertRepository.countByStatusAndVulnerability_Severity(AlertStatus.OPEN, Severity.LOW);
        long openAlertsNone = alertRepository.countByStatusAndVulnerability_Severity(AlertStatus.OPEN, Severity.NONE);


        // “UNMAPPED (CPE)” の件数。Alerts一覧でも cpeName null/empty を UNMAPPED 表示しているので同条件で揃える【turn10file11†52_alerts 3038ede1588c80c38a77f3c6776ba1e7.md†L64-L71】。
        long unmappedInstalls = softwareInstallRepository.countUnmappedCpe();

        long cpeVendors = cpeVendorRepository.count();
        long cpeProducts = cpeProductRepository.count();

        model.addAttribute("assets", assets);
        model.addAttribute("installs", installs);
        model.addAttribute("vulns", vulns);
        model.addAttribute("openAlerts", openAlerts);
        model.addAttribute("openAlertsCritical", openAlertsCritical);
        model.addAttribute("openAlertsHigh", openAlertsHigh);
        model.addAttribute("openAlertsMedium", openAlertsMedium);
        model.addAttribute("openAlertsLow", openAlertsLow);
        model.addAttribute("openAlertsNone", openAlertsNone);
        model.addAttribute("unmappedInstalls", unmappedInstalls);
        model.addAttribute("cpeVendors", cpeVendors);
        model.addAttribute("cpeProducts", cpeProducts);

        long criticalNoCpeCount = vulnerabilityRepository.countCriticalWithoutAffectedCpes();
        List<Vulnerability> criticalNoCpe = vulnerabilityRepository
                .findCriticalWithoutAffectedCpes(PageRequest.of(0, 20))
                .getContent();

        model.addAttribute("criticalNoCpeCount", criticalNoCpeCount);
        model.addAttribute("criticalNoCpe", criticalNoCpe);

// List側は別名にする
        List<Alert> openAlertList = alertService.list("OPEN", null, null);

        Map<Severity, Long> severityCounts = openAlertList.stream()
                .filter(a -> a.getVulnerability() != null)
                .collect(Collectors.groupingBy(
                        a -> {
                            Severity s = a.getVulnerability().getSeverity();
                            return (s == null) ? Severity.NONE : s;
                        },
                        () -> new EnumMap<>(Severity.class),
                        Collectors.counting()
                ));

        model.addAttribute("openAlerts", openAlerts);               // 既存のまま（ヘッダ用）
        model.addAttribute("severityCounts", severityCounts);       // 追加（カード用）

        return "dashboard";
    }
}
