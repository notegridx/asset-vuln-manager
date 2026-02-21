package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.Vulnerability;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus;
import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityRepository;
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

    public DashboardController(
            AssetRepository assetRepository,
            SoftwareInstallRepository softwareInstallRepository,
            VulnerabilityRepository vulnerabilityRepository,
            AlertRepository alertRepository
    ) {
        this.assetRepository = assetRepository;
        this.softwareInstallRepository = softwareInstallRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.alertRepository = alertRepository;
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

        // “UNMAPPED (CPE)” の件数。Alerts一覧でも cpeName null/empty を UNMAPPED 表示しているので同条件で揃える【turn10file11†52_alerts 3038ede1588c80c38a77f3c6776ba1e7.md†L64-L71】。
        long unmappedInstalls = softwareInstallRepository.countUnmappedCpe();

        model.addAttribute("assets", assets);
        model.addAttribute("installs", installs);
        model.addAttribute("vulns", vulns);
        model.addAttribute("openAlerts", openAlerts);
        model.addAttribute("unmappedInstalls", unmappedInstalls);

        long criticalNoCpeCount = vulnerabilityRepository.countCriticalWithoutAffectedCpes();
        List<Vulnerability> criticalNoCpe = vulnerabilityRepository
                .findCriticalWithoutAffectedCpes(PageRequest.of(0, 20))
                .getContent();

        model.addAttribute("criticalNoCpeCount", criticalNoCpeCount);
        model.addAttribute("criticalNoCpe", criticalNoCpe);

        return "dashboard";
    }
}
