package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.domain.Vulnerability;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertCertainty;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus;
import dev.notegridx.security.assetvulnmanager.domain.enums.Severity;
import dev.notegridx.security.assetvulnmanager.repository.*;
import org.springframework.data.domain.PageRequest;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.*;
import java.util.*;

@Controller
public class DashboardController {

    private final AssetRepository assetRepository;
    private final SoftwareInstallRepository softwareInstallRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final AlertRepository alertRepository;
    private final CpeVendorRepository cpeVendorRepository;
    private final CpeProductRepository cpeProductRepository;
    private final VulnerabilityAffectedCpeRepository affectedCpeRepository;

    public DashboardController(
            AssetRepository assetRepository,
            SoftwareInstallRepository softwareInstallRepository,
            VulnerabilityRepository vulnerabilityRepository,
            AlertRepository alertRepository,
            CpeVendorRepository cpeVendorRepository,
            CpeProductRepository cpeProductRepository,
            VulnerabilityAffectedCpeRepository affectedCpeRepository
    ) {
        this.assetRepository = assetRepository;
        this.softwareInstallRepository = softwareInstallRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.alertRepository = alertRepository;
        this.cpeVendorRepository = cpeVendorRepository;
        this.cpeProductRepository = cpeProductRepository;
        this.affectedCpeRepository = affectedCpeRepository;
    }

    @GetMapping("/")
    public String root() {
        return "redirect:/dashboard";
    }

    public record TopCountRow(Long id, String label, long cveCount) {}

    private enum TopRange {
        ALL("All time"),
        D7("Last 7 days"),
        D30("Last 30 days"),
        D90("Last 90 days"),
        D180("Last 180 days"),
        D365("Last 365 days"),
        YTD("Year to date"),
        CUSTOM("Custom");

        final String label;
        TopRange(String label) { this.label = label; }

        static TopRange parse(String raw) {
            if (raw == null) return ALL;
            String t = raw.trim().toUpperCase(Locale.ROOT);
            return switch (t) {
                case "7D", "D7" -> D7;
                case "30D", "D30" -> D30;
                case "90D", "D90" -> D90;
                case "180D", "D180" -> D180;
                case "365D", "D365" -> D365;
                case "YTD" -> YTD;
                case "CUSTOM" -> CUSTOM;
                default -> ALL;
            };
        }
    }

    private record RangeWindow(LocalDateTime from, LocalDateTime to) {}

    private static RangeWindow computeWindow(TopRange range, LocalDate fromDate, LocalDate toDate) {
        // Dashboardは「最近更新されたCVE傾向」を見る用途が多いので lastModifiedAt フィルタ前提
        // to は「今日の終端」に寄せる（LocalDateTimeで inclusive 運用）
        LocalDate today = LocalDate.now();
        LocalDateTime to = today.atTime(23, 59, 59);

        return switch (range) {
            case ALL -> new RangeWindow(null, null);

            case D7 -> new RangeWindow(today.minusDays(7).atStartOfDay(), to);
            case D30 -> new RangeWindow(today.minusDays(30).atStartOfDay(), to);
            case D90 -> new RangeWindow(today.minusDays(90).atStartOfDay(), to);
            case D180 -> new RangeWindow(today.minusDays(180).atStartOfDay(), to);
            case D365 -> new RangeWindow(today.minusDays(365).atStartOfDay(), to);

            case YTD -> {
                LocalDate jan1 = LocalDate.of(today.getYear(), 1, 1);
                yield new RangeWindow(jan1.atStartOfDay(), to);
            }

            case CUSTOM -> {
                // CUSTOM は from/to が無ければ ALL 扱い（UIからは date を入れる想定だが、安全側に倒す）
                if (fromDate == null && toDate == null) yield new RangeWindow(null, null);

                LocalDateTime f = (fromDate != null) ? fromDate.atStartOfDay() : null;
                LocalDateTime t = (toDate != null) ? toDate.atTime(23, 59, 59) : null;

                // from > to の場合は入れ替え（ユーザ操作ミス救済）
                if (f != null && t != null && f.isAfter(t)) {
                    LocalDateTime tmp = f;
                    f = t.toLocalDate().atStartOfDay();
                    t = tmp.toLocalDate().atTime(23, 59, 59);
                }
                yield new RangeWindow(f, t);
            }
        };
    }

    @GetMapping("/dashboard")
    public String dashboard(
            @RequestParam(name = "range", required = false) String range,
            @RequestParam(name = "from", required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
            @RequestParam(name = "to", required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to,
            Model model
    ) {
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

        long unmappedInstalls = softwareInstallRepository.countUnmappedCpe();

        long cpeVendors = cpeVendorRepository.count();
        long cpeProducts = cpeProductRepository.count();

        boolean needsSetup = (assets == 0) || (vulns == 0) || (cpeVendors == 0);

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

        // =========================================================
        // Top 10 Vendors / Products by distinct CVE count (with time range)
        // =========================================================

        TopRange tr = TopRange.parse(range);
        RangeWindow w = computeWindow(tr, from, to);

        // UI state
        model.addAttribute("topRange", tr.name());
        model.addAttribute("topRangeLabel", tr.label);
        model.addAttribute("from", from);
        model.addAttribute("to", to);

        List<Object[]> topVendorRows = affectedCpeRepository.countTopVendorsByDistinctCvesWithinLastModified(
                w.from(), w.to(), PageRequest.of(0, 10)
        );
        List<Object[]> topProductRows = affectedCpeRepository.countTopProductsByDistinctCvesWithinLastModified(
                w.from(), w.to(), PageRequest.of(0, 10)
        );

        List<Long> topVendorIds = topVendorRows.stream()
                .map(r -> (Long) r[0])
                .filter(Objects::nonNull)
                .toList();

        List<Long> topProductIds = topProductRows.stream()
                .map(r -> (Long) r[0])
                .filter(Objects::nonNull)
                .toList();

        Map<Long, CpeVendor> vendorById = new HashMap<>();
        if (!topVendorIds.isEmpty()) {
            for (CpeVendor v : cpeVendorRepository.findAllById(topVendorIds)) {
                vendorById.put(v.getId(), v);
            }
        }

        Map<Long, CpeProduct> productById = new HashMap<>();
        if (!topProductIds.isEmpty()) {
            for (CpeProduct p : cpeProductRepository.findAllById(topProductIds)) {
                productById.put(p.getId(), p);
            }
        }

        List<TopCountRow> topVendors = topVendorRows.stream()
                .map(r -> {
                    Long id = (Long) r[0];
                    long cnt = ((Number) r[1]).longValue();
                    CpeVendor v = vendorById.get(id);
                    String label = (v == null)
                            ? ("vendor#" + id)
                            : ((v.getDisplayName() == null || v.getDisplayName().isBlank()) ? v.getNameNorm() : v.getDisplayName());
                    return new TopCountRow(id, label, cnt);
                })
                .toList();

        List<TopCountRow> topProducts = topProductRows.stream()
                .map(r -> {
                    Long id = (Long) r[0];
                    long cnt = ((Number) r[1]).longValue();
                    CpeProduct p = productById.get(id);
                    String label = (p == null)
                            ? ("product#" + id)
                            : ((p.getDisplayName() == null || p.getDisplayName().isBlank()) ? p.getNameNorm() : p.getDisplayName());
                    return new TopCountRow(id, label, cnt);
                })
                .toList();

        model.addAttribute("topVendors", topVendors);
        model.addAttribute("topProducts", topProducts);

        return "dashboard";
    }
}