package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.Vulnerability;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityRepository;
import dev.notegridx.security.assetvulnmanager.service.DashboardStatsService;
import org.springframework.data.domain.PageRequest;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;

@Controller
public class DashboardController {

    private final DashboardStatsService dashboardStatsService;
    private final VulnerabilityRepository vulnerabilityRepository;

    public DashboardController(
            DashboardStatsService dashboardStatsService,
            VulnerabilityRepository vulnerabilityRepository
    ) {
        this.dashboardStatsService = dashboardStatsService;
        this.vulnerabilityRepository = vulnerabilityRepository;
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

        TopRange(String label) {
            this.label = label;
        }

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
                if (fromDate == null && toDate == null) {
                    yield new RangeWindow(null, null);
                }

                LocalDateTime f = (fromDate != null) ? fromDate.atStartOfDay() : null;
                LocalDateTime t = (toDate != null) ? toDate.atTime(23, 59, 59) : null;

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
        DashboardStatsService.DashboardViewStats s = dashboardStatsService.load();

        model.addAttribute("assets", s.assets());
        model.addAttribute("installs", s.installs());
        model.addAttribute("vulns", s.vulns());

        model.addAttribute("openAlerts", s.openAlerts());
        model.addAttribute("openAlertsConfirmed", s.openAlertsConfirmed());
        model.addAttribute("openAlertsUnconfirmed", s.openAlertsUnconfirmed());

        model.addAttribute("openAlertsCritical", s.openAlertsCritical());
        model.addAttribute("openAlertsCriticalConfirmed", s.openAlertsCriticalConfirmed());
        model.addAttribute("openAlertsCriticalUnconfirmed", s.openAlertsCriticalUnconfirmed());

        model.addAttribute("openAlertsHigh", s.openAlertsHigh());
        model.addAttribute("openAlertsHighConfirmed", s.openAlertsHighConfirmed());
        model.addAttribute("openAlertsHighUnconfirmed", s.openAlertsHighUnconfirmed());

        model.addAttribute("openAlertsMedium", s.openAlertsMedium());
        model.addAttribute("openAlertsMediumConfirmed", s.openAlertsMediumConfirmed());
        model.addAttribute("openAlertsMediumUnconfirmed", s.openAlertsMediumUnconfirmed());

        model.addAttribute("openAlertsLow", s.openAlertsLow());
        model.addAttribute("openAlertsLowConfirmed", s.openAlertsLowConfirmed());
        model.addAttribute("openAlertsLowUnconfirmed", s.openAlertsLowUnconfirmed());

        model.addAttribute("unmappedInstalls", s.unmappedInstalls());
        model.addAttribute("cpeVendors", s.cpeVendors());
        model.addAttribute("cpeProducts", s.cpeProducts());
        model.addAttribute("needsSetup", s.needsSetup());

        long criticalNoCpeCount = vulnerabilityRepository.countCriticalWithoutAffectedCpes();
        List<Vulnerability> criticalNoCpe = vulnerabilityRepository
                .findCriticalWithoutAffectedCpes(PageRequest.of(0, 20))
                .getContent();

        model.addAttribute("criticalNoCpeCount", criticalNoCpeCount);
        model.addAttribute("criticalNoCpe", criticalNoCpe);

        TopRange tr = TopRange.parse(range);

        model.addAttribute("topRange", tr.name());
        model.addAttribute("topRangeLabel", tr.label);
        model.addAttribute("from", from);
        model.addAttribute("to", to);

        // Keep the existing model contract for the template.
        // Heavy top vendor/product aggregation is loaded asynchronously via dashboard API.
        model.addAttribute("topVendors", List.<TopCountRow>of());
        model.addAttribute("topProducts", List.<TopCountRow>of());

        return "dashboard";
    }
}