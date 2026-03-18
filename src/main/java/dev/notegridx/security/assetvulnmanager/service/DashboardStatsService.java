package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.enums.AlertCertainty;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus;
import dev.notegridx.security.assetvulnmanager.domain.enums.Severity;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.DashboardStatsRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

@Service
public class DashboardStatsService {

    private final AssetRepository assetRepository;
    private final SoftwareInstallRepository softwareInstallRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final CpeVendorRepository cpeVendorRepository;
    private final CpeProductRepository cpeProductRepository;
    private final DashboardStatsRepository dashboardStatsRepository;

    public DashboardStatsService(
            AssetRepository assetRepository,
            SoftwareInstallRepository softwareInstallRepository,
            VulnerabilityRepository vulnerabilityRepository,
            CpeVendorRepository cpeVendorRepository,
            CpeProductRepository cpeProductRepository,
            DashboardStatsRepository dashboardStatsRepository
    ) {
        this.assetRepository = assetRepository;
        this.softwareInstallRepository = softwareInstallRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.cpeVendorRepository = cpeVendorRepository;
        this.cpeProductRepository = cpeProductRepository;
        this.dashboardStatsRepository = dashboardStatsRepository;
    }

    @Transactional(readOnly = true)
    public DashboardViewStats load() {
        // Basic counts
        long assets = assetRepository.count();
        long installs = softwareInstallRepository.count();
        long vulns = vulnerabilityRepository.count();

        // Count of installs that are not mapped to canonical CPE
        long unmappedInstalls = softwareInstallRepository.countUnmappedCpe();

        // Dictionary size
        long cpeVendors = cpeVendorRepository.count();
        long cpeProducts = cpeProductRepository.count();

        // Aggregate OPEN alerts in a single query (grouped by severity and certainty)
        List<DashboardStatsRepository.OpenAlertBreakdownRow> rows =
                dashboardStatsRepository.aggregateAlertBreakdownBySeverityAndCertainty(AlertStatus.OPEN);

        AlertMatrix matrix = AlertMatrix.from(rows);

        // Keep the same logic as current DashboardController
        boolean needsSetup = (assets == 0L) || (vulns == 0L) || (cpeVendors == 0L);

        return new DashboardViewStats(
                assets,
                installs,
                vulns,

                matrix.openAlerts(),
                matrix.openAlertsConfirmed(),
                matrix.openAlertsUnconfirmed(),

                matrix.openAlertsCritical(),
                matrix.openAlertsCriticalConfirmed(),
                matrix.openAlertsCriticalUnconfirmed(),

                matrix.openAlertsHigh(),
                matrix.openAlertsHighConfirmed(),
                matrix.openAlertsHighUnconfirmed(),

                matrix.openAlertsMedium(),
                matrix.openAlertsMediumConfirmed(),
                matrix.openAlertsMediumUnconfirmed(),

                matrix.openAlertsLow(),
                matrix.openAlertsLowConfirmed(),
                matrix.openAlertsLowUnconfirmed(),

                unmappedInstalls,
                cpeVendors,
                cpeProducts,
                needsSetup
        );
    }

    public record DashboardViewStats(
            long assets,
            long installs,
            long vulns,

            long openAlerts,
            long openAlertsConfirmed,
            long openAlertsUnconfirmed,

            long openAlertsCritical,
            long openAlertsCriticalConfirmed,
            long openAlertsCriticalUnconfirmed,

            long openAlertsHigh,
            long openAlertsHighConfirmed,
            long openAlertsHighUnconfirmed,

            long openAlertsMedium,
            long openAlertsMediumConfirmed,
            long openAlertsMediumUnconfirmed,

            long openAlertsLow,
            long openAlertsLowConfirmed,
            long openAlertsLowUnconfirmed,

            long unmappedInstalls,
            long cpeVendors,
            long cpeProducts,
            boolean needsSetup
    ) {
    }

    /**
     * Holds aggregated alert counts and provides derived metrics.
     * This replaces multiple count queries with a single grouped query.
     */
    private static final class AlertMatrix {

        private final Map<Severity, Long> totalBySeverity = new EnumMap<>(Severity.class);
        private final Map<Severity, Long> confirmedBySeverity = new EnumMap<>(Severity.class);
        private final Map<Severity, Long> unconfirmedBySeverity = new EnumMap<>(Severity.class);

        private long openAlerts;
        private long openAlertsConfirmed;
        private long openAlertsUnconfirmed;

        static AlertMatrix from(List<DashboardStatsRepository.OpenAlertBreakdownRow> rows) {
            AlertMatrix m = new AlertMatrix();

            // Initialize all severities to zero
            for (Severity severity : Severity.values()) {
                m.totalBySeverity.put(severity, 0L);
                m.confirmedBySeverity.put(severity, 0L);
                m.unconfirmedBySeverity.put(severity, 0L);
            }

            if (rows == null || rows.isEmpty()) {
                return m;
            }

            for (DashboardStatsRepository.OpenAlertBreakdownRow row : rows) {
                Severity severity = row.getSeverity();
                AlertCertainty certainty = row.getCertainty();
                long cnt = row.getCnt();

                // Skip rows without severity (should not normally happen)
                if (severity == null) {
                    continue;
                }

                // Total OPEN alerts
                m.openAlerts += cnt;
                m.totalBySeverity.merge(severity, cnt, Long::sum);

                // Split by certainty
                if (certainty == AlertCertainty.CONFIRMED) {
                    m.openAlertsConfirmed += cnt;
                    m.confirmedBySeverity.merge(severity, cnt, Long::sum);
                } else if (certainty == AlertCertainty.UNCONFIRMED) {
                    m.openAlertsUnconfirmed += cnt;
                    m.unconfirmedBySeverity.merge(severity, cnt, Long::sum);
                } else {
                    // Future-proof: if new certainty values are added, they still count in total
                }
            }

            return m;
        }

        long openAlerts() {
            return openAlerts;
        }

        long openAlertsConfirmed() {
            return openAlertsConfirmed;
        }

        long openAlertsUnconfirmed() {
            return openAlertsUnconfirmed;
        }

        long openAlertsCritical() {
            return total(Severity.CRITICAL);
        }

        long openAlertsCriticalConfirmed() {
            return confirmed(Severity.CRITICAL);
        }

        long openAlertsCriticalUnconfirmed() {
            return unconfirmed(Severity.CRITICAL);
        }

        long openAlertsHigh() {
            return total(Severity.HIGH);
        }

        long openAlertsHighConfirmed() {
            return confirmed(Severity.HIGH);
        }

        long openAlertsHighUnconfirmed() {
            return unconfirmed(Severity.HIGH);
        }

        long openAlertsMedium() {
            return total(Severity.MEDIUM);
        }

        long openAlertsMediumConfirmed() {
            return confirmed(Severity.MEDIUM);
        }

        long openAlertsMediumUnconfirmed() {
            return unconfirmed(Severity.MEDIUM);
        }

        long openAlertsLow() {
            return total(Severity.LOW);
        }

        long openAlertsLowConfirmed() {
            return confirmed(Severity.LOW);
        }

        long openAlertsLowUnconfirmed() {
            return unconfirmed(Severity.LOW);
        }

        private long total(Severity severity) {
            return totalBySeverity.getOrDefault(severity, 0L);
        }

        private long confirmed(Severity severity) {
            return confirmedBySeverity.getOrDefault(severity, 0L);
        }

        private long unconfirmed(Severity severity) {
            return unconfirmedBySeverity.getOrDefault(severity, 0L);
        }
    }
}