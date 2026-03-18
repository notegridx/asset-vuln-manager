package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityAffectedCpeRepository;
import dev.notegridx.security.assetvulnmanager.service.DashboardTopService;
import org.springframework.data.domain.PageRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;

@RestController
public class DashboardApiController {

    private final VulnerabilityAffectedCpeRepository affectedCpeRepository;
    private final CpeProductRepository cpeProductRepository;
    private final CpeVendorRepository cpeVendorRepository;
    private final DashboardTopService dashboardTopService;

    public DashboardApiController(
            VulnerabilityAffectedCpeRepository affectedCpeRepository,
            CpeProductRepository cpeProductRepository,
            CpeVendorRepository cpeVendorRepository,
            DashboardTopService dashboardTopService
    ) {
        this.affectedCpeRepository = affectedCpeRepository;
        this.cpeProductRepository = cpeProductRepository;
        this.cpeVendorRepository = cpeVendorRepository;
        this.dashboardTopService = dashboardTopService;
    }

    public record TopCountRow(Long id, String label, long cnt) {}

    public record TopProductsResponse(
            Long vendorId,
            String vendorLabel,
            List<TopCountRow> rows
    ) {}

    public record TopResponse(
            List<TopCountRow> vendors,
            List<TopCountRow> products
    ) {}

    @GetMapping("/api/dashboard/top")
    public TopResponse top(
            @RequestParam(name = "from", required = false) LocalDateTime from,
            @RequestParam(name = "to", required = false) LocalDateTime to,
            @RequestParam(name = "limit", defaultValue = "10") int limit
    ) {
        DashboardTopService.TopResponse r = dashboardTopService.load(from, to, limit);

        return new TopResponse(
                r.vendors().stream()
                        .map(x -> new TopCountRow(x.id(), x.label(), x.cnt()))
                        .toList(),
                r.products().stream()
                        .map(x -> new TopCountRow(x.id(), x.label(), x.cnt()))
                        .toList()
        );
    }

    @GetMapping("/api/dashboard/top-products")
    public TopProductsResponse topProductsByVendor(
            @RequestParam("vendorId") Long vendorId,
            @RequestParam(name = "limit", defaultValue = "10") int limit
    ) {
        if (vendorId == null) {
            return new TopProductsResponse(null, null, List.of());
        }

        String vendorLabel = "vendor#" + vendorId;
        Optional<CpeVendor> vOpt = cpeVendorRepository.findById(vendorId);
        if (vOpt.isPresent()) {
            CpeVendor v = vOpt.get();
            vendorLabel = (v.getDisplayName() == null || v.getDisplayName().isBlank())
                    ? v.getNameNorm()
                    : v.getDisplayName();
        }

        List<Object[]> rows = affectedCpeRepository
                .countTopProductsByDistinctCvesForVendor(vendorId, PageRequest.of(0, Math.max(1, limit)));

        List<Long> productIds = rows.stream()
                .map(r -> (Long) r[0])
                .filter(Objects::nonNull)
                .toList();

        Map<Long, CpeProduct> productById = new HashMap<>();
        if (!productIds.isEmpty()) {
            for (CpeProduct p : cpeProductRepository.findAllById(productIds)) {
                productById.put(p.getId(), p);
            }
        }

        List<TopCountRow> out = rows.stream()
                .map(r -> {
                    Long id = (Long) r[0];
                    long cnt = ((Number) r[1]).longValue();
                    CpeProduct p = productById.get(id);
                    String label = (p == null)
                            ? ("product#" + id)
                            : ((p.getDisplayName() == null || p.getDisplayName().isBlank())
                            ? p.getNameNorm()
                            : p.getDisplayName());
                    return new TopCountRow(id, label, cnt);
                })
                .toList();

        return new TopProductsResponse(vendorId, vendorLabel, out);
    }

    public record TopCveCountResponse(
            String range,
            String rangeLabel,
            List<TopCountRow> vendors,
            List<TopCountRow> products
    ) {}

    @GetMapping("/api/dashboard/top-cve-count")
    public TopCveCountResponse topCveCount(
            @RequestParam(name = "range", defaultValue = "ALL") String range,
            @RequestParam(name = "from", required = false) String from,
            @RequestParam(name = "to", required = false) String to,
            @RequestParam(name = "limit", defaultValue = "10") int limit
    ) {
        int lim = Math.max(1, Math.min(limit, 50));

        LocalDateTime fromDt = null;
        LocalDateTime toDt = null;

        LocalDate today = LocalDate.now();

        switch (range) {
            case "D7" -> fromDt = today.minusDays(7).atStartOfDay();
            case "D30" -> fromDt = today.minusDays(30).atStartOfDay();
            case "D90" -> fromDt = today.minusDays(90).atStartOfDay();
            case "D180" -> fromDt = today.minusDays(180).atStartOfDay();
            case "D365" -> fromDt = today.minusDays(365).atStartOfDay();
            case "YTD" -> fromDt = today.withDayOfYear(1).atStartOfDay();
            case "CUSTOM" -> {
                if (from != null && !from.isBlank()) {
                    fromDt = LocalDate.parse(from).atStartOfDay();
                }
                if (to != null && !to.isBlank()) {
                    // Inclusive end-date handling: [from, to+1day)
                    toDt = LocalDate.parse(to).plusDays(1).atStartOfDay();
                }
            }
            default -> {
                // ALL: keep from/to as null
            }
        }

        DashboardTopService.TopResponse r = dashboardTopService.load(fromDt, toDt, lim);

        List<TopCountRow> vendors = r.vendors().stream()
                .map(x -> new TopCountRow(x.id(), x.label(), x.cnt()))
                .toList();

        List<TopCountRow> products = r.products().stream()
                .map(x -> new TopCountRow(x.id(), x.label(), x.cnt()))
                .toList();

        return new TopCveCountResponse(range, toRangeLabel(range, from, to), vendors, products);
    }

    private List<TopCountRow> resolveVendorRows(List<Object[]> rows) {
        if (rows == null || rows.isEmpty()) return List.of();

        List<Long> ids = rows.stream()
                .map(r -> (Long) r[0])
                .filter(Objects::nonNull)
                .toList();

        Map<Long, CpeVendor> byId = new HashMap<>();
        if (!ids.isEmpty()) {
            for (CpeVendor v : cpeVendorRepository.findAllById(ids)) {
                byId.put(v.getId(), v);
            }
        }

        return rows.stream()
                .map(r -> {
                    Long id = (Long) r[0];
                    long cnt = ((Number) r[1]).longValue();
                    CpeVendor v = byId.get(id);
                    String label = (v == null)
                            ? ("vendor#" + id)
                            : ((v.getDisplayName() == null || v.getDisplayName().isBlank())
                            ? v.getNameNorm()
                            : v.getDisplayName());
                    return new TopCountRow(id, label, cnt);
                })
                .toList();
    }

    private List<TopCountRow> resolveProductRows(List<Object[]> rows) {
        if (rows == null || rows.isEmpty()) return List.of();

        List<Long> ids = rows.stream()
                .map(r -> (Long) r[0])
                .filter(Objects::nonNull)
                .toList();

        Map<Long, CpeProduct> byId = new HashMap<>();
        if (!ids.isEmpty()) {
            for (CpeProduct p : cpeProductRepository.findAllById(ids)) {
                byId.put(p.getId(), p);
            }
        }

        return rows.stream()
                .map(r -> {
                    Long id = (Long) r[0];
                    long cnt = ((Number) r[1]).longValue();
                    CpeProduct p = byId.get(id);
                    String label = (p == null)
                            ? ("product#" + id)
                            : ((p.getDisplayName() == null || p.getDisplayName().isBlank())
                            ? p.getNameNorm()
                            : p.getDisplayName());
                    return new TopCountRow(id, label, cnt);
                })
                .toList();
    }

    private String toRangeLabel(String range, String from, String to) {
        return switch (range) {
            case "D7" -> "Last 7 days";
            case "D30" -> "Last 30 days";
            case "D90" -> "Last 90 days";
            case "D180" -> "Last 180 days";
            case "D365" -> "Last 365 days";
            case "YTD" -> "Year to date";
            case "CUSTOM" -> "Custom" + ((from != null && !from.isBlank()) ? (" (" + from + "…") : "")
                    + ((to != null && !to.isBlank()) ? (to + ")") : "");
            default -> "All time";
        };
    }
}