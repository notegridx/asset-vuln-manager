package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityAffectedCpeRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Service
public class DashboardTopService {

    private final VulnerabilityAffectedCpeRepository affectedCpeRepository;
    private final CpeVendorRepository cpeVendorRepository;
    private final CpeProductRepository cpeProductRepository;

    public DashboardTopService(
            VulnerabilityAffectedCpeRepository affectedCpeRepository,
            CpeVendorRepository cpeVendorRepository,
            CpeProductRepository cpeProductRepository
    ) {
        this.affectedCpeRepository = affectedCpeRepository;
        this.cpeVendorRepository = cpeVendorRepository;
        this.cpeProductRepository = cpeProductRepository;
    }

    public record TopCountRow(Long id, String label, long cnt) {}

    public record TopResponse(
            List<TopCountRow> vendors,
            List<TopCountRow> products
    ) {}

    @Transactional(readOnly = true)
    public TopResponse load(LocalDateTime from, LocalDateTime to, int limit) {
        int lim = Math.max(1, Math.min(limit, 50));

        List<Object[]> vendorRows = affectedCpeRepository
                .countTopVendorsByDistinctCvesWithinLastModified(from, to, PageRequest.of(0, lim));

        List<Object[]> productRows = affectedCpeRepository
                .countTopProductsByDistinctCvesWithinLastModified(from, to, PageRequest.of(0, lim));

        return new TopResponse(
                resolveVendorRows(vendorRows),
                resolveProductRows(productRows)
        );
    }

    private List<TopCountRow> resolveVendorRows(List<Object[]> rows) {
        if (rows == null || rows.isEmpty()) {
            return List.of();
        }

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
        if (rows == null || rows.isEmpty()) {
            return List.of();
        }

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
}