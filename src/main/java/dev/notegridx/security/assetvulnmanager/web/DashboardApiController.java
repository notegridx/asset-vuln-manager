package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityAffectedCpeRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

@RestController
public class DashboardApiController {

    private final VulnerabilityAffectedCpeRepository affectedCpeRepository;
    private final CpeProductRepository cpeProductRepository;
    private final CpeVendorRepository cpeVendorRepository;

    public DashboardApiController(
            VulnerabilityAffectedCpeRepository affectedCpeRepository,
            CpeProductRepository cpeProductRepository,
            CpeVendorRepository cpeVendorRepository
    ) {
        this.affectedCpeRepository = affectedCpeRepository;
        this.cpeProductRepository = cpeProductRepository;
        this.cpeVendorRepository = cpeVendorRepository;
    }

    public record TopCountRow(Long id, String label, long cnt) {}

    public record TopProductsResponse(
            Long vendorId,
            String vendorLabel,
            List<TopCountRow> rows
    ) {}

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
}