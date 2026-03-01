package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import org.springframework.stereotype.Service;

@Service
public class CanonicalResolver {

    private final CpeVendorRepository vendorRepo;
    private final CpeProductRepository productRepo;

    public CanonicalResolver(CpeVendorRepository vendorRepo, CpeProductRepository productRepo) {
        this.vendorRepo = vendorRepo;
        this.productRepo = productRepo;
    }

    public CpeVendor requireVendorByNorm(String vendorNorm) {
        return vendorRepo.findByNameNorm(vendorNorm)
                .orElseThrow(() -> new IllegalStateException("CPE vendor not found: " + vendorNorm));
    }

    public CpeProduct requireProductByNorm(Long vendorId, String productNorm) {
        return productRepo.findByVendorIdAndNameNorm(vendorId, productNorm)
                .orElseThrow(() -> new IllegalStateException("CPE product not found: vendorId=" + vendorId + " product=" + productNorm));
    }
}