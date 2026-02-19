package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import org.springframework.stereotype.Service;

@Service
public class SoftwareDictionaryValidator {

    private final CpeVendorRepository vendorRepo;
    private final CpeProductRepository productRepo;
    private final VendorProductNormalizer normalizer;
    private final SynonymService synonymService;

    public SoftwareDictionaryValidator(
            CpeVendorRepository vendorRepo,
            CpeProductRepository productRepo,
            VendorProductNormalizer normalizer,
            SynonymService synonymService
    ) {
        this.vendorRepo = vendorRepo;
        this.productRepo = productRepo;
        this.normalizer = normalizer;
        this.synonymService = synonymService;
    }

    public Resolve resolve(String vendorRaw, String productRaw) {
        // 1) normalize
        String v0 = normalizer.normalizeVendor(vendorRaw);
        String p0 = normalizer.normalizeProduct(productRaw);

        if (p0 == null) {
            return Resolve.miss(DictionaryValidationException.DictionaryErrorCode.DICT_PRODUCT_REQUIRED,
                    "product", "Product is required.", null, null);
        }

        // 2) synonym
        String v1 = synonymService.canonicalVendorOrSame(v0);
        String p1 = synonymService.canonicalProductOrSame(v1, p0);

        // 3) dictionary lookup
        if (v1 == null || v1.isBlank()) {
            return Resolve.miss(DictionaryValidationException.DictionaryErrorCode.DICT_VENDOR_REQUIRED,
                    "vendor", "Vendor is required (CPE dictionary lookup).", null, p1);
        }

        CpeVendor vendor = vendorRepo.findByNameNorm(v1).orElse(null);
        if (vendor == null) {
            return Resolve.miss(DictionaryValidationException.DictionaryErrorCode.DICT_VENDOR_NOT_FOUND,
                    "vendor", "Vendor not found in CPE dictionary: " + v1, v1, p1);
        }

        CpeProduct prod = productRepo.findByVendorIdAndNameNorm(vendor.getId(), p1).orElse(null);
        if (prod == null) {
            return Resolve.miss(DictionaryValidationException.DictionaryErrorCode.DICT_PRODUCT_NOT_FOUND,
                    "product", "Product not found in CPE dictionary: " + v1 + ":" + p1, v1, p1);
        }

        return Resolve.hit(vendor.getId(), prod.getId(), v1, p1);
    }

    public Resolve resolveOrThrow(String vendorRaw, String productRaw) {
        Resolve r = resolve(vendorRaw, productRaw);
        if (!r.hit()) {
            throw new DictionaryValidationException(
                    r.code(),
                    r.field(),
                    r.message(),
                    r.vendorNorm(),
                    r.productNorm()
            );
        }
        return r;
    }

    public record Resolve(
            boolean hit,
            Long vendorId,
            Long productId,
            String vendorNorm,
            String productNorm,
            DictionaryValidationException.DictionaryErrorCode code,
            String field,
            String message
    ) {
        public static Resolve hit(Long vendorId, Long productId, String vendorNorm, String productNorm) {
            return new Resolve(true, vendorId, productId, vendorNorm, productNorm, null, null, null);
        }
        public static Resolve miss(DictionaryValidationException.DictionaryErrorCode code, String field, String message,
                                   String vendorNorm, String productNorm) {
            return new Resolve(false, null, null, vendorNorm, productNorm, code, field, message);
        }
    }
}
