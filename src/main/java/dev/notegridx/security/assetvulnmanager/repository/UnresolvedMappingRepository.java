package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface UnresolvedMappingRepository extends JpaRepository<UnresolvedMapping, Long> {

    Optional<UnresolvedMapping>
    findTopByVendorRawAndProductRaw(
            String vendorRaw,
            String productRaw
    );

    /**
     * Active unresolved mappings only:
     * those whose raw vendor/product still exist in software_installs.
     *
     * NOTE:
     * - software_installs has both vendor_raw/product_raw and vendor/product;
     *   unresolved is created using coalesce(vendorRaw, vendor) etc.
     * - so this query also uses the same coalesce logic on the software side.
     * - source/version are kept on unresolved_mappings as reference fields only,
     *   and are not used for active existence checks.
     */
    @Query("""
    select um
    from UnresolvedMapping um
    where exists (
        select 1
        from SoftwareInstall s
        where lower(trim(coalesce(s.vendorRaw, s.vendor))) = lower(trim(um.vendorRaw))
          and lower(trim(coalesce(s.productRaw, s.product))) = lower(trim(um.productRaw))
    )
    """)
    List<UnresolvedMapping> findAllActive();
}