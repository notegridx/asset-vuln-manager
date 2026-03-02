package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface UnresolvedMappingRepository extends JpaRepository<UnresolvedMapping, Long> {

    Optional<UnresolvedMapping>
    findTopBySourceAndVendorRawAndProductRawAndVersionRaw(
            String source,
            String vendorRaw,
            String productRaw,
            String versionRaw
    );

    /**
     * Active unresolved mappings only:
     * those whose (source + raw vendor/product/version) still exist in software_installs.
     *
     * NOTE:
     * - software_installs has both vendor_raw/product_raw/version_raw and vendor/product/version;
     *   unresolved is created using coalesce(vendorRaw, vendor) etc.
     * - so this query also uses the same coalesce logic on the software side.
     */
    @Query("""
        select um
        from UnresolvedMapping um
        where exists (
            select 1
            from SoftwareInstall s
            where lower(trim(s.source)) = lower(trim(um.source))
              and lower(trim(coalesce(s.vendorRaw, s.vendor))) = lower(trim(um.vendorRaw))
              and lower(trim(coalesce(s.productRaw, s.product))) = lower(trim(um.productRaw))
              and lower(trim(coalesce(s.versionRaw, s.version))) = lower(trim(um.versionRaw))
        )
        """)
    List<UnresolvedMapping> findAllActive();
}