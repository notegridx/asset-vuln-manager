package dev.notegridx.security.assetvulnmanager.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;

import java.util.Optional;

public interface UnresolvedMappingRepository extends JpaRepository<UnresolvedMapping, Long> {

    Optional<UnresolvedMapping>
    findTopBySourceAndVendorRawAndProductRawAndVersionRaw(
            String source,
            String vendorRaw,
            String productRaw,
            String versionRaw
    );
}