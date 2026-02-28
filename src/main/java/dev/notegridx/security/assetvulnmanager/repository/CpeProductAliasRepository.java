package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.CpeProductAlias;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CpeProductAliasRepository extends JpaRepository<CpeProductAlias, Long> {

    Optional<CpeProductAlias> findFirstByCpeVendorIdAndAliasNormAndStatusIgnoreCase(
            Long cpeVendorId,
            String aliasNorm,
            String status
    );
}