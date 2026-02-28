package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.CpeVendorAlias;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CpeVendorAliasRepository extends JpaRepository<CpeVendorAlias, Long> {

    Optional<CpeVendorAlias> findFirstByAliasNormAndStatusIgnoreCase(String aliasNorm, String status);
}