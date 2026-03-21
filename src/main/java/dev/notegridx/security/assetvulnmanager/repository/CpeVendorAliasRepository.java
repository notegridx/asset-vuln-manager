package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.CpeVendorAlias;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface CpeVendorAliasRepository extends JpaRepository<CpeVendorAlias, Long> {

    Optional<CpeVendorAlias> findFirstByAliasNormAndStatusIgnoreCase(String aliasNorm, String status);

    Optional<CpeVendorAlias> findByAliasNorm(String aliasNorm);

    @Query("""
           select a
           from CpeVendorAlias a
           where (:q is null or :q = '' or lower(a.aliasNorm) like lower(concat('%', :q, '%')))
             and (:status is null or :status = '' or lower(a.status) = lower(:status))
           order by a.id desc
           """)
    List<CpeVendorAlias> search(@Param("q") String q, @Param("status") String status, Pageable pageable);

    @Query("""
           select distinct a.cpeVendorId
           from CpeVendorAlias a
           where a.cpeVendorId is not null
           order by a.cpeVendorId
           """)
    List<Long> findDistinctCanonicalVendorIds();
}