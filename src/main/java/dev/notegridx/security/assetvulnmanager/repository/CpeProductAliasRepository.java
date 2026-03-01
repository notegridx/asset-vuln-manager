package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.CpeProductAlias;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface CpeProductAliasRepository extends JpaRepository<CpeProductAlias, Long> {

    Optional<CpeProductAlias> findFirstByCpeVendorIdAndAliasNormAndStatusIgnoreCase(Long cpeVendorId, String aliasNorm, String status);

    @Query("""
           select a
           from CpeProductAlias a
           where (:vendorId is null or a.cpeVendorId = :vendorId)
             and (:q is null or :q = '' or lower(a.aliasNorm) like lower(concat('%', :q, '%')))
             and (:status is null or :status = '' or lower(a.status) = lower(:status))
           order by a.id desc
           """)
    List<CpeProductAlias> search(
            @Param("vendorId") Long vendorId,
            @Param("q") String q,
            @Param("status") String status,
            Pageable pageable
    );
}