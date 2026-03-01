package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface CpeVendorRepository extends JpaRepository<CpeVendor, Long> {

    Optional<CpeVendor> findByNameNorm(String nameNorm);

    boolean existsByNameNorm(String nameNorm);

    // 前方一致サジェスト用
    List<CpeVendor> findTop20ByNameNormStartingWithOrderByNameNormAsc(String prefix);

    List<CpeVendor> findTop20ByNameNormContainingOrderByNameNormAsc(String q);

    @Query("""
    select v from CpeVendor v
    where lower(v.nameNorm) = lower(:q)
    order by v.nameNorm asc
""")
    List<CpeVendor> findExact(@Param("q") String q);

    @Query("""
    select v from CpeVendor v
    where lower(v.nameNorm) like lower(concat(:q, '%'))
    order by length(v.nameNorm) asc
""")
    List<CpeVendor> findPrefixOrderByLength(@Param("q") String q);

    @Query("""
    select v from CpeVendor v
    where lower(v.nameNorm) like lower(concat('%', :q, '%'))
    order by length(v.nameNorm) asc
""")
    List<CpeVendor> findContainsOrderByLength(@Param("q") String q);
}