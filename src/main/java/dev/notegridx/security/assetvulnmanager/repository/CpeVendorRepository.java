package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface CpeVendorRepository extends JpaRepository<CpeVendor, Long> {

    /**
     * Finds a vendor by normalized name.
     * Expected to return at most one result.
     */
    Optional<CpeVendor> findByNameNorm(String nameNorm);

    /**
     * Checks existence of a vendor by normalized name.
     */
    boolean existsByNameNorm(String nameNorm);

    /**
     * Prefix-based suggestion.
     * Returns up to 20 results ordered by normalized name.
     */
    List<CpeVendor> findTop20ByNameNormStartingWithOrderByNameNormAsc(String prefix);

    /**
     * Contains-based suggestion.
     * Returns up to 20 results ordered by normalized name.
     */
    List<CpeVendor> findTop20ByNameNormContainingOrderByNameNormAsc(String q);

    /**
     * Exact match (case-insensitive).
     * Used for strict equality checks in candidate resolution.
     */
    @Query("""
    select v from CpeVendor v
    where lower(v.nameNorm) = lower(:q)
    order by v.nameNorm asc
""")
    List<CpeVendor> findExact(@Param("q") String q);

    /**
     * Prefix match (case-insensitive) with shorter names prioritized.
     * Ordering by length helps surface more canonical/concise names first.
     */
    @Query("""
    select v from CpeVendor v
    where lower(v.nameNorm) like lower(concat(:q, '%'))
    order by length(v.nameNorm) asc
""")
    List<CpeVendor> findPrefixOrderByLength(@Param("q") String q);

    /**
     * Contains match (case-insensitive) with shorter names prioritized.
     * Used as a fallback when prefix matching does not yield sufficient results.
     */
    @Query("""
    select v from CpeVendor v
    where lower(v.nameNorm) like lower(concat('%', :q, '%'))
    order by length(v.nameNorm) asc
""")
    List<CpeVendor> findContainsOrderByLength(@Param("q") String q);
}