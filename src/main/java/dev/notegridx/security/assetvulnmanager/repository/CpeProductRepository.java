package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface CpeProductRepository extends JpaRepository<CpeProduct, Long> {

    /**
     * Finds a product by vendor ID and normalized product name.
     * Expected to return at most one result.
     */
    Optional<CpeProduct> findByVendorIdAndNameNorm(Long vendorId, String nameNorm);

    /**
     * Checks existence of a product for a given vendor and normalized name.
     */
    boolean existsByVendorIdAndNameNorm(Long vendorId, String nameNorm);

    /**
     * Bulk lookup for products by vendor and a set of normalized names.
     */
    List<CpeProduct> findByVendorIdAndNameNormIn(Long vendorId, Collection<String> nameNorms);

    /**
     * Prefix-based suggestion (vendor-scoped).
     * Returns up to 20 results ordered by normalized name.
     */
    List<CpeProduct> findTop20ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(Long vendorId, String prefix);

    /**
     * Contains-based suggestion (vendor-scoped).
     * Returns up to 20 results ordered by normalized name.
     */
    List<CpeProduct> findTop20ByVendorIdAndNameNormContainingOrderByNameNormAsc(Long vendorId, String q);

    /**
     * Exact match within a vendor (case-insensitive).
     * Used when strict equality is required for candidate resolution.
     */
    @Query("""
  select p from CpeProduct p
  where p.vendor.id = :vendorId and lower(p.nameNorm) = lower(:nameNorm)
""")
    List<CpeProduct> findExactByVendorId(@Param("vendorId") Long vendorId, @Param("nameNorm") String nameNorm);

    /**
     * Extended prefix search (up to 50 results).
     * Typically used for grouping or secondary candidate expansion.
     */
    List<CpeProduct> findTop50ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(Long vendorId, String nameNorm);

    /**
     * Fallback contains search using explicit JPQL.
     * Case-insensitive match with ordering by normalized name.
     * Returns up to 50 results.
     */
    @Query("""
  select p from CpeProduct p
  where p.vendor.id = :vendorId and lower(p.nameNorm) like lower(concat('%', :q, '%'))
  order by p.nameNorm asc
""")
    List<CpeProduct> findTop50ByVendorIdAndNameNormContainsOrderByNameNormAsc(@Param("vendorId") Long vendorId, @Param("q") String q);

    /**
     * Wide contains search (up to 200 results).
     * Used when broader recall is needed after narrower queries.
     */
    List<CpeProduct> findTop200ByVendorIdAndNameNormContainingOrderByNameNormAsc(Long vendorId, String q);
}