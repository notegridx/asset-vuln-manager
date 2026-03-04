package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface CpeProductRepository extends JpaRepository<CpeProduct, Long> {

    Optional<CpeProduct> findByVendorIdAndNameNorm(Long vendorId, String nameNorm);

    boolean existsByVendorIdAndNameNorm(Long vendorId, String nameNorm);

    // 前方一致サジェスト用（vendor scope）
    List<CpeProduct> findTop20ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(Long vendorId, String prefix);

    List<CpeProduct> findTop20ByVendorIdAndNameNormContainingOrderByNameNormAsc(Long vendorId, String q);

    // exact within vendor
    @Query("""
  select p from CpeProduct p
  where p.vendor.id = :vendorId and lower(p.nameNorm) = lower(:nameNorm)
""")
    List<CpeProduct> findExactByVendorId(@Param("vendorId") Long vendorId, @Param("nameNorm") String nameNorm);

    // prefix more than 20 (for grouping)
    List<CpeProduct> findTop50ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(Long vendorId, String nameNorm);

    // contains (fallback)
    @Query("""
  select p from CpeProduct p
  where p.vendor.id = :vendorId and lower(p.nameNorm) like lower(concat('%', :q, '%'))
  order by p.nameNorm asc
""")
    List<CpeProduct> findTop50ByVendorIdAndNameNormContainsOrderByNameNormAsc(@Param("vendorId") Long vendorId, @Param("q") String q);

    List<CpeProduct> findTop200ByVendorIdAndNameNormContainingOrderByNameNormAsc(Long vendorId, String q);
}