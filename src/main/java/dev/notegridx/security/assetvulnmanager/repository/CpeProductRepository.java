package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface CpeProductRepository extends JpaRepository<CpeProduct, Long> {

    Optional<CpeProduct> findByVendorIdAndNameNorm(Long vendorId, String nameNorm);

    boolean existsByVendorIdAndNameNorm(Long vendorId, String nameNorm);

    // 前方一致サジェスト用
    List<CpeProduct> findTop20ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(Long vendorId, String prefix);
}