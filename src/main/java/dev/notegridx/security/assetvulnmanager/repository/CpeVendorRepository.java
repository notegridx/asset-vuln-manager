package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface CpeVendorRepository extends JpaRepository<CpeVendor, Long> {

    Optional<CpeVendor> findByNameNorm(String nameNorm);

    boolean existsByNameNorm(String nameNorm);

    // 前方一致サジェスト用
    List<CpeVendor> findTop20ByNameNormStartingWithOrderByNameNormAsc(String prefix);
}