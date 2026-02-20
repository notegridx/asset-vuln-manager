package dev.notegridx.security.assetvulnmanager.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import org.springframework.data.jpa.repository.Query;

public interface SoftwareInstallRepository extends JpaRepository<SoftwareInstall, Long> {

    List<SoftwareInstall> findByCpeNameIsNotNull();

    List<SoftwareInstall> findByAssetIdOrderByIdDesc(Long assetId);

    List<SoftwareInstall> findByNormalizedVendorAndNormalizedProduct(String normalizedVendor, String normalizedProduct);

    Optional<SoftwareInstall> findByAssetIdAndVendorAndProductAndVersion(
            Long assetId, String vendor, String product, String version);

    boolean existsByAssetIdAndVendorAndProductAndVersion(
            Long assetId, String vendor, String product, String version);

    List<SoftwareInstall> findTop500ByNormalizedProductIsNullOrNormalizedProductOrderByIdDesc(String normalizedProduct);

    @Query("""
            select s from SoftwareInstall s
            where (s.normalizedProduct is null or s.normalizedProduct = '')
            or (s.normalizedVendor is null)
            """)
    List<SoftwareInstall> findNeedsNormalization();

    @Query("""
           select count(s)
           from SoftwareInstall s
           where s.cpeName is null or trim(s.cpeName) = ''
           """)
    long countUnmappedCpe();
}
