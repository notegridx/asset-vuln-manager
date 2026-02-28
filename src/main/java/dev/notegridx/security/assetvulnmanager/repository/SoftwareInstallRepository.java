package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface SoftwareInstallRepository extends JpaRepository<SoftwareInstall, Long> {
    List<SoftwareInstall> findByAssetIdOrderByIdAsc(Long assetId);

    long deleteByAssetId(Long assetId);

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

    @EntityGraph(attributePaths = {"asset"})
    @Query("""
            select s from SoftwareInstall s
            where (:assetId is null or s.asset.id = :assetId)
              and (
                    :q is null or :q = ''
                    or lower(coalesce(s.vendor, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.product, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.version, '')) like lower(concat('%', :q, '%'))
                  )
              and (
                    :unmappedCpe is null
                    or (:unmappedCpe = true and (s.cpeName is null or trim(s.cpeName) = ''))
                    or (:unmappedCpe = false and (s.cpeName is not null and trim(s.cpeName) <> ''))
                  )
            order by s.id desc
            """)
    Page<SoftwareInstall> searchPaged(
            @Param("assetId") Long assetId,
            @Param("q") String q,
            @Param("unmappedCpe") Boolean unmappedCpe,
            Pageable pageable
    );

    // =========================================================
    // Bulk apply canonical IDs from Unresolved queue
    // =========================================================

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            update SoftwareInstall s
               set s.cpeVendorId = :vendorId
             where (s.cpeVendorId is null)
               and (s.normalizedVendor = :vendorNorm)
            """)
    int bulkSetCpeVendorIdByNormalizedVendor(
            @Param("vendorId") Long vendorId,
            @Param("vendorNorm") String vendorNorm
    );

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            update SoftwareInstall s
               set s.cpeVendorId = :vendorId,
                   s.cpeProductId = :productId
             where (s.cpeProductId is null)
               and (s.normalizedVendor = :vendorNorm)
               and (s.normalizedProduct = :productNorm)
            """)
    int bulkSetCpeVendorProductIdByNormalizedVendorProduct(
            @Param("vendorId") Long vendorId,
            @Param("productId") Long productId,
            @Param("vendorNorm") String vendorNorm,
            @Param("productNorm") String productNorm
    );

    /**
     * canonical link (cpeVendorId/cpeProductId) が未設定で、
     * normalizedVendor/normalizedProduct がある程度揃っているものを拾う
     */
    @Query("""
            select s from SoftwareInstall s
            where (
                    (s.normalizedVendor is not null and s.normalizedVendor <> '')
                    and (s.cpeVendorId is null)
                  )
               or (
                    (s.normalizedVendor is not null and s.normalizedVendor <> '')
                    and (s.normalizedProduct is not null and s.normalizedProduct <> '')
                    and (s.cpeProductId is null)
                  )
            order by s.id desc
            """)
    List<SoftwareInstall> findNeedsCanonicalLink();
}