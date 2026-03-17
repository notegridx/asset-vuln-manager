package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface SoftwareInstallRepository extends JpaRepository<SoftwareInstall, Long> {

    @EntityGraph(attributePaths = {"asset"})
    @Query("""
            select s from SoftwareInstall s
            order by s.id asc
            """)
    List<SoftwareInstall> findAllWithAsset();

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

    /**
     * Paged search for /software list with SQL-level link status filtering.
     * This avoids loading the full software inventory into memory before paging.
     *
     * Supported linkStatus values:
     * - null / ALL       : no link filter
     * - LINKED           : both cpeVendorId and cpeProductId are present
     * - NOT_LINKED       : either cpeVendorId or cpeProductId is missing
     */
    @EntityGraph(attributePaths = {"asset"})
    @Query("""
            select s from SoftwareInstall s
            where (:assetId is null or s.asset.id = :assetId)
              and (
                    :q is null or :q = ''
                    or lower(coalesce(s.vendorRaw, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.vendor, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.normalizedVendor, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.productRaw, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.product, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.normalizedProduct, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.versionRaw, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.version, '')) like lower(concat('%', :q, '%'))
                  )
              and (
                    :linkStatus is null
                    or :linkStatus = 'ALL'
                    or (:linkStatus = 'LINKED' and s.cpeVendorId is not null and s.cpeProductId is not null)
                    or (:linkStatus = 'NOT_LINKED' and (s.cpeVendorId is null or s.cpeProductId is null))
                  )
            order by s.id desc
            """)
    Page<SoftwareInstall> searchPaged(
            @Param("assetId") Long assetId,
            @Param("q") String q,
            @Param("linkStatus") String linkStatus,
            Pageable pageable
    );

    // =========================================================
    // /admin/canonical optimized reads
    // - SQL-pageable filters only: all / fullyLinked / vendorOnlyLinked / notLinked
    // =========================================================

    @EntityGraph(attributePaths = {"asset"})
    @Query("""
            select s from SoftwareInstall s
            where (:assetId is null or s.asset.id = :assetId)
              and (:assetName is null or lower(coalesce(s.asset.name, '')) like lower(concat('%', :assetName, '%')))
              and (
                    :q is null or :q = ''
                    or lower(coalesce(s.vendorRaw, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.productRaw, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.versionRaw, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.normalizedVendor, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.normalizedProduct, '')) like lower(concat('%', :q, '%'))
                  )
              and (
                    :linkState = 'all'
                    or (:linkState = 'fullyLinked' and s.cpeVendorId is not null and s.cpeProductId is not null)
                    or (:linkState = 'vendorOnlyLinked' and s.cpeVendorId is not null and s.cpeProductId is null)
                    or (:linkState = 'notLinked' and s.cpeVendorId is null and s.cpeProductId is null)
                  )
            order by s.id desc
            """)
    Page<SoftwareInstall> findCanonicalSqlPage(
            @Param("assetId") Long assetId,
            @Param("assetName") String assetName,
            @Param("q") String q,
            @Param("linkState") String linkState,
            Pageable pageable
    );

    @EntityGraph(attributePaths = {"asset"})
    @Query("""
            select s from SoftwareInstall s
            where (:assetId is null or s.asset.id = :assetId)
              and (:assetName is null or lower(coalesce(s.asset.name, '')) like lower(concat('%', :assetName, '%')))
              and (
                    :q is null or :q = ''
                    or lower(coalesce(s.vendorRaw, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.productRaw, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.versionRaw, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.normalizedVendor, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.normalizedProduct, '')) like lower(concat('%', :q, '%'))
                  )
            order by s.id desc
            """)
    List<SoftwareInstall> findCanonicalBaseRows(
            @Param("assetId") Long assetId,
            @Param("assetName") String assetName,
            @Param("q") String q
    );

    // =========================================================
    // Bulk apply canonical IDs from Unresolved queue (normalized match)
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

    // =========================================================
    // Bulk apply canonical IDs (raw/display coalesce match)
    // - match logic aligns with UnresolvedMappingRepository.findAllActive()
    // =========================================================

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            update SoftwareInstall s
               set s.cpeVendorId = :vendorId
             where (s.cpeVendorId is null)
               and lower(trim(coalesce(s.vendorRaw, s.vendor))) = lower(trim(:vendorRaw))
            """)
    int bulkSetCpeVendorIdByVendorRawCoalesce(
            @Param("vendorId") Long vendorId,
            @Param("vendorRaw") String vendorRaw
    );

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            update SoftwareInstall s
               set s.cpeVendorId = :vendorId,
                   s.cpeProductId = :productId
             where (s.cpeProductId is null)
               and lower(trim(coalesce(s.vendorRaw, s.vendor))) = lower(trim(:vendorRaw))
               and lower(trim(coalesce(s.productRaw, s.product))) = lower(trim(:productRaw))
            """)
    int bulkSetCpeVendorProductIdByVendorProductRawCoalesce(
            @Param("vendorId") Long vendorId,
            @Param("productId") Long productId,
            @Param("vendorRaw") String vendorRaw,
            @Param("productRaw") String productRaw
    );

    /**
     * Select rows that still need canonical linking.
     * Rows are included when normalized vendor/product data exists
     * but canonical vendor/product IDs are still missing.
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

    /**
     * Same scope as findNeedsCanonicalLink(), but returns only IDs and supports paging.
     * This avoids loading the full SoftwareInstall list into memory during backfill.
     */
    @Query("""
            select s.id from SoftwareInstall s
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
    Page<Long> findNeedsCanonicalLinkIds(Pageable pageable);

    /**
     * Full rebuild path: page through all IDs only.
     */
    @Query("""
            select s.id from SoftwareInstall s
            order by s.id desc
            """)
    Page<Long> findAllIds(Pageable pageable);

    @Query("select s.id from SoftwareInstall s where s.importRunId = :runId")
    List<Long> findIdsByImportRunId(@Param("runId") Long runId);

    @EntityGraph(attributePaths = {"asset"})
    @Query("""
            select s
            from SoftwareInstall s
            where (:assetId is null or s.asset.id = :assetId)
              and (
                    :q is null or :q = ''
                    or lower(coalesce(s.vendorRaw, s.vendor, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.productRaw, s.product, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.versionRaw, s.version, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.normalizedVendor, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.normalizedProduct, '')) like lower(concat('%', :q, '%'))
                 )
            order by s.id desc
            """)
    Page<SoftwareInstall> searchPagedBase(
            @Param("assetId") Long assetId,
            @Param("q") String q,
            Pageable pageable
    );

    @EntityGraph(attributePaths = {"asset"})
    @Query("""
            select s
            from SoftwareInstall s
            where (:assetId is null or s.asset.id = :assetId)
              and (
                    :q is null or :q = ''
                    or lower(coalesce(s.vendorRaw, s.vendor, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.productRaw, s.product, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.versionRaw, s.version, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.normalizedVendor, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.normalizedProduct, '')) like lower(concat('%', :q, '%'))
                 )
              and s.cpeVendorId is not null
              and s.cpeProductId is not null
            order by s.id desc
            """)
    Page<SoftwareInstall> searchPagedLinked(
            @Param("assetId") Long assetId,
            @Param("q") String q,
            Pageable pageable
    );

    @EntityGraph(attributePaths = {"asset"})
    @Query("""
            select s
            from SoftwareInstall s
            where (:assetId is null or s.asset.id = :assetId)
              and (
                    :q is null or :q = ''
                    or lower(coalesce(s.vendorRaw, s.vendor, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.productRaw, s.product, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.versionRaw, s.version, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.normalizedVendor, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(s.normalizedProduct, '')) like lower(concat('%', :q, '%'))
                 )
              and (s.cpeVendorId is null or s.cpeProductId is null)
            order by s.id desc
            """)
    Page<SoftwareInstall> searchPagedNotLinked(
            @Param("assetId") Long assetId,
            @Param("q") String q,
            Pageable pageable
    );
}