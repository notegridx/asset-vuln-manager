package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.ImportRun;
import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;
import dev.notegridx.security.assetvulnmanager.repository.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AdminInventoryReadServiceTest {

    @Mock
    private ImportRunRepository importRunRepository;

    @Mock
    private UnresolvedMappingRepository unresolvedMappingRepository;

    @Mock
    private SoftwareInstallRepository softwareInstallRepository;

    @Mock
    private CanonicalCpeLinkingService canonicalCpeLinkingService;

    @Mock
    private CpeVendorRepository cpeVendorRepository;

    @Mock
    private CpeProductRepository cpeProductRepository;

    private AdminInventoryReadService service;

    @Mock
    private AssetRepository assetRepository;

    @BeforeEach
    void setUp() {
        service = new AdminInventoryReadService(
                importRunRepository,
                unresolvedMappingRepository,
                softwareInstallRepository,
                canonicalCpeLinkingService,
                cpeVendorRepository,
                cpeProductRepository,
                assetRepository
        );

    }

    @Test
    @DisplayName("findImportRuns sorts by id desc and null id last")
    void findImportRuns_sortsByIdDesc_nullIdLast() {
        ImportRun run1 = mockImportRun(1L);
        ImportRun run3 = mockImportRun(3L);
        ImportRun runNull = mockImportRun(null);

        when(importRunRepository.findAll()).thenReturn(List.of(run1, runNull, run3));

        List<ImportRun> result = service.findImportRuns();

        assertThat(result).containsExactly(run3, run1, runNull);
        verify(importRunRepository).findAll();
    }

    @Test
    @DisplayName("findUnresolvedMappings defaults to all and returns empty when no software exists")
    void findUnresolvedMappings_defaultsToAllAndReturnsEmptyWhenNoSoftwareExists() {
        when(softwareInstallRepository.findAll()).thenReturn(List.of());

        AdminInventoryReadService.UnresolvedListView result =
                service.findUnresolvedMappings(null, null, null, null, null, null, null, 0, 50);

        assertThat(result.status()).isEqualTo("all");
        assertThat(result.activeOnly()).isFalse();
        assertThat(result.q()).isNull();
        assertThat(result.runId()).isNull();
        assertThat(result.id()).isNull();
        assertThat(result.mappings()).isEmpty();
        assertThat(result.pageNumber()).isEqualTo(0);
        assertThat(result.pageSize()).isEqualTo(50);
        assertThat(result.totalPages()).isEqualTo(0);
        assertThat(result.totalElements()).isEqualTo(0);
        assertThat(result.pagerItems()).isEmpty();

        verify(softwareInstallRepository).findAll();
    }

    @Test
    @DisplayName("findUnresolvedMappings keeps ALL status and trimmed q when no software exists")
    void findUnresolvedMappings_keepsAllStatusAndTrimmedQWhenNoSoftwareExists() {
        when(softwareInstallRepository.findAll()).thenReturn(List.of());

        AdminInventoryReadService.UnresolvedListView result =
                service.findUnresolvedMappings("ALL", 99L, "  micro  ", true, "1", null, null, 0, 50);

        assertThat(result.status()).isEqualTo("all");
        assertThat(result.runId()).isEqualTo(99L);
        assertThat(result.q()).isEqualTo("micro");
        assertThat(result.activeOnly()).isFalse();
        assertThat(result.id()).isNull();
        assertThat(result.mappings()).isEmpty();
        assertThat(result.pageNumber()).isEqualTo(0);
        assertThat(result.pageSize()).isEqualTo(50);
        assertThat(result.totalPages()).isEqualTo(0);
        assertThat(result.totalElements()).isEqualTo(0);
        assertThat(result.pagerItems()).isEmpty();

        verify(softwareInstallRepository).findAll();
    }

    @Test
    @DisplayName("findUnresolvedMappings normalizes legacy NEW status to all when no software exists")
    void findUnresolvedMappings_normalizesLegacyStatusNewToAllWhenNoSoftwareExists() {
        when(softwareInstallRepository.findAll()).thenReturn(List.of());

        AdminInventoryReadService.UnresolvedListView result =
                service.findUnresolvedMappings("NEW", null, null, true, null, null, null, 0, 50);

        assertThat(result.status()).isEqualTo("all");
        assertThat(result.activeOnly()).isFalse();
        assertThat(result.mappings()).isEmpty();
        assertThat(result.pageNumber()).isEqualTo(0);
        assertThat(result.pageSize()).isEqualTo(50);
        assertThat(result.totalPages()).isEqualTo(0);
        assertThat(result.totalElements()).isEqualTo(0);
        assertThat(result.pagerItems()).isEmpty();

        verify(softwareInstallRepository).findAll();
    }

    @Test
    @DisplayName("findUnresolvedMappings id review mode returns only the requested mapping")
    void findUnresolvedMappings_idReviewMode_returnsRequestedMappingOnly() {
        UnresolvedMapping mapping1 = mockMapping(10L, "NEW", "Microsoft", "Edge");

        when(unresolvedMappingRepository.findById(10L)).thenReturn(Optional.of(mapping1));
        when(softwareInstallRepository.findAll()).thenReturn(List.of());

        AdminInventoryReadService.UnresolvedListView result =
                service.findUnresolvedMappings(null, 77L, null, null, null, null, 10L, 0, 50);

        assertThat(result.status()).isEqualTo("all");
        assertThat(result.runId()).isEqualTo(77L);
        assertThat(result.id()).isEqualTo(10L);

        assertThat(result.mappings())
                .extracting(AdminInventoryReadService.UnresolvedReviewRow::mapping)
                .containsExactly(mapping1);

        assertThat(result.pageNumber()).isEqualTo(0);
        assertThat(result.pageSize()).isEqualTo(1);
        assertThat(result.totalPages()).isEqualTo(1);
        assertThat(result.totalElements()).isEqualTo(1);
        assertThat(result.pagerItems()).isEmpty();

        verify(unresolvedMappingRepository).findById(10L);
    }

    @Test
    @DisplayName("findUnresolvedMappings id review mode returns empty when mapping is missing")
    void findUnresolvedMappings_idReviewMode_returnsEmptyWhenMissing() {
        when(unresolvedMappingRepository.findById(999L)).thenReturn(Optional.empty());
        when(softwareInstallRepository.findAll()).thenReturn(List.of());

        AdminInventoryReadService.UnresolvedListView result =
                service.findUnresolvedMappings(null, null, null, null, null, null, 999L, 0, 50);

        assertThat(result.status()).isEqualTo("all");
        assertThat(result.id()).isEqualTo(999L);
        assertThat(result.mappings()).isEmpty();
        assertThat(result.pageNumber()).isEqualTo(0);
        assertThat(result.pageSize()).isEqualTo(1);
        assertThat(result.totalPages()).isEqualTo(0);
        assertThat(result.totalElements()).isEqualTo(0);
        assertThat(result.pagerItems()).isEmpty();

        verify(unresolvedMappingRepository).findById(999L);
    }

    private static ImportRun mockImportRun(Long id) {
        ImportRun run = mock(ImportRun.class);
        when(run.getId()).thenReturn(id);
        return run;
    }

    private static UnresolvedMapping mockMapping(Long id, String status, String vendorRaw, String productRaw) {
        UnresolvedMapping mapping = mock(UnresolvedMapping.class);

        lenient().when(mapping.getId()).thenReturn(id);
        lenient().when(mapping.getStatus()).thenReturn(status);
        lenient().when(mapping.getVendorRaw()).thenReturn(vendorRaw);
        lenient().when(mapping.getProductRaw()).thenReturn(productRaw);
        lenient().when(mapping.getVersionRaw()).thenReturn(null);
        lenient().when(mapping.getNormalizedVendor()).thenReturn(vendorRaw);
        lenient().when(mapping.getNormalizedProduct()).thenReturn(productRaw);
        lenient().when(mapping.getLinkedCpeVendorId()).thenReturn(null);
        lenient().when(mapping.getLinkedCpeProductId()).thenReturn(null);
        lenient().when(mapping.getCandidateVendorIds()).thenReturn(null);
        lenient().when(mapping.getCandidateProductIds()).thenReturn(null);

        return mapping;
    }
}