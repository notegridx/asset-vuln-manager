package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.ImportRun;
import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;
import dev.notegridx.security.assetvulnmanager.repository.ImportRunRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.repository.UnresolvedMappingRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
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

    private AdminInventoryReadService service;

    @BeforeEach
    void setUp() {
        service = new AdminInventoryReadService(
                importRunRepository,
                unresolvedMappingRepository,
                softwareInstallRepository,
                canonicalCpeLinkingService
        );

        // Keep unresolved review tests simple:
        // no related software rows => status becomes UNRESOLVABLE
        when(softwareInstallRepository.findAll()).thenReturn(List.of());
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
    }

    @Test
    @DisplayName("findUnresolvedMappings defaults to ALL and activeOnly=true on initial access")
    void findUnresolvedMappings_defaultsToNewAndActiveOnlyOnInitialAccess() {
        UnresolvedMapping mapping1 = mockMapping(1L, "NEW", "Microsoft", "Edge");
        UnresolvedMapping mapping2 = mockMapping(2L, "RESOLVED", "Oracle", "Java");

        when(unresolvedMappingRepository.findAllActive()).thenReturn(List.of(mapping1, mapping2));

        AdminInventoryReadService.UnresolvedListView result =
                service.findUnresolvedMappings(null, null, null, null, null, null);

        assertThat(result.status()).isEqualTo("ALL");
        assertThat(result.activeOnly()).isTrue();
        assertThat(result.q()).isNull();
        assertThat(result.runId()).isNull();
        assertThat(result.id()).isNull();

        assertThat(result.mappings())
                .extracting(AdminInventoryReadService.UnresolvedReviewRow::raw)
                .containsExactly(mapping2, mapping1);

        verify(unresolvedMappingRepository).findAllActive();
        verify(unresolvedMappingRepository, never()).findAll();
    }

    @Test
    @DisplayName("findUnresolvedMappings returns all rows when status is ALL")
    void findUnresolvedMappings_returnsAllStatusesWhenStatusIsAll() {
        UnresolvedMapping mapping1 = mockMapping(1L, "NEW", "Microsoft", "Edge");
        UnresolvedMapping mapping2 = mockMapping(2L, "RESOLVED", "Oracle", "Java");

        when(unresolvedMappingRepository.findAllActive()).thenReturn(List.of(mapping1, mapping2));

        AdminInventoryReadService.UnresolvedListView result =
                service.findUnresolvedMappings("ALL", null, null, true, null, null);

        assertThat(result.status()).isEqualTo("ALL");
        assertThat(result.activeOnly()).isTrue();

        assertThat(result.mappings())
                .extracting(AdminInventoryReadService.UnresolvedReviewRow::raw)
                .containsExactly(mapping2, mapping1);

        verify(unresolvedMappingRepository).findAllActive();
        verify(unresolvedMappingRepository, never()).findAll();
    }

    @Test
    @DisplayName("findUnresolvedMappings uses findAll when checkbox was unchecked")
    void findUnresolvedMappings_usesFindAllWhenCheckboxWasUnchecked() {
        UnresolvedMapping mapping1 = mockMapping(1L, "NEW", "Microsoft", "Edge");
        UnresolvedMapping mapping2 = mockMapping(2L, "RESOLVED", "Oracle", "Java");

        when(unresolvedMappingRepository.findAll()).thenReturn(List.of(mapping1, mapping2));

        AdminInventoryReadService.UnresolvedListView result =
                service.findUnresolvedMappings("ALL", null, null, null, "1", null);

        assertThat(result.status()).isEqualTo("ALL");
        assertThat(result.activeOnly()).isFalse();

        assertThat(result.mappings())
                .extracting(AdminInventoryReadService.UnresolvedReviewRow::raw)
                .containsExactly(mapping2, mapping1);

        verify(unresolvedMappingRepository).findAll();
        verify(unresolvedMappingRepository, never()).findAllActive();
    }

    @Test
    @DisplayName("findUnresolvedMappings filters keyword case-insensitively and preserves runId state")
    void findUnresolvedMappings_filtersCaseInsensitivelyAndPreservesRunIdState() {
        UnresolvedMapping mapping1 = mockMapping(1L, "NEW", "Microsoft", "Edge");
        UnresolvedMapping mapping2 = mockMapping(2L, "NEW", "Oracle", "Java");

        when(unresolvedMappingRepository.findAllActive()).thenReturn(List.of(mapping1, mapping2));

        AdminInventoryReadService.UnresolvedListView result =
                service.findUnresolvedMappings("ALL", 99L, "  micro  ", true, "1", null);

        assertThat(result.status()).isEqualTo("ALL");
        assertThat(result.runId()).isEqualTo(99L);
        assertThat(result.q()).isEqualTo("micro");
        assertThat(result.activeOnly()).isTrue();

        assertThat(result.mappings())
                .extracting(AdminInventoryReadService.UnresolvedReviewRow::raw)
                .containsExactly(mapping1);

        verify(unresolvedMappingRepository).findAllActive();
    }

    @Test
    @DisplayName("findUnresolvedMappings id review mode returns only the requested mapping")
    void findUnresolvedMappings_idReviewMode_returnsRequestedMappingOnly() {
        UnresolvedMapping mapping1 = mockMapping(10L, "NEW", "Microsoft", "Edge");

        when(unresolvedMappingRepository.findById(10L)).thenReturn(Optional.of(mapping1));

        AdminInventoryReadService.UnresolvedListView result =
                service.findUnresolvedMappings(null, 77L, null, null, null, 10L);

        assertThat(result.status()).isEqualTo("ALL");
        assertThat(result.runId()).isEqualTo(77L);
        assertThat(result.id()).isEqualTo(10L);

        assertThat(result.mappings())
                .extracting(AdminInventoryReadService.UnresolvedReviewRow::raw)
                .containsExactly(mapping1);

        verify(unresolvedMappingRepository).findById(10L);
        verify(unresolvedMappingRepository, never()).findAll();
        verify(unresolvedMappingRepository, never()).findAllActive();
    }

    @Test
    @DisplayName("findUnresolvedMappings id review mode returns empty when mapping is missing")
    void findUnresolvedMappings_idReviewMode_returnsEmptyWhenMissing() {
        when(unresolvedMappingRepository.findById(999L)).thenReturn(Optional.empty());

        AdminInventoryReadService.UnresolvedListView result =
                service.findUnresolvedMappings(null, null, null, null, null, 999L);

        assertThat(result.status()).isEqualTo("ALL");
        assertThat(result.id()).isEqualTo(999L);
        assertThat(result.mappings()).isEmpty();

        verify(unresolvedMappingRepository).findById(999L);
        verify(unresolvedMappingRepository, never()).findAll();
        verify(unresolvedMappingRepository, never()).findAllActive();
    }

    @Test
    @DisplayName("findUnresolvedMappings normalizes legacy status NEW to ALL")
    void findUnresolvedMappings_normalizesLegacyStatusNewToAll() {
        UnresolvedMapping mapping1 = mockMapping(1L, "NEW", "Microsoft", "Edge");
        UnresolvedMapping mapping2 = mockMapping(2L, "RESOLVED", "Oracle", "Java");

        when(unresolvedMappingRepository.findAllActive()).thenReturn(List.of(mapping1, mapping2));

        AdminInventoryReadService.UnresolvedListView result =
                service.findUnresolvedMappings("NEW", null, null, true, null, null);

        assertThat(result.status()).isEqualTo("ALL");

        assertThat(result.mappings())
                .extracting(AdminInventoryReadService.UnresolvedReviewRow::raw)
                .containsExactly(mapping2, mapping1);
    }

    private static ImportRun mockImportRun(Long id) {
        ImportRun run = mock(ImportRun.class);
        when(run.getId()).thenReturn(id);
        return run;
    }

    private static UnresolvedMapping mockMapping(Long id, String status, String vendorRaw, String productRaw) {
        UnresolvedMapping mapping = mock(UnresolvedMapping.class);

        when(mapping.getId()).thenReturn(id);
        when(mapping.getStatus()).thenReturn(status);

        when(mapping.getVendorRaw()).thenReturn(vendorRaw);
        when(mapping.getProductRaw()).thenReturn(productRaw);
        when(mapping.getVersionRaw()).thenReturn(null);

        when(mapping.getNormalizedVendor()).thenReturn(vendorRaw == null ? null : vendorRaw.toLowerCase());
        when(mapping.getNormalizedProduct()).thenReturn(productRaw == null ? null : productRaw.toLowerCase());

        // Keep template-facing passthrough getters safe if they are referenced later
        try {
            when(mapping.getLinkedVendorName()).thenReturn(null);
            when(mapping.getLinkedProductName()).thenReturn(null);
        } catch (Exception ignored) {
            // ignore when those methods do not exist in the current entity shape
        }

        return mapping;
    }
}