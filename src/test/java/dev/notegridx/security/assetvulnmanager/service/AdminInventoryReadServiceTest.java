package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.ImportRun;
import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;
import dev.notegridx.security.assetvulnmanager.repository.ImportRunRepository;
import dev.notegridx.security.assetvulnmanager.repository.UnresolvedMappingRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class AdminInventoryReadServiceTest {

    private ImportRunRepository importRunRepository;
    private UnresolvedMappingRepository unresolvedMappingRepository;
    private AdminInventoryReadService service;

    @BeforeEach
    void setup() {
        importRunRepository = mock(ImportRunRepository.class);
        unresolvedMappingRepository = mock(UnresolvedMappingRepository.class);
        service = new AdminInventoryReadService(importRunRepository, unresolvedMappingRepository);
    }

    @Test
    void findImportRuns_sortsByIdDesc_nullIdLast() {
        ImportRun run1 = mock(ImportRun.class);
        ImportRun run2 = mock(ImportRun.class);
        ImportRun run3 = mock(ImportRun.class);

        when(run1.getId()).thenReturn(10L);
        when(run2.getId()).thenReturn(null);
        when(run3.getId()).thenReturn(20L);

        when(importRunRepository.findAll()).thenReturn(List.of(run1, run2, run3));

        List<ImportRun> result = service.findImportRuns();

        assertThat(result).containsExactly(run3, run1, run2);
        verify(importRunRepository).findAll();
    }

    @Test
    void findUnresolvedMappings_defaultsToNewAndActiveOnlyOnInitialAccess() {
        UnresolvedMapping mapping1 = mock(UnresolvedMapping.class);
        UnresolvedMapping mapping2 = mock(UnresolvedMapping.class);

        when(mapping1.getId()).thenReturn(10L);
        when(mapping1.getStatus()).thenReturn("NEW");

        when(mapping2.getId()).thenReturn(20L);
        when(mapping2.getStatus()).thenReturn("RESOLVED");

        when(unresolvedMappingRepository.findAllActive()).thenReturn(List.of(mapping1, mapping2));

        AdminInventoryReadService.UnresolvedListView result =
                service.findUnresolvedMappings(null, null, null, null);

        assertThat(result).isNotNull();
        assertThat(result.status()).isEqualTo("NEW");
        assertThat(result.runId()).isNull();
        assertThat(result.activeOnly()).isTrue();
        assertThat(result.activeOnlyPresent()).isNull();
        assertThat(result.mappings()).containsExactly(mapping1);

        verify(unresolvedMappingRepository).findAllActive();
        verify(unresolvedMappingRepository, never()).findAll();
    }

    @Test
    void findUnresolvedMappings_returnsAllStatusesWhenStatusIsAll() {
        UnresolvedMapping mapping1 = mock(UnresolvedMapping.class);
        UnresolvedMapping mapping2 = mock(UnresolvedMapping.class);

        when(mapping1.getId()).thenReturn(10L);
        when(mapping1.getStatus()).thenReturn("NEW");

        when(mapping2.getId()).thenReturn(20L);
        when(mapping2.getStatus()).thenReturn("RESOLVED");

        when(unresolvedMappingRepository.findAllActive()).thenReturn(List.of(mapping1, mapping2));

        AdminInventoryReadService.UnresolvedListView result =
                service.findUnresolvedMappings("ALL", null, true, "1");

        assertThat(result.status()).isEqualTo("ALL");
        assertThat(result.activeOnly()).isTrue();
        assertThat(result.activeOnlyPresent()).isEqualTo("1");
        assertThat(result.mappings()).containsExactly(mapping2, mapping1);

        verify(unresolvedMappingRepository).findAllActive();
        verify(unresolvedMappingRepository, never()).findAll();
    }

    @Test
    void findUnresolvedMappings_usesFindAllWhenCheckboxWasUnchecked() {
        UnresolvedMapping mapping1 = mock(UnresolvedMapping.class);
        UnresolvedMapping mapping2 = mock(UnresolvedMapping.class);

        when(mapping1.getId()).thenReturn(10L);
        when(mapping1.getStatus()).thenReturn("NEW");

        when(mapping2.getId()).thenReturn(20L);
        when(mapping2.getStatus()).thenReturn("NEW");

        when(unresolvedMappingRepository.findAll()).thenReturn(List.of(mapping1, mapping2));

        AdminInventoryReadService.UnresolvedListView result =
                service.findUnresolvedMappings("NEW", null, null, "1");

        assertThat(result.status()).isEqualTo("NEW");
        assertThat(result.activeOnly()).isFalse();
        assertThat(result.activeOnlyPresent()).isEqualTo("1");
        assertThat(result.mappings()).containsExactly(mapping2, mapping1);

        verify(unresolvedMappingRepository).findAll();
        verify(unresolvedMappingRepository, never()).findAllActive();
    }

    @Test
    void findUnresolvedMappings_filtersCaseInsensitivelyAndPreservesRunIdState() {
        UnresolvedMapping mapping1 = mock(UnresolvedMapping.class);
        UnresolvedMapping mapping2 = mock(UnresolvedMapping.class);
        UnresolvedMapping mapping3 = mock(UnresolvedMapping.class);

        when(mapping1.getId()).thenReturn(10L);
        when(mapping1.getStatus()).thenReturn("NEW");

        when(mapping2.getId()).thenReturn(30L);
        when(mapping2.getStatus()).thenReturn("resolved");

        when(mapping3.getId()).thenReturn(20L);
        when(mapping3.getStatus()).thenReturn("RESOLVED");

        when(unresolvedMappingRepository.findAllActive()).thenReturn(List.of(mapping1, mapping2, mapping3));

        AdminInventoryReadService.UnresolvedListView result =
                service.findUnresolvedMappings("resolved", 99L, true, "1");

        assertThat(result.status()).isEqualTo("RESOLVED");
        assertThat(result.runId()).isEqualTo(99L);
        assertThat(result.activeOnly()).isTrue();
        assertThat(result.activeOnlyPresent()).isEqualTo("1");
        assertThat(result.mappings()).containsExactly(mapping2, mapping3);

        verify(unresolvedMappingRepository).findAllActive();
        verify(unresolvedMappingRepository, never()).findAll();
    }
}