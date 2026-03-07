package dev.notegridx.security.assetvulnmanager.service;

import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.*;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import dev.notegridx.security.assetvulnmanager.domain.Alert;
import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.ImportStagingSoftware;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportStagingSoftwareRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AssetSoftwareReplaceServiceTest {

    private AssetSoftwareReplaceService service;

    private ImportStagingSoftwareRepository stagingSoftwareRepository;
    private AssetRepository assetRepository;
    private SoftwareInstallRepository softwareInstallRepository;
    private AlertRepository alertRepository;
    private AlertService alertService;

    @BeforeEach
    void setup() {
        stagingSoftwareRepository = mock(ImportStagingSoftwareRepository.class);
        assetRepository = mock(AssetRepository.class);
        softwareInstallRepository = mock(SoftwareInstallRepository.class);
        alertRepository = mock(AlertRepository.class);
        alertService = mock(AlertService.class);

        service = new AssetSoftwareReplaceService(
                stagingSoftwareRepository,
                assetRepository,
                softwareInstallRepository,
                alertRepository,
                alertService
        );
    }

    @Test
    void prepareReplaceForRun_deletesExistingSoftwareAndDetachesAlerts_forValidAsset() {
        ImportStagingSoftware row = mock(ImportStagingSoftware.class);
        when(row.isValid()).thenReturn(true);
        when(row.getExternalKey()).thenReturn("asset-001");

        Asset asset = mock(Asset.class);
        when(asset.getId()).thenReturn(10L);

        SoftwareInstall sw1 = mock(SoftwareInstall.class);
        SoftwareInstall sw2 = mock(SoftwareInstall.class);
        when(sw1.getId()).thenReturn(100L);
        when(sw2.getId()).thenReturn(101L);

        Alert alert1 = mock(Alert.class);
        Alert alert2 = mock(Alert.class);

        when(stagingSoftwareRepository.findByImportRunIdOrderByRowNoAsc(1L))
                .thenReturn(List.of(row));

        when(assetRepository.findByExternalKey("asset-001"))
                .thenReturn(Optional.of(asset));

        when(softwareInstallRepository.findByAssetIdOrderByIdAsc(10L))
                .thenReturn(List.of(sw1, sw2));

        when(alertRepository.findBySoftwareInstallIdIn(List.of(100L, 101L)))
                .thenReturn(List.of(alert1, alert2));

        service.prepareReplaceForRun(1L);

        verify(alertRepository).findBySoftwareInstallIdIn(List.of(100L, 101L));
        verify(alertService).detachForDeletedSoftware(List.of(alert1, alert2));
        verify(softwareInstallRepository).deleteByAssetId(10L);
    }

    @Test
    void prepareReplaceForRun_skipsInvalidRows() {
        ImportStagingSoftware invalidRow = mock(ImportStagingSoftware.class);
        when(invalidRow.isValid()).thenReturn(false);

        when(stagingSoftwareRepository.findByImportRunIdOrderByRowNoAsc(1L))
                .thenReturn(List.of(invalidRow));

        service.prepareReplaceForRun(1L);

        verifyNoInteractions(assetRepository);
        verifyNoInteractions(softwareInstallRepository);
        verifyNoInteractions(alertRepository);
        verifyNoInteractions(alertService);
    }

    @Test
    void prepareReplaceForRun_skipsBlankExternalKey() {
        ImportStagingSoftware blankRow = mock(ImportStagingSoftware.class);
        when(blankRow.isValid()).thenReturn(true);
        when(blankRow.getExternalKey()).thenReturn("   ");

        when(stagingSoftwareRepository.findByImportRunIdOrderByRowNoAsc(1L))
                .thenReturn(List.of(blankRow));

        service.prepareReplaceForRun(1L);

        verifyNoInteractions(assetRepository);
        verifyNoInteractions(softwareInstallRepository);
        verifyNoInteractions(alertRepository);
        verifyNoInteractions(alertService);
    }

    @Test
    void prepareReplaceForRun_deduplicatesSameExternalKey() {
        ImportStagingSoftware row1 = mock(ImportStagingSoftware.class);
        when(row1.isValid()).thenReturn(true);
        when(row1.getExternalKey()).thenReturn("asset-001");

        ImportStagingSoftware row2 = mock(ImportStagingSoftware.class);
        when(row2.isValid()).thenReturn(true);
        when(row2.getExternalKey()).thenReturn("asset-001");

        Asset asset = mock(Asset.class);
        when(asset.getId()).thenReturn(10L);

        SoftwareInstall sw = mock(SoftwareInstall.class);
        when(sw.getId()).thenReturn(100L);

        when(stagingSoftwareRepository.findByImportRunIdOrderByRowNoAsc(1L))
                .thenReturn(List.of(row1, row2));

        when(assetRepository.findByExternalKey("asset-001"))
                .thenReturn(Optional.of(asset));

        when(softwareInstallRepository.findByAssetIdOrderByIdAsc(10L))
                .thenReturn(List.of(sw));

        when(alertRepository.findBySoftwareInstallIdIn(List.of(100L)))
                .thenReturn(Collections.emptyList());

        service.prepareReplaceForRun(1L);

        verify(assetRepository, times(1)).findByExternalKey("asset-001");
        verify(softwareInstallRepository, times(1)).findByAssetIdOrderByIdAsc(10L);
        verify(alertService, times(1)).detachForDeletedSoftware(anyList());
        verify(softwareInstallRepository, times(1)).deleteByAssetId(10L);
    }

    @Test
    void prepareReplaceForRun_skipsWhenAssetNotFound() {
        ImportStagingSoftware row = mock(ImportStagingSoftware.class);
        when(row.isValid()).thenReturn(true);
        when(row.getExternalKey()).thenReturn("missing-asset");

        when(stagingSoftwareRepository.findByImportRunIdOrderByRowNoAsc(1L))
                .thenReturn(List.of(row));

        when(assetRepository.findByExternalKey("missing-asset"))
                .thenReturn(Optional.empty());

        service.prepareReplaceForRun(1L);

        verify(assetRepository).findByExternalKey("missing-asset");
        verifyNoInteractions(alertRepository);
        verify(alertService, never()).detachForDeletedSoftware(anyList());
        verify(softwareInstallRepository, never()).deleteByAssetId(anyLong());
    }

    @Test
    void prepareReplaceForRun_skipsDeleteWhenExistingSoftwareIsEmpty() {
        ImportStagingSoftware row = mock(ImportStagingSoftware.class);
        when(row.isValid()).thenReturn(true);
        when(row.getExternalKey()).thenReturn("asset-001");

        Asset asset = mock(Asset.class);
        when(asset.getId()).thenReturn(10L);

        when(stagingSoftwareRepository.findByImportRunIdOrderByRowNoAsc(1L))
                .thenReturn(List.of(row));

        when(assetRepository.findByExternalKey("asset-001"))
                .thenReturn(Optional.of(asset));

        when(softwareInstallRepository.findByAssetIdOrderByIdAsc(10L))
                .thenReturn(Collections.emptyList());

        service.prepareReplaceForRun(1L);

        verify(softwareInstallRepository).findByAssetIdOrderByIdAsc(10L);
        verifyNoInteractions(alertRepository);
        verify(alertService, never()).detachForDeletedSoftware(anyList());
        verify(softwareInstallRepository, never()).deleteByAssetId(anyLong());
    }

    @Test
    void prepareReplaceForRun_callsDetachEvenWhenRelatedAlertsAreEmpty() {
        ImportStagingSoftware row = mock(ImportStagingSoftware.class);
        when(row.isValid()).thenReturn(true);
        when(row.getExternalKey()).thenReturn("asset-001");

        Asset asset = mock(Asset.class);
        when(asset.getId()).thenReturn(10L);

        SoftwareInstall sw = mock(SoftwareInstall.class);
        when(sw.getId()).thenReturn(100L);

        when(stagingSoftwareRepository.findByImportRunIdOrderByRowNoAsc(1L))
                .thenReturn(List.of(row));

        when(assetRepository.findByExternalKey("asset-001"))
                .thenReturn(Optional.of(asset));

        when(softwareInstallRepository.findByAssetIdOrderByIdAsc(10L))
                .thenReturn(List.of(sw));

        when(alertRepository.findBySoftwareInstallIdIn(List.of(100L)))
                .thenReturn(Collections.emptyList());

        service.prepareReplaceForRun(1L);

        verify(alertRepository).findBySoftwareInstallIdIn(List.of(100L));
        verify(alertService).detachForDeletedSoftware(Collections.emptyList());
        verify(softwareInstallRepository).deleteByAssetId(10L);
    }
}