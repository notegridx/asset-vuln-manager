package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.ImportRun;
import dev.notegridx.security.assetvulnmanager.domain.ImportStagingAsset;
import dev.notegridx.security.assetvulnmanager.domain.enums.SoftwareImportMode;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportRunRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportStagingAssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportStagingSoftwareRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CsvStagedImportServiceTest {

    private CsvStagedImportService service;

    private ImportRunRepository importRunRepository;
    private ImportStagingAssetRepository stagingAssetRepository;
    private ImportStagingSoftwareRepository stagingSoftwareRepository;
    private AssetRepository assetRepository;
    private SoftwareInstallRepository softwareInstallRepository;
    private SoftwareDictionaryValidator validator;
    private CanonicalBackfillService canonicalBackfillService;
    private AssetSoftwareReplaceService replaceService;

    @BeforeEach
    void setup() {
        importRunRepository = mock(ImportRunRepository.class);
        stagingAssetRepository = mock(ImportStagingAssetRepository.class);
        stagingSoftwareRepository = mock(ImportStagingSoftwareRepository.class);
        assetRepository = mock(AssetRepository.class);
        softwareInstallRepository = mock(SoftwareInstallRepository.class);
        validator = mock(SoftwareDictionaryValidator.class);
        canonicalBackfillService = mock(CanonicalBackfillService.class);
        replaceService = mock(AssetSoftwareReplaceService.class);

        when(importRunRepository.save(any())).thenAnswer(i -> i.getArgument(0));

        when(importRunRepository.findById(anyLong()))
                .thenReturn(Optional.of(
                        ImportRun.newStaged("CSV_UPLOAD", "CSV_ASSETS", "assets.csv", "ABC")
                ));

        when(stagingAssetRepository.findByImportRunIdOrderByRowNoAsc(anyLong()))
                .thenReturn(Collections.emptyList());

        when(stagingSoftwareRepository.findByImportRunIdOrderByRowNoAsc(anyLong()))
                .thenReturn(Collections.emptyList());

        when(canonicalBackfillService.backfillForSoftwareIds(anyList(), eq(false)))
                .thenReturn(new CanonicalBackfillService.BackfillResult(0, 0, 0, false));

        service = new CsvStagedImportService(
                importRunRepository,
                stagingAssetRepository,
                stagingSoftwareRepository,
                assetRepository,
                softwareInstallRepository,
                validator,
                canonicalBackfillService,
                replaceService
        );
    }

    @Test
    void stageAssets_mapsExtendedInventoryFields() {
        String csv = """
                external_key,name,asset_type,owner,note,source,platform,os_version,system_uuid,serial_number,hardware_vendor,hardware_model,hardware_version,computer_name,local_hostname,hostname,cpu_brand,cpu_physical_cores,cpu_logical_cores,cpu_sockets,physical_memory,arch,board_vendor,board_model,board_version,board_serial,os_name,os_build,os_major,os_minor,os_patch,last_seen_at
                asset-001,Host 001,SERVER,user1,imported,CSV_UPLOAD,windows,11,uuid-001,sn-001,Dell,OptiPlex,Gen2,HOST-001,host-001.local,host-001.example.local,Intel,4,8,1,17179869184,x64,Dell,Board-A,1.0,board-001,Windows,22631,11,0,1,2026-03-08T06:00:00
                """;

        ImportRun run = service.stageAssets(
                "assets.csv",
                csv.getBytes(StandardCharsets.UTF_8)
        );

        @SuppressWarnings("rawtypes")
        ArgumentCaptor<List> captor = ArgumentCaptor.forClass(List.class);
        verify(stagingAssetRepository).saveAll(captor.capture());

        @SuppressWarnings("unchecked")
        List<ImportStagingAsset> rows = captor.getValue();

        assertThat(rows).hasSize(1);

        ImportStagingAsset row = rows.get(0);
        assertThat(row.isValid()).isTrue();
        assertThat(row.getExternalKey()).isEqualTo("asset-001");
        assertThat(row.getName()).isEqualTo("Host 001");
        assertThat(row.getAssetType()).isEqualTo("SERVER");
        assertThat(row.getOwner()).isEqualTo("user1");
        assertThat(row.getNote()).isEqualTo("imported");
        assertThat(row.getSource()).isEqualTo("CSV_UPLOAD");
        assertThat(row.getPlatform()).isEqualTo("windows");
        assertThat(row.getOsVersion()).isEqualTo("11");
        assertThat(row.getSystemUuid()).isEqualTo("uuid-001");
        assertThat(row.getSerialNumber()).isEqualTo("sn-001");
        assertThat(row.getHardwareVendor()).isEqualTo("Dell");
        assertThat(row.getHardwareModel()).isEqualTo("OptiPlex");
        assertThat(row.getHardwareVersion()).isEqualTo("Gen2");
        assertThat(row.getComputerName()).isEqualTo("HOST-001");
        assertThat(row.getLocalHostname()).isEqualTo("host-001.local");
        assertThat(row.getHostname()).isEqualTo("host-001.example.local");
        assertThat(row.getCpuBrand()).isEqualTo("Intel");
        assertThat(row.getCpuPhysicalCores()).isEqualTo(4);
        assertThat(row.getCpuLogicalCores()).isEqualTo(8);
        assertThat(row.getCpuSockets()).isEqualTo(1);
        assertThat(row.getPhysicalMemory()).isEqualTo(17179869184L);
        assertThat(row.getArch()).isEqualTo("x64");
        assertThat(row.getBoardVendor()).isEqualTo("Dell");
        assertThat(row.getBoardModel()).isEqualTo("Board-A");
        assertThat(row.getBoardVersion()).isEqualTo("1.0");
        assertThat(row.getBoardSerial()).isEqualTo("board-001");
        assertThat(row.getOsName()).isEqualTo("Windows");
        assertThat(row.getOsBuild()).isEqualTo("22631");
        assertThat(row.getOsMajor()).isEqualTo(11);
        assertThat(row.getOsMinor()).isEqualTo(0);
        assertThat(row.getOsPatch()).isEqualTo(1);
        assertThat(row.getLastSeenAt()).isEqualTo(LocalDateTime.of(2026, 3, 8, 6, 0));

        assertThat(run.getTotalRows()).isEqualTo(1);
        assertThat(run.getValidRows()).isEqualTo(1);
        assertThat(run.getInvalidRows()).isEqualTo(0);
    }

    @Test
    void importAssets_createsNewAsset_whenExternalKeyDoesNotExist_andCopiesExtendedInventoryFields() {
        ImportStagingAsset row = mock(ImportStagingAsset.class);

        when(row.isValid()).thenReturn(true);
        when(row.getExternalKey()).thenReturn("asset-001");
        when(row.getName()).thenReturn("Host 001");
        when(row.getAssetType()).thenReturn("SERVER");
        when(row.getOwner()).thenReturn("user1");
        when(row.getNote()).thenReturn("imported");
        when(row.getSource()).thenReturn("CSV_UPLOAD");
        when(row.getPlatform()).thenReturn("windows");
        when(row.getOsVersion()).thenReturn("11");
        when(row.getSystemUuid()).thenReturn("uuid-001");
        when(row.getSerialNumber()).thenReturn("sn-001");
        when(row.getHardwareVendor()).thenReturn("Dell");
        when(row.getHardwareModel()).thenReturn("OptiPlex");
        when(row.getHardwareVersion()).thenReturn("Gen2");
        when(row.getComputerName()).thenReturn("HOST-001");
        when(row.getLocalHostname()).thenReturn("host-001.local");
        when(row.getHostname()).thenReturn("host-001.example.local");
        when(row.getCpuBrand()).thenReturn("Intel");
        when(row.getCpuPhysicalCores()).thenReturn(4);
        when(row.getCpuLogicalCores()).thenReturn(8);
        when(row.getCpuSockets()).thenReturn(1);
        when(row.getPhysicalMemory()).thenReturn(17179869184L);
        when(row.getArch()).thenReturn("x64");
        when(row.getBoardVendor()).thenReturn("Dell");
        when(row.getBoardModel()).thenReturn("Board-A");
        when(row.getBoardVersion()).thenReturn("1.0");
        when(row.getBoardSerial()).thenReturn("board-001");
        when(row.getOsName()).thenReturn("Windows");
        when(row.getOsBuild()).thenReturn("22631");
        when(row.getOsMajor()).thenReturn(11);
        when(row.getOsMinor()).thenReturn(0);
        when(row.getOsPatch()).thenReturn(1);
        when(row.getLastSeenAt()).thenReturn(LocalDateTime.of(2026, 3, 8, 6, 0));

        when(stagingAssetRepository.findByImportRunIdOrderByRowNoAsc(1L)).thenReturn(List.of(row));
        when(assetRepository.findByExternalKey("asset-001")).thenReturn(Optional.empty());
        when(assetRepository.save(any(Asset.class))).thenAnswer(i -> i.getArgument(0));

        ImportRun imported = service.importAssets(1L);

        ArgumentCaptor<Asset> captor = ArgumentCaptor.forClass(Asset.class);
        verify(assetRepository).save(captor.capture());

        Asset saved = captor.getValue();
        assertThat(saved.getName()).isEqualTo("Host 001");
        assertThat(saved.getExternalKey()).isEqualTo("asset-001");
        assertThat(saved.getAssetType()).isEqualTo("SERVER");
        assertThat(saved.getOwner()).isEqualTo("user1");
        assertThat(saved.getNote()).isEqualTo("imported");
        assertThat(saved.getSource()).isEqualTo("CSV_UPLOAD");
        assertThat(saved.getPlatform()).isEqualTo("windows");
        assertThat(saved.getOsVersion()).isEqualTo("11");
        assertThat(saved.getSystemUuid()).isEqualTo("uuid-001");
        assertThat(saved.getSerialNumber()).isEqualTo("sn-001");
        assertThat(saved.getHardwareVendor()).isEqualTo("Dell");
        assertThat(saved.getHardwareModel()).isEqualTo("OptiPlex");
        assertThat(saved.getHardwareVersion()).isEqualTo("Gen2");
        assertThat(saved.getComputerName()).isEqualTo("HOST-001");
        assertThat(saved.getLocalHostname()).isEqualTo("host-001.local");
        assertThat(saved.getHostname()).isEqualTo("host-001.example.local");
        assertThat(saved.getCpuBrand()).isEqualTo("Intel");
        assertThat(saved.getCpuPhysicalCores()).isEqualTo(4);
        assertThat(saved.getCpuLogicalCores()).isEqualTo(8);
        assertThat(saved.getCpuSockets()).isEqualTo(1);
        assertThat(saved.getPhysicalMemory()).isEqualTo(17179869184L);
        assertThat(saved.getArch()).isEqualTo("x64");
        assertThat(saved.getBoardVendor()).isEqualTo("Dell");
        assertThat(saved.getBoardModel()).isEqualTo("Board-A");
        assertThat(saved.getBoardVersion()).isEqualTo("1.0");
        assertThat(saved.getBoardSerial()).isEqualTo("board-001");
        assertThat(saved.getOsName()).isEqualTo("Windows");
        assertThat(saved.getOsBuild()).isEqualTo("22631");
        assertThat(saved.getOsMajor()).isEqualTo(11);
        assertThat(saved.getOsMinor()).isEqualTo(0);
        assertThat(saved.getOsPatch()).isEqualTo(1);
        assertThat(saved.getLastSeenAt()).isEqualTo(LocalDateTime.of(2026, 3, 8, 6, 0));

        assertThat(imported.getAssetsUpserted()).isEqualTo(1);
        assertThat(imported.getSoftwareUpserted()).isEqualTo(0);
    }
}