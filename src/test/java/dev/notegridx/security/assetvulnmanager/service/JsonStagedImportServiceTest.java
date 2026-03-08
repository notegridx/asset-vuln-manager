package dev.notegridx.security.assetvulnmanager.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.databind.ObjectMapper;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.ImportRun;
import dev.notegridx.security.assetvulnmanager.domain.ImportStagingAsset;
import dev.notegridx.security.assetvulnmanager.domain.ImportStagingSoftware;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.domain.enums.SoftwareImportMode;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportRunRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportStagingAssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportStagingSoftwareRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class JsonStagedImportServiceTest {

    private JsonStagedImportService service;

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
        ObjectMapper mapper = new ObjectMapper();

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
                        ImportRun.newStaged("JSON_UPLOAD", "JSON_SOFTWARE", "software.json", "ABC")
                ));

        when(stagingSoftwareRepository.findByImportRunIdOrderByRowNoAsc(anyLong()))
                .thenReturn(Collections.emptyList());

        when(stagingAssetRepository.findByImportRunIdOrderByRowNoAsc(anyLong()))
                .thenReturn(Collections.emptyList());

        when(softwareInstallRepository.findIdsByImportRunId(anyLong()))
                .thenReturn(Collections.emptyList());

        when(canonicalBackfillService.backfillForSoftwareIds(anyList(), eq(false)))
                .thenReturn(new CanonicalBackfillService.BackfillResult(0, 0, 0, false));

        service = new JsonStagedImportService(
                mapper,
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
    void stageAssets_marksInvalid_whenExternalKeyMissing() {
        String json = """
                [
                  {"name":"host1"}
                ]
                """;

        ImportRun run = service.stageAssets(
                "assets.json",
                json.getBytes(StandardCharsets.UTF_8)
        );

        ArgumentCaptor<List> captor = ArgumentCaptor.forClass(List.class);
        verify(stagingAssetRepository).saveAll(captor.capture());

        List<?> rows = captor.getValue();
        assertThat(rows).hasSize(1);
        assertThat(run.getInvalidRows()).isEqualTo(1);
    }

    @Test
    void stageAssets_marksValid_whenRequiredFieldsPresent() {
        String json = """
                [
                  {"externalKey":"abc","name":"host1"}
                ]
                """;

        ImportRun run = service.stageAssets(
                "assets.json",
                json.getBytes(StandardCharsets.UTF_8)
        );

        assertThat(run.getValidRows()).isEqualTo(1);
        assertThat(run.getInvalidRows()).isEqualTo(0);
    }

    @Test
    void stageSoftware_invalid_whenAssetDoesNotExist() {
        when(assetRepository.existsByExternalKey("host1")).thenReturn(false);

        String json = """
                [
                  {
                    "externalKey":"host1",
                    "product":"Chrome"
                  }
                ]
                """;

        ImportRun run = service.stageSoftware(
                "software.json",
                json.getBytes(StandardCharsets.UTF_8)
        );

        assertThat(run.getInvalidRows()).isEqualTo(1);
    }

    @Test
    void stageSoftware_valid_whenAssetExists() {
        when(assetRepository.existsByExternalKey("host1")).thenReturn(true);

        String json = """
                [
                  {
                    "externalKey":"host1",
                    "product":"Chrome"
                  }
                ]
                """;

        ImportRun run = service.stageSoftware(
                "software.json",
                json.getBytes(StandardCharsets.UTF_8)
        );

        assertThat(run.getValidRows()).isEqualTo(1);
    }

    @Test
    void importSoftware_replaceMode_triggersReplacePreparation() {
        service.importSoftware(10L, SoftwareImportMode.REPLACE_ASSET_SOFTWARE);
        verify(replaceService).prepareReplaceForRun(10L);
    }

    @Test
    void importSoftware_appendMode_doesNotTriggerReplace() {
        service.importSoftware(10L, SoftwareImportMode.APPEND);
        verify(replaceService, never()).prepareReplaceForRun(anyLong());
    }

    @Test
    void importAssets_createsNewAsset_whenExternalKeyDoesNotExist() {
        ImportStagingAsset row = mock(ImportStagingAsset.class);

        when(row.isValid()).thenReturn(true);
        when(row.getExternalKey()).thenReturn("asset-001");
        when(row.getName()).thenReturn("Host 001");
        when(row.getAssetType()).thenReturn("SERVER");
        when(row.getOwner()).thenReturn("ops");
        when(row.getNote()).thenReturn("imported");
        when(row.getSource()).thenReturn(null);
        when(row.getPlatform()).thenReturn("windows");
        when(row.getOsVersion()).thenReturn("11");
        when(row.getSystemUuid()).thenReturn("uuid-001");
        when(row.getSerialNumber()).thenReturn("sn-001");
        when(row.getHardwareVendor()).thenReturn("Dell");
        when(row.getHardwareModel()).thenReturn("OptiPlex");
        when(row.getComputerName()).thenReturn("PC-001");
        when(row.getLocalHostname()).thenReturn("pc001.local");
        when(row.getCpuBrand()).thenReturn("Intel");
        when(row.getCpuPhysicalCores()).thenReturn(4);
        when(row.getCpuLogicalCores()).thenReturn(8);
        when(row.getArch()).thenReturn("x64");
        when(row.getOsName()).thenReturn("Windows");
        when(row.getOsBuild()).thenReturn("22631");
        when(row.getOsMajor()).thenReturn(11);
        when(row.getOsMinor()).thenReturn(0);
        when(row.getOsPatch()).thenReturn(1);
        when(row.getLastSeenAt()).thenReturn(LocalDateTime.of(2026, 3, 8, 6, 0));

        when(stagingAssetRepository.findByImportRunIdOrderByRowNoAsc(1L)).thenReturn(List.of(row));
        when(assetRepository.findByExternalKey("asset-001")).thenReturn(Optional.empty());

        service.importAssets(1L);

        ArgumentCaptor<Asset> captor = ArgumentCaptor.forClass(Asset.class);
        verify(assetRepository).save(captor.capture());

        Asset saved = captor.getValue();
        assertThat(saved.getName()).isEqualTo("Host 001");
        assertThat(saved.getExternalKey()).isEqualTo("asset-001");
        assertThat(saved.getAssetType()).isEqualTo("SERVER");
        assertThat(saved.getOwner()).isEqualTo("ops");
        assertThat(saved.getSource()).isEqualTo("JSON_UPLOAD");
        assertThat(saved.getPlatform()).isEqualTo("windows");
        assertThat(saved.getOsVersion()).isEqualTo("11");
        assertThat(saved.getSystemUuid()).isEqualTo("uuid-001");
        assertThat(saved.getArch()).isEqualTo("x64");
        assertThat(saved.getLastSeenAt()).isEqualTo(LocalDateTime.of(2026, 3, 8, 6, 0));
    }

    @Test
    void importAssets_updatesExistingAsset_whenExternalKeyExists() {
        ImportStagingAsset row = mock(ImportStagingAsset.class);
        Asset existing = new Asset("Old Name");

        when(row.isValid()).thenReturn(true);
        when(row.getExternalKey()).thenReturn("asset-001");
        when(row.getName()).thenReturn("New Name");
        when(row.getAssetType()).thenReturn("LAPTOP");
        when(row.getOwner()).thenReturn("junichi");
        when(row.getNote()).thenReturn("updated");
        when(row.getSource()).thenReturn("OSQUERY");
        when(row.getPlatform()).thenReturn("macOS");
        when(row.getOsVersion()).thenReturn("15.0");
        when(row.getSystemUuid()).thenReturn("uuid-xyz");
        when(row.getSerialNumber()).thenReturn("serial-xyz");
        when(row.getHardwareVendor()).thenReturn("Apple");
        when(row.getHardwareModel()).thenReturn("iMac");
        when(row.getComputerName()).thenReturn("Junichi-iMac");
        when(row.getLocalHostname()).thenReturn("junichi-imac.local");
        when(row.getCpuBrand()).thenReturn("Intel");
        when(row.getCpuPhysicalCores()).thenReturn(6);
        when(row.getCpuLogicalCores()).thenReturn(12);
        when(row.getArch()).thenReturn("x86_64");
        when(row.getOsName()).thenReturn("macOS");
        when(row.getOsBuild()).thenReturn("24A");
        when(row.getOsMajor()).thenReturn(15);
        when(row.getOsMinor()).thenReturn(0);
        when(row.getOsPatch()).thenReturn(0);
        when(row.getLastSeenAt()).thenReturn(LocalDateTime.of(2026, 3, 8, 7, 0));

        when(stagingAssetRepository.findByImportRunIdOrderByRowNoAsc(2L)).thenReturn(List.of(row));
        when(assetRepository.findByExternalKey("asset-001")).thenReturn(Optional.of(existing));

        service.importAssets(2L);

        ArgumentCaptor<Asset> captor = ArgumentCaptor.forClass(Asset.class);
        verify(assetRepository).save(captor.capture());

        Asset saved = captor.getValue();
        assertThat(saved).isSameAs(existing);
        assertThat(saved.getName()).isEqualTo("New Name");
        assertThat(saved.getExternalKey()).isEqualTo("asset-001");
        assertThat(saved.getSource()).isEqualTo("OSQUERY");
        assertThat(saved.getPlatform()).isEqualTo("macOS");
        assertThat(saved.getOsVersion()).isEqualTo("15.0");
        assertThat(saved.getHardwareVendor()).isEqualTo("Apple");
        assertThat(saved.getLastSeenAt()).isEqualTo(LocalDateTime.of(2026, 3, 8, 7, 0));
    }

    @Test
    void importSoftware_skipsInvalidRows() {
        ImportStagingSoftware row = mock(ImportStagingSoftware.class);
        when(row.isValid()).thenReturn(false);

        when(stagingSoftwareRepository.findByImportRunIdOrderByRowNoAsc(3L)).thenReturn(List.of(row));

        service.importSoftware(3L);

        verify(assetRepository, never()).findByExternalKey(anyString());
        verify(softwareInstallRepository, never()).save(any());
    }

    @Test
    void importSoftware_skipsWhenAssetNotFound() {
        ImportStagingSoftware row = mock(ImportStagingSoftware.class);

        when(row.isValid()).thenReturn(true);
        when(row.getExternalKey()).thenReturn("missing-asset");

        when(stagingSoftwareRepository.findByImportRunIdOrderByRowNoAsc(4L)).thenReturn(List.of(row));
        when(assetRepository.findByExternalKey("missing-asset")).thenReturn(Optional.empty());

        service.importSoftware(4L);

        verify(assetRepository).findByExternalKey("missing-asset");
        verify(softwareInstallRepository, never()).save(any());
    }

    @Test
    void importSoftware_defaultsSourceAndSourceTypeToJsonUpload() {
        ImportStagingSoftware row = mock(ImportStagingSoftware.class);
        Asset asset = mock(Asset.class);

        when(row.isValid()).thenReturn(true);
        when(row.getExternalKey()).thenReturn("asset-001");
        when(row.getVendor()).thenReturn("Google");
        when(row.getProduct()).thenReturn("Chrome");
        when(row.getVersion()).thenReturn("145.0");
        when(row.getVendorRaw()).thenReturn(null);
        when(row.getProductRaw()).thenReturn(null);
        when(row.getVersionRaw()).thenReturn(null);
        when(row.getSource()).thenReturn(null);
        when(row.getSourceType()).thenReturn(null);
        when(row.getType()).thenReturn("APPLICATION");
        when(row.getInstallLocation()).thenReturn("C:\\Program Files\\Google\\Chrome");
        when(row.getInstalledAt()).thenReturn(LocalDateTime.of(2026, 3, 1, 0, 0));
        when(row.getPackageIdentifier()).thenReturn("{ABC}");
        when(row.getArch()).thenReturn("x64");
        when(row.getLastSeenAt()).thenReturn(LocalDateTime.of(2026, 3, 8, 8, 0));
        when(row.getPublisher()).thenReturn("Google LLC");
        when(row.getBundleId()).thenReturn(null);
        when(row.getPackageManager()).thenReturn(null);
        when(row.getInstallSource()).thenReturn(null);
        when(row.getEdition()).thenReturn(null);
        when(row.getChannel()).thenReturn(null);
        when(row.getRelease()).thenReturn(null);
        when(row.getPurl()).thenReturn(null);

        when(stagingSoftwareRepository.findByImportRunIdOrderByRowNoAsc(5L)).thenReturn(List.of(row));
        when(assetRepository.findByExternalKey("asset-001")).thenReturn(Optional.of(asset));
        when(asset.getId()).thenReturn(1L);

        when(softwareInstallRepository.findByAssetIdAndVendorAndProductAndVersion(1L, "Google", "Chrome", "145.0"))
                .thenReturn(Optional.empty());

        when(validator.resolve("Google", "Chrome"))
                .thenReturn(SoftwareDictionaryValidator.Resolve.miss(
                        DictionaryValidationException.DictionaryErrorCode.DICT_PRODUCT_NOT_FOUND,
                        "product",
                        "not found",
                        "google",
                        "chrome"
                ));

        when(softwareInstallRepository.findIdsByImportRunId(5L)).thenReturn(Collections.emptyList());

        service.importSoftware(5L);

        ArgumentCaptor<SoftwareInstall> captor = ArgumentCaptor.forClass(SoftwareInstall.class);
        verify(softwareInstallRepository).save(captor.capture());

        SoftwareInstall saved = captor.getValue();
        assertThat(saved.getSource()).isEqualTo("JSON_UPLOAD");
        assertThat(saved.getSourceType()).isEqualTo("JSON_UPLOAD");
        assertThat(saved.getVendor()).isEqualTo("Google");
        assertThat(saved.getProduct()).isEqualTo("Chrome");
        assertThat(saved.getVersion()).isEqualTo("145.0");
        assertThat(saved.getVersionNorm()).isEqualTo("145.0");
        assertThat(saved.getImportRunId()).isEqualTo(5L);
        assertThat(saved.getInstallLocation()).isEqualTo("C:\\Program Files\\Google\\Chrome");
        assertThat(saved.getPublisher()).isEqualTo("Google LLC");
        assertThat(saved.getCpeVendorId()).isNull();
        assertThat(saved.getCpeProductId()).isNull();
    }

    @Test
    void importSoftware_unlinksCanonical_whenProductLooksLikeWindowsComponent() {
        ImportStagingSoftware row = mock(ImportStagingSoftware.class);
        Asset asset = mock(Asset.class);
        SoftwareInstall existing = new SoftwareInstall(new Asset("Host 001"), "Microsoft.WindowsNotepad");

        existing.linkCanonical(100L, 200L);

        when(row.isValid()).thenReturn(true);
        when(row.getExternalKey()).thenReturn("asset-001");
        when(row.getVendor()).thenReturn("Microsoft");
        when(row.getProduct()).thenReturn("Microsoft.WindowsNotepad");
        when(row.getVersion()).thenReturn("11.0");
        when(row.getVendorRaw()).thenReturn("Microsoft");
        when(row.getProductRaw()).thenReturn("Microsoft.WindowsNotepad");
        when(row.getVersionRaw()).thenReturn("11.0");
        when(row.getSource()).thenReturn("OSQUERY");
        when(row.getSourceType()).thenReturn("OSQUERY");
        when(row.getType()).thenReturn("APPLICATION");
        when(row.getInstallLocation()).thenReturn(null);
        when(row.getInstalledAt()).thenReturn(null);
        when(row.getPackageIdentifier()).thenReturn(null);
        when(row.getArch()).thenReturn(null);
        when(row.getLastSeenAt()).thenReturn(LocalDateTime.of(2026, 3, 8, 9, 0));
        when(row.getPublisher()).thenReturn(null);
        when(row.getBundleId()).thenReturn(null);
        when(row.getPackageManager()).thenReturn(null);
        when(row.getInstallSource()).thenReturn(null);
        when(row.getEdition()).thenReturn(null);
        when(row.getChannel()).thenReturn(null);
        when(row.getRelease()).thenReturn(null);
        when(row.getPurl()).thenReturn(null);

        when(stagingSoftwareRepository.findByImportRunIdOrderByRowNoAsc(6L)).thenReturn(List.of(row));
        when(assetRepository.findByExternalKey("asset-001")).thenReturn(Optional.of(asset));
        when(asset.getId()).thenReturn(10L);
        when(softwareInstallRepository.findByAssetIdAndVendorAndProductAndVersion(
                10L, "Microsoft", "Microsoft.WindowsNotepad", "11.0"
        )).thenReturn(Optional.of(existing));
        when(softwareInstallRepository.findIdsByImportRunId(6L)).thenReturn(Collections.emptyList());

        service.importSoftware(6L);

        ArgumentCaptor<SoftwareInstall> captor = ArgumentCaptor.forClass(SoftwareInstall.class);
        verify(softwareInstallRepository).save(captor.capture());

        SoftwareInstall saved = captor.getValue();
        assertThat(saved).isSameAs(existing);
        assertThat(saved.getCpeVendorId()).isNull();
        assertThat(saved.getCpeProductId()).isNull();

        verify(validator, never()).resolve(any(), any());
    }

    @Test
    void importSoftware_linksCanonical_whenDictionaryResolveHits() {
        ImportStagingSoftware row = mock(ImportStagingSoftware.class);
        Asset asset = mock(Asset.class);

        when(row.isValid()).thenReturn(true);
        when(row.getExternalKey()).thenReturn("asset-001");
        when(row.getVendor()).thenReturn("Google");
        when(row.getProduct()).thenReturn("Chrome");
        when(row.getVersion()).thenReturn("145.0");
        when(row.getVendorRaw()).thenReturn("Google LLC");
        when(row.getProductRaw()).thenReturn("Google Chrome");
        when(row.getVersionRaw()).thenReturn("145.0.7632.159");
        when(row.getSource()).thenReturn("OSQUERY");
        when(row.getSourceType()).thenReturn("OSQUERY");
        when(row.getType()).thenReturn("APPLICATION");
        when(row.getInstallLocation()).thenReturn("C:\\\\Chrome");
        when(row.getInstalledAt()).thenReturn(LocalDateTime.of(2026, 3, 2, 0, 0));
        when(row.getPackageIdentifier()).thenReturn("{PKG}");
        when(row.getArch()).thenReturn("x64");
        when(row.getLastSeenAt()).thenReturn(LocalDateTime.of(2026, 3, 8, 10, 0));
        when(row.getPublisher()).thenReturn("Google LLC");
        when(row.getBundleId()).thenReturn(null);
        when(row.getPackageManager()).thenReturn(null);
        when(row.getInstallSource()).thenReturn(null);
        when(row.getEdition()).thenReturn(null);
        when(row.getChannel()).thenReturn(null);
        when(row.getRelease()).thenReturn(null);
        when(row.getPurl()).thenReturn(null);

        when(stagingSoftwareRepository.findByImportRunIdOrderByRowNoAsc(7L)).thenReturn(List.of(row));
        when(assetRepository.findByExternalKey("asset-001")).thenReturn(Optional.of(asset));
        when(asset.getId()).thenReturn(77L);
        when(softwareInstallRepository.findByAssetIdAndVendorAndProductAndVersion(
                77L, "Google LLC", "Google Chrome", "145.0.7632.159"
        )).thenReturn(Optional.empty());
        when(validator.resolve("Google LLC", "Google Chrome"))
                .thenReturn(SoftwareDictionaryValidator.Resolve.hit(11L, 22L, "google", "chrome"));
        when(softwareInstallRepository.findIdsByImportRunId(7L)).thenReturn(List.of(501L, 502L));

        service.importSoftware(7L);

        ArgumentCaptor<SoftwareInstall> captor = ArgumentCaptor.forClass(SoftwareInstall.class);
        verify(softwareInstallRepository).save(captor.capture());

        SoftwareInstall saved = captor.getValue();
        assertThat(saved.getVendor()).isEqualTo("Google LLC");
        assertThat(saved.getProduct()).isEqualTo("Google Chrome");
        assertThat(saved.getVersion()).isEqualTo("145.0.7632.159");
        assertThat(saved.getSource()).isEqualTo("OSQUERY");
        assertThat(saved.getSourceType()).isEqualTo("OSQUERY");
        assertThat(saved.getCpeVendorId()).isEqualTo(11L);
        assertThat(saved.getCpeProductId()).isEqualTo(22L);

        verify(canonicalBackfillService).backfillForSoftwareIds(List.of(501L, 502L), false);
    }

    @Test
    void stageAssets_acceptsSnakeCaseFields() {
        String json = """
            [
              {
                "externalKey":"asset-001",
                "name":"Host 001",
                "asset_type":"WORKSTATION",
                "platform":"windows",
                "os_version":"11",
                "system_uuid":"uuid-001",
                "serial_number":"sn-001",
                "hardware_vendor":"Dell",
                "hardware_model":"OptiPlex",
                "computer_name":"PC-001",
                "local_hostname":"pc001.local",
                "cpu_brand":"Intel",
                "cpu_physical_cores":4,
                "cpu_logical_cores":8,
                "arch":"x64",
                "os_name":"Windows",
                "os_build":"22631",
                "os_major":11,
                "os_minor":0,
                "os_patch":1,
                "last_seen_at":"2026-03-08T06:00:00"
              }
            ]
            """;

        ImportRun run = service.stageAssets(
                "assets.json",
                json.getBytes(StandardCharsets.UTF_8)
        );

        ArgumentCaptor<List> captor = ArgumentCaptor.forClass(List.class);
        verify(stagingAssetRepository).saveAll(captor.capture());

        List<?> rows = captor.getValue();
        assertThat(rows).hasSize(1);

        ImportStagingAsset saved = (ImportStagingAsset) rows.get(0);
        assertThat(saved.getExternalKey()).isEqualTo("asset-001");
        assertThat(saved.getName()).isEqualTo("Host 001");
        assertThat(saved.getAssetType()).isEqualTo("WORKSTATION");
        assertThat(saved.getOsVersion()).isEqualTo("11");
        assertThat(saved.getSystemUuid()).isEqualTo("uuid-001");
        assertThat(saved.getSerialNumber()).isEqualTo("sn-001");
        assertThat(saved.getHardwareVendor()).isEqualTo("Dell");
        assertThat(saved.getHardwareModel()).isEqualTo("OptiPlex");
        assertThat(saved.getComputerName()).isEqualTo("PC-001");
        assertThat(saved.getLocalHostname()).isEqualTo("pc001.local");
        assertThat(saved.getCpuBrand()).isEqualTo("Intel");
        assertThat(saved.getCpuPhysicalCores()).isEqualTo(4);
        assertThat(saved.getCpuLogicalCores()).isEqualTo(8);
        assertThat(saved.getArch()).isEqualTo("x64");
        assertThat(saved.getOsName()).isEqualTo("Windows");
        assertThat(saved.getOsBuild()).isEqualTo("22631");
        assertThat(saved.getOsMajor()).isEqualTo(11);
        assertThat(saved.getOsMinor()).isEqualTo(0);
        assertThat(saved.getOsPatch()).isEqualTo(1);
        assertThat(saved.getLastSeenAt()).isEqualTo(LocalDateTime.of(2026, 3, 8, 6, 0));

        assertThat(run.getValidRows()).isEqualTo(1);
        assertThat(run.getInvalidRows()).isEqualTo(0);
    }
}