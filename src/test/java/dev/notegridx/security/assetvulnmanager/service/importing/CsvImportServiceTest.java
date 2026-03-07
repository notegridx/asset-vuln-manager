package dev.notegridx.security.assetvulnmanager.service.importing;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.ImportRun;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportRunRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.repository.UnresolvedMappingRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class CsvImportServiceTest {

    @Autowired
    private CsvImportService csvImportService;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private SoftwareInstallRepository softwareInstallRepository;

    @Autowired
    private ImportRunRepository importRunRepository;

    @Autowired
    private UnresolvedMappingRepository unresolvedMappingRepository;

    @BeforeEach
    void setUp() {
        // application-test.yml が永続H2(file)を向いているため、毎回明示的に掃除する
        softwareInstallRepository.deleteAll();
        unresolvedMappingRepository.deleteAll();
        assetRepository.deleteAll();
        importRunRepository.deleteAll();
    }

    @Test
    @DisplayName("importAssetsCsv(dry-run) returns counts without persisting assets or import run")
    void importAssetsCsv_dryRun_returnsCountsWithoutPersisting() throws Exception {
        String csv = """
                external_key,name,asset_type,owner,note,platform,os_version
                host-01,Host One,SERVER,Alice,Primary server,windows,11
                """;

        ImportResult result = csvImportService.importAssetsCsv(
                bytes(csv),
                false
        );

        assertThat(result.dryRun()).isTrue();
        assertThat(result.linesRead()).isEqualTo(2); // header + 1 data row
        assertThat(result.ok()).isEqualTo(1);
        assertThat(result.inserted()).isEqualTo(1);
        assertThat(result.updated()).isEqualTo(0);
        assertThat(result.skipped()).isEqualTo(0);
        assertThat(result.errors()).isEqualTo(0);
        assertThat(result.hasErrors()).isFalse();

        assertThat(assetRepository.count()).isZero();
        assertThat(importRunRepository.count()).isZero();
    }

    @Test
    @DisplayName("importAssetsCsv(commit) inserts asset and normalizes external_key to uppercase")
    void importAssetsCsv_commit_insertsAsset() throws Exception {
        String csv = """
                external_key,name,asset_type,owner,note,platform,os_version
                host-01,Host One,SERVER,Alice,Primary server,windows,11
                """;

        ImportResult result = csvImportService.importAssetsCsv(
                bytes(csv),
                true
        );

        assertThat(result.dryRun()).isFalse();
        assertThat(result.linesRead()).isEqualTo(2);
        assertThat(result.ok()).isEqualTo(1);
        assertThat(result.inserted()).isEqualTo(1);
        assertThat(result.updated()).isEqualTo(0);
        assertThat(result.errors()).isEqualTo(0);

        Asset asset = assetRepository.findByExternalKey("HOST-01").orElse(null);
        assertThat(asset).isNotNull();
        assertThat(asset.getName()).isEqualTo("Host One");
        assertThat(asset.getAssetType()).isEqualTo("SERVER");
        assertThat(asset.getOwner()).isEqualTo("Alice");
        assertThat(asset.getPlatform()).isEqualTo("windows");
        assertThat(asset.getOsVersion()).isEqualTo("11");
        assertThat(asset.getSource()).isEqualTo("CSV");
        assertThat(asset.getLastSeenAt()).isNotNull();

        List<ImportRun> runs = importRunRepository.findAll();
        assertThat(runs).hasSize(1);

        ImportRun run = runs.get(0);
        assertThat(run.getSource()).isEqualTo("CSV");
        assertThat(run.getKind()).isEqualTo("CSV_ASSETS");
        assertThat(run.getAssetsUpserted()).isEqualTo(1);
        assertThat(run.getSoftwareUpserted()).isEqualTo(0);
        assertThat(run.getErrorCount()).isEqualTo(0);
        assertThat(run.getFinishedAt()).isNotNull();
    }

    @Test
    @DisplayName("importAssetsCsv(commit) updates existing asset basic fields but keeps existing name")
    void importAssetsCsv_commit_updatesExistingAsset_butKeepsName() throws Exception {
        Asset asset = new Asset("Original Name");
        asset.updateDetails("HOST-01", "SERVER", "Alice", "old");
        asset.setPlatform("windows");
        asset.setOsVersion("10");
        assetRepository.save(asset);

        String csv = """
                external_key,name,asset_type,owner,note,platform,os_version
                host-01,New Name,WORKSTATION,Bob,new note,linux,22.04
                """;

        ImportResult result = csvImportService.importAssetsCsv(
                bytes(csv),
                true
        );

        assertThat(result.ok()).isEqualTo(1);
        assertThat(result.inserted()).isEqualTo(0);
        assertThat(result.updated()).isEqualTo(1);
        assertThat(assetRepository.count()).isEqualTo(1);

        Asset reloaded = assetRepository.findByExternalKey("HOST-01").orElseThrow();
        assertThat(reloaded.getName()).isEqualTo("Original Name"); // current behavior
        assertThat(reloaded.getAssetType()).isEqualTo("WORKSTATION");
        assertThat(reloaded.getOwner()).isEqualTo("Bob");
        assertThat(reloaded.getNote()).isEqualTo("new note");
        assertThat(reloaded.getPlatform()).isEqualTo("linux");
        assertThat(reloaded.getOsVersion()).isEqualTo("22.04");
        assertThat(reloaded.getSource()).isEqualTo("CSV");
    }

    @Test
    @DisplayName("importAssetsCsv returns validation error when required columns are missing")
    void importAssetsCsv_returnsError_whenRequiredColumnMissing() throws Exception {
        String csv = """
                external_key,asset_type
                host-01,SERVER
                """;

        ImportResult result = csvImportService.importAssetsCsv(
                bytes(csv),
                false
        );

        assertThat(result.hasErrors()).isTrue();
        assertThat(result.errorList())
                .extracting(ImportError::code)
                .contains("MISSING_COLUMN");
    }

    @Test
    @DisplayName("importSoftwareCsv(dry-run) returns counts without persisting software or import run")
    void importSoftwareCsv_dryRun_returnsCountsWithoutPersisting() throws Exception {
        Asset asset = new Asset("Host One");
        asset.updateDetails("HOST-01", "SERVER", "Alice", null);
        assetRepository.save(asset);

        String csv = """
                external_key,vendor,product,version,cpe_name
                host-01,Microsoft,Edge,120.0,
                """;

        ImportResult result = csvImportService.importSoftwareCsv(
                bytes(csv),
                false
        );

        assertThat(result.dryRun()).isTrue();
        assertThat(result.linesRead()).isEqualTo(2);
        assertThat(result.ok()).isEqualTo(1);
        assertThat(result.inserted()).isEqualTo(1);
        assertThat(result.updated()).isEqualTo(0);
        assertThat(result.errors()).isEqualTo(0);

        assertThat(softwareInstallRepository.count()).isZero();
        assertThat(unresolvedMappingRepository.count()).isZero();
        assertThat(importRunRepository.count()).isZero();
    }

    @Test
    @DisplayName("importSoftwareCsv(commit) inserts software, import run, and unresolved mapping when cpe is blank")
    void importSoftwareCsv_commit_insertsSoftwareAndQueuesUnresolved() throws Exception {
        Asset asset = new Asset("Host One");
        asset.updateDetails("HOST-01", "SERVER", "Alice", null);
        assetRepository.save(asset);

        String csv = """
                external_key,vendor,product,version,cpe_name
                host-01,Microsoft,Edge,120.0,
                """;

        ImportResult result = csvImportService.importSoftwareCsv(
                bytes(csv),
                true
        );

        assertThat(result.dryRun()).isFalse();
        assertThat(result.linesRead()).isEqualTo(2);
        assertThat(result.ok()).isEqualTo(1);
        assertThat(result.inserted()).isEqualTo(1);
        assertThat(result.updated()).isEqualTo(0);
        assertThat(result.errors()).isEqualTo(0);

        Optional<SoftwareInstall> swOpt =
                softwareInstallRepository.findByAssetIdAndVendorAndProductAndVersion(
                        assetRepository.findByExternalKey("HOST-01").orElseThrow().getId(),
                        "Microsoft",
                        "Edge",
                        "120.0"
                );

        assertThat(swOpt).isPresent();
        SoftwareInstall sw = swOpt.get();

        assertThat(sw.getSource()).isEqualTo("CSV");
        assertThat(sw.getVendorRaw()).isEqualTo("Microsoft");
        assertThat(sw.getProductRaw()).isEqualTo("Edge");
        assertThat(sw.getVersionRaw()).isEqualTo("120.0");
        assertThat(sw.getVersionNorm()).isEqualTo("120.0");
        assertThat(sw.getImportRunId()).isNotNull();
        assertThat(sw.getLastSeenAt()).isNotNull();
        assertThat(sw.getCpeName()).isNull();
        assertThat(sw.getCpeVendorId()).isNull();
        assertThat(sw.getCpeProductId()).isNull();

        List<UnresolvedMapping> unresolved = unresolvedMappingRepository.findAll();
        assertThat(unresolved).hasSize(1);
        assertThat(unresolved.get(0).getSource()).isEqualTo("CSV");
        assertThat(unresolved.get(0).getVendorRaw()).isEqualTo("Microsoft");
        assertThat(unresolved.get(0).getProductRaw()).isEqualTo("Edge");
        assertThat(unresolved.get(0).getVersionRaw()).isEqualTo("120.0");
        assertThat(unresolved.get(0).getFirstSeenAt()).isNotNull();
        assertThat(unresolved.get(0).getLastSeenAt()).isNotNull();

        List<ImportRun> runs = importRunRepository.findAll();
        assertThat(runs).hasSize(1);

        ImportRun run = runs.get(0);
        assertThat(run.getSource()).isEqualTo("CSV");
        assertThat(run.getKind()).isEqualTo("CSV_SOFTWARE");
        assertThat(run.getSoftwareUpserted()).isEqualTo(1);
        assertThat(run.getUnresolvedCount()).isEqualTo(1);
        assertThat(run.getErrorCount()).isEqualTo(0);
        assertThat(run.getFinishedAt()).isNotNull();
    }

    @Test
    @DisplayName("importSoftwareCsv(commit) updates existing software row instead of inserting duplicate")
    void importSoftwareCsv_commit_updatesExistingSoftware() throws Exception {
        Asset asset = new Asset("Host One");
        asset.updateDetails("HOST-01", "SERVER", "Alice", null);
        assetRepository.save(asset);

        SoftwareInstall existing = new SoftwareInstall(asset, "Edge");
        existing.updateDetails("Microsoft", "Edge", "120.0", null);
        existing.markSeen("MANUAL");
        softwareInstallRepository.save(existing);

        String csv = """
                external_key,vendor,product,version,cpe_name
                host-01,Microsoft,Edge,120.0,cpe:2.3:a:microsoft:edge:120.0:*:*:*:*:*:*:*
                """;

        ImportResult result = csvImportService.importSoftwareCsv(
                bytes(csv),
                true
        );

        assertThat(result.ok()).isEqualTo(1);
        assertThat(result.inserted()).isEqualTo(0);
        assertThat(result.updated()).isEqualTo(1);
        assertThat(softwareInstallRepository.count()).isEqualTo(1);

        SoftwareInstall reloaded = softwareInstallRepository
                .findByAssetIdAndVendorAndProductAndVersion(asset.getId(), "Microsoft", "Edge", "120.0")
                .orElseThrow();

        assertThat(reloaded.getCpeName())
                .isEqualTo("cpe:2.3:a:microsoft:edge:120.0:*:*:*:*:*:*:*");
        assertThat(unresolvedMappingRepository.count()).isZero();
    }

    @Test
    @DisplayName("importSoftwareCsv returns ASSET_NOT_FOUND when external_key does not exist")
    void importSoftwareCsv_returnsError_whenAssetNotFound() throws Exception {
        String csv = """
                external_key,vendor,product,version,cpe_name
                host-99,Microsoft,Edge,120.0,
                """;

        ImportResult result = csvImportService.importSoftwareCsv(
                bytes(csv),
                false
        );

        assertThat(result.hasErrors()).isTrue();
        assertThat(result.errorList())
                .extracting(ImportError::code)
                .contains("ASSET_NOT_FOUND");

        assertThat(result.ok()).isEqualTo(0);
        assertThat(result.inserted()).isEqualTo(0);
        assertThat(result.updated()).isEqualTo(0);
    }

    @Test
    @DisplayName("importSoftwareCsv(commit) upserts unresolved mapping by vendor_raw + product_raw")
    void importSoftwareCsv_commit_upsertsUnresolvedMappingByVendorAndProduct() throws Exception {
        Asset asset = new Asset("Host One");
        asset.updateDetails("HOST-01", "SERVER", "Alice", null);
        assetRepository.save(asset);

        String csv1 = """
                external_key,vendor,product,version,cpe_name
                host-01,Microsoft,Edge,120.0,
                """;

        String csv2 = """
                external_key,vendor,product,version,cpe_name
                host-01,Microsoft,Edge,121.0,
                """;

        csvImportService.importSoftwareCsv(bytes(csv1), true);
        csvImportService.importSoftwareCsv(bytes(csv2), true);

        List<UnresolvedMapping> unresolved = unresolvedMappingRepository.findAll();
        assertThat(unresolved).hasSize(1);

        UnresolvedMapping um = unresolved.get(0);
        assertThat(um.getVendorRaw()).isEqualTo("Microsoft");
        assertThat(um.getProductRaw()).isEqualTo("Edge");
        assertThat(um.getVersionRaw()).isEqualTo("121.0"); // latest reference value
        assertThat(softwareInstallRepository.count()).isEqualTo(2); // current unique strategy: version included
    }

    @Test
    @DisplayName("importSoftwareCsv(commit) queues unresolved when overrideLineNos contains the row even if cpe_name is present")
    void importSoftwareCsv_commit_overrideLineForcesUnresolvedQueue() throws Exception {
        Asset asset = new Asset("Host One");
        asset.updateDetails("HOST-01", "SERVER", "Alice", null);
        assetRepository.save(asset);

        String csv = """
                external_key,vendor,product,version,cpe_name
                host-01,Microsoft,Edge,120.0,cpe:2.3:a:microsoft:edge:120.0:*:*:*:*:*:*:*
                """;

        ImportResult result = csvImportService.importSoftwareCsv(
                bytes(csv),
                true,
                Set.of(2) // header=1, first data row=2
        );

        assertThat(result.errors()).isEqualTo(0);
        assertThat(unresolvedMappingRepository.count()).isEqualTo(1);
    }

    private static ByteArrayInputStream bytes(String s) {
        return new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8));
    }
}