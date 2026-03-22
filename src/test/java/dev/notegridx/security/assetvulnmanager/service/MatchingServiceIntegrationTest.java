package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.Alert;
import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.domain.Vulnerability;
import dev.notegridx.security.assetvulnmanager.domain.VulnerabilityAffectedCpe;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertCertainty;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertMatchMethod;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertUncertainReason;
import dev.notegridx.security.assetvulnmanager.domain.enums.CloseReason;
import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityAffectedCpeRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityRepository;
import dev.notegridx.security.assetvulnmanager.domain.VulnerabilityCriteriaCpe;
import dev.notegridx.security.assetvulnmanager.domain.VulnerabilityCriteriaNode;
import dev.notegridx.security.assetvulnmanager.domain.enums.CriteriaNodeType;
import dev.notegridx.security.assetvulnmanager.domain.enums.CriteriaOperator;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityCriteriaCpeRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityCriteriaNodeRepository;

import java.time.LocalDateTime;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class MatchingServiceIntegrationTest {

    @Autowired
    private MatchingService matchingService;

    @Autowired
    private AlertRepository alertRepository;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private SoftwareInstallRepository softwareInstallRepository;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private VulnerabilityAffectedCpeRepository affectedCpeRepository;

    @Autowired
    private CpeVendorRepository cpeVendorRepository;

    @Autowired
    private CpeProductRepository cpeProductRepository;

    @Autowired
    private VulnerabilityCriteriaNodeRepository criteriaNodeRepository;

    @Autowired
    private VulnerabilityCriteriaCpeRepository criteriaCpeRepository;

    @Test
    @DisplayName("matchAndUpsertAlerts creates CONFIRMED alert when canonical IDs match and version is in range")
    void matchAndUpsertAlerts_createsConfirmedAlert_forCanonicalMatchInRange() {
        CpeVendor vendor = cpeVendorRepository.save(new CpeVendor("microsoft", "Microsoft"));
        CpeProduct product = cpeProductRepository.save(new CpeProduct(vendor, "edge", "Microsoft Edge"));

        Asset asset = assetRepository.save(new Asset("Host-01"));

        SoftwareInstall sw = new SoftwareInstall(asset, "Microsoft Edge");
        sw.updateDetails("Microsoft", "Microsoft Edge", "120.0.0", null);
        sw.linkCanonical(vendor.getId(), product.getId());
        sw = softwareInstallRepository.save(sw);

        Vulnerability vuln = new Vulnerability("NVD", "CVE-2099-0001");
        vuln.applyNvdDetails(
                "Test description",
                "3.1",
                new BigDecimal("9.8"),
                null,
                null
        );
        vuln = vulnerabilityRepository.save(vuln);

        affectedCpeRepository.save(new VulnerabilityAffectedCpe(
                vuln,
                "cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*",
                vendor.getId(),
                product.getId(),
                "microsoft",
                "edge",
                "a",
                "*",
                "*",
                "100.0.0",
                "",
                "130.0.0",
                ""
        ));

        Object result = matchingService.matchAndUpsertAlerts();
        assertThat(result).isNotNull();

        Alert alert = alertRepository
                .findBySoftwareInstallIdAndVulnerabilityId(sw.getId(), vuln.getId())
                .orElse(null);

        assertThat(alert).isNotNull();
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getUncertainReason()).isNull();
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
    }

    @Test
    @DisplayName("matchAndUpsertAlerts creates UNCONFIRMED alert when canonical IDs match but software version is missing")
    void matchAndUpsertAlerts_createsUnconfirmedAlert_whenSoftwareVersionIsMissing() {
        CpeVendor vendor = cpeVendorRepository.save(new CpeVendor("microsoft", "Microsoft"));
        CpeProduct product = cpeProductRepository.save(new CpeProduct(vendor, "edge", "Microsoft Edge"));

        Asset asset = assetRepository.save(new Asset("Host-02"));

        SoftwareInstall sw = new SoftwareInstall(asset, "Microsoft Edge");
        sw.updateDetails("Microsoft", "Microsoft Edge", "", null);
        sw.linkCanonical(vendor.getId(), product.getId());
        sw = softwareInstallRepository.save(sw);

        Vulnerability vuln = new Vulnerability("NVD", "CVE-2099-0002");
        vuln.applyNvdDetails(
                "Test description 2",
                "3.1",
                new BigDecimal("7.5"),
                null,
                null
        );
        vuln = vulnerabilityRepository.save(vuln);

        affectedCpeRepository.save(new VulnerabilityAffectedCpe(
                vuln,
                "cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*",
                vendor.getId(),
                product.getId(),
                "microsoft",
                "edge",
                "a",
                "*",
                "*",
                "100.0.0",
                "",
                "130.0.0",
                ""
        ));

        Object result = matchingService.matchAndUpsertAlerts();
        assertThat(result).isNotNull();

        Alert alert = alertRepository
                .findBySoftwareInstallIdAndVulnerabilityId(sw.getId(), vuln.getId())
                .orElse(null);

        assertThat(alert).isNotNull();
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.UNCONFIRMED);
        assertThat(alert.getUncertainReason()).isEqualTo(AlertUncertainReason.MISSING_SOFTWARE_VERSION);
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
    }

    @Test
    @DisplayName("matchAndUpsertAlerts creates UNCONFIRMED alert when canonical IDs match and vulnerability has no version constraint")
    void matchAndUpsertAlerts_createsUnconfirmedAlert_whenNoVersionConstraintExists() {
        CpeVendor vendor = cpeVendorRepository.save(new CpeVendor("google", "Google"));
        CpeProduct product = cpeProductRepository.save(new CpeProduct(vendor, "chrome", "Google Chrome"));

        Asset asset = assetRepository.save(new Asset("Host-03"));

        SoftwareInstall sw = new SoftwareInstall(asset, "Google Chrome");
        sw.updateDetails("Google", "Google Chrome", "122.0.0", null);
        sw.linkCanonical(vendor.getId(), product.getId());
        sw = softwareInstallRepository.save(sw);

        Vulnerability vuln = new Vulnerability("NVD", "CVE-2099-0003");
        vuln.applyNvdDetails(
                "Test description 3",
                "3.1",
                new BigDecimal("5.0"),
                null,
                null
        );
        vuln = vulnerabilityRepository.save(vuln);

        affectedCpeRepository.save(new VulnerabilityAffectedCpe(
                vuln,
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                vendor.getId(),
                product.getId(),
                "google",
                "chrome",
                "a",
                "*",
                "*",
                "",
                "",
                "",
                ""
        ));

        Object result = matchingService.matchAndUpsertAlerts();
        assertThat(result).isNotNull();

        Alert alert = alertRepository
                .findBySoftwareInstallIdAndVulnerabilityId(sw.getId(), vuln.getId())
                .orElse(null);

        assertThat(alert).isNotNull();
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.UNCONFIRMED);
        assertThat(alert.getUncertainReason()).isEqualTo(AlertUncertainReason.NO_VERSION_CONSTRAINT);
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
    }

    @Test
    @DisplayName("matchAndUpsertAlerts does not create alert when canonical IDs match but version is out of range")
    void matchAndUpsertAlerts_doesNotCreateAlert_whenVersionIsOutOfRange() {
        CpeVendor vendor = cpeVendorRepository.save(new CpeVendor("microsoft", "Microsoft"));
        CpeProduct product = cpeProductRepository.save(new CpeProduct(vendor, "edge", "Microsoft Edge"));

        Asset asset = assetRepository.save(new Asset("Host-04"));

        SoftwareInstall sw = new SoftwareInstall(asset, "Microsoft Edge");
        sw.updateDetails("Microsoft", "Microsoft Edge", "140.0.0", null);
        sw.linkCanonical(vendor.getId(), product.getId());
        sw = softwareInstallRepository.save(sw);

        Vulnerability vuln = new Vulnerability("NVD", "CVE-2099-0004");
        vuln.applyNvdDetails(
                "Test description 4",
                "3.1",
                new BigDecimal("8.1"),
                null,
                null
        );
        vuln = vulnerabilityRepository.save(vuln);

        affectedCpeRepository.save(new VulnerabilityAffectedCpe(
                vuln,
                "cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*",
                vendor.getId(),
                product.getId(),
                "microsoft",
                "edge",
                "a",
                "*",
                "*",
                "100.0.0",
                "",
                "130.0.0",
                ""
        ));

        Object result = matchingService.matchAndUpsertAlerts();
        assertThat(result).isNotNull();

        Alert alert = alertRepository
                .findBySoftwareInstallIdAndVulnerabilityId(sw.getId(), vuln.getId())
                .orElse(null);

        assertThat(alert).isNull();
        assertThat(alertRepository.findAll()).isEmpty();
    }

    @Test
    @DisplayName("matchAndUpsertAlerts is idempotent for the same software and vulnerability")
    void matchAndUpsertAlerts_isIdempotent_forSameMatch() {
        CpeVendor vendor = cpeVendorRepository.save(new CpeVendor("google", "Google"));
        CpeProduct product = cpeProductRepository.save(new CpeProduct(vendor, "chrome", "Google Chrome"));

        Asset asset = assetRepository.save(new Asset("Host-05"));

        SoftwareInstall sw = new SoftwareInstall(asset, "Google Chrome");
        sw.updateDetails("Google", "Google Chrome", "122.0.0", null);
        sw.linkCanonical(vendor.getId(), product.getId());
        sw = softwareInstallRepository.save(sw);

        Vulnerability vuln = new Vulnerability("NVD", "CVE-2099-0005");
        vuln.applyNvdDetails(
                "Test description 5",
                "3.1",
                new BigDecimal("6.5"),
                null,
                null
        );
        vuln = vulnerabilityRepository.save(vuln);

        affectedCpeRepository.save(new VulnerabilityAffectedCpe(
                vuln,
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                vendor.getId(),
                product.getId(),
                "google",
                "chrome",
                "a",
                "*",
                "*",
                "120.0.0",
                "",
                "130.0.0",
                ""
        ));

        Object result1 = matchingService.matchAndUpsertAlerts();
        Object result2 = matchingService.matchAndUpsertAlerts();

        assertThat(result1).isNotNull();
        assertThat(result2).isNotNull();

        Alert alert = alertRepository
                .findBySoftwareInstallIdAndVulnerabilityId(sw.getId(), vuln.getId())
                .orElse(null);

        assertThat(alert).isNotNull();
        assertThat(alertRepository.findAll()).hasSize(1);
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
    }

    @Test
    @DisplayName("matchAndUpsertAlerts chooses best verdict when multiple affected CPE rows exist")
    void matchAndUpsertAlerts_choosesBestVerdict_whenMultipleAffectedCpesExist() {
        CpeVendor vendor = cpeVendorRepository.save(new CpeVendor("microsoft", "Microsoft"));
        CpeProduct product = cpeProductRepository.save(new CpeProduct(vendor, "edge", "Microsoft Edge"));

        Asset asset = assetRepository.save(new Asset("Host-06"));

        SoftwareInstall sw = new SoftwareInstall(asset, "Microsoft Edge");
        sw.updateDetails("Microsoft", "Microsoft Edge", "120.0.0", null);
        sw.linkCanonical(vendor.getId(), product.getId());
        sw = softwareInstallRepository.save(sw);

        Vulnerability vuln = new Vulnerability("NVD", "CVE-2099-0006");
        vuln.applyNvdDetails(
                "Test description 6",
                "3.1",
                new BigDecimal("9.0"),
                null,
                null
        );
        vuln = vulnerabilityRepository.save(vuln);

        affectedCpeRepository.save(new VulnerabilityAffectedCpe(
                vuln,
                "cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*",
                vendor.getId(),
                product.getId(),
                "microsoft",
                "edge",
                "a",
                "*",
                "*",
                "",
                "",
                "",
                ""
        ));

        affectedCpeRepository.save(new VulnerabilityAffectedCpe(
                vuln,
                "cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*",
                vendor.getId(),
                product.getId(),
                "microsoft",
                "edge",
                "a",
                "*",
                "*",
                "100.0.0",
                "",
                "130.0.0",
                ""
        ));

        Object result = matchingService.matchAndUpsertAlerts();
        assertThat(result).isNotNull();

        Alert alert = alertRepository
                .findBySoftwareInstallIdAndVulnerabilityId(sw.getId(), vuln.getId())
                .orElse(null);

        assertThat(alert).isNotNull();
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getUncertainReason()).isNull();
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
        assertThat(alertRepository.findAll()).hasSize(1);
    }

    @Test
    @DisplayName("matchAndUpsertAlerts reopens previously auto-closed alert when the software is still affected")
    void matchAndUpsertAlerts_reopensPreviouslyAutoClosedAlert_whenStillAffected() {
        CpeVendor vendor = cpeVendorRepository.save(new CpeVendor("google", "Google"));
        CpeProduct product = cpeProductRepository.save(new CpeProduct(vendor, "chrome", "Google Chrome"));

        Asset asset = assetRepository.save(new Asset("Host-07"));

        SoftwareInstall sw = new SoftwareInstall(asset, "Google Chrome");
        sw.updateDetails("Google LLC", "Google Chrome", "145.0.7632.117", null);
        sw.linkCanonical(vendor.getId(), product.getId());
        sw = softwareInstallRepository.save(sw);

        Vulnerability vuln = new Vulnerability("NVD", "CVE-2099-0007");
        vuln.applyNvdDetails(
                "Test description 7",
                "3.1",
                new BigDecimal("8.8"),
                null,
                null
        );
        vuln = vulnerabilityRepository.save(vuln);

        affectedCpeRepository.save(new VulnerabilityAffectedCpe(
                vuln,
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                vendor.getId(),
                product.getId(),
                "google",
                "chrome",
                "a",
                "*",
                "*",
                "",
                "",
                "145.0.7632.159",
                ""
        ));

        Alert existing = new Alert(
                sw,
                vuln,
                java.time.LocalDateTime.now().minusDays(1),
                AlertCertainty.CONFIRMED,
                null,
                AlertMatchMethod.DICT_ID
        );
        existing.close(CloseReason.AUTO_CLOSED_NO_LONGER_AFFECTED, java.time.LocalDateTime.now().minusHours(12));
        existing = alertRepository.save(existing);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.alertsTouched()).isEqualTo(1);
        assertThat(result.alertsInserted()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = alertRepository
                .findBySoftwareInstallIdAndVulnerabilityId(sw.getId(), vuln.getId())
                .orElse(null);

        assertThat(alert).isNotNull();
        assertThat(alert.getId()).isEqualTo(existing.getId());
        assertThat(alert.getStatus()).isEqualTo(AlertStatus.OPEN);
        assertThat(alert.getCloseReason()).isNull();
        assertThat(alert.getClosedAt()).isNull();
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getUncertainReason()).isNull();
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
        assertThat(alert.getLastSeenAt()).isAfterOrEqualTo(alert.getFirstSeenAt());
        assertThat(alertRepository.findAll()).hasSize(1);
    }

    @Test
    @DisplayName("matchAndUpsertAlerts does not auto-close alerts that were touched in the same run")
    void matchAndUpsertAlerts_doesNotAutoCloseTouchedAlerts_inSameRun() {
        CpeVendor vendor = cpeVendorRepository.save(new CpeVendor("google", "Google"));
        CpeProduct product = cpeProductRepository.save(new CpeProduct(vendor, "chrome", "Google Chrome"));

        Asset asset = assetRepository.save(new Asset("Host-08"));

        SoftwareInstall sw = new SoftwareInstall(asset, "Google Chrome");
        sw.updateDetails("Google LLC", "Google Chrome", "145.0.7632.117", null);
        sw.linkCanonical(vendor.getId(), product.getId());
        sw = softwareInstallRepository.save(sw);

        Vulnerability vuln = new Vulnerability("NVD", "CVE-2099-0008");
        vuln.applyNvdDetails(
                "Test description 8",
                "3.1",
                new BigDecimal("8.8"),
                null,
                null
        );
        vuln = vulnerabilityRepository.save(vuln);

        affectedCpeRepository.save(new VulnerabilityAffectedCpe(
                vuln,
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                vendor.getId(),
                product.getId(),
                "google",
                "chrome",
                "a",
                "*",
                "*",
                "",
                "",
                "145.0.7632.159",
                ""
        ));

        Alert existing = new Alert(
                sw,
                vuln,
                java.time.LocalDateTime.now().minusDays(2),
                AlertCertainty.CONFIRMED,
                null,
                AlertMatchMethod.DICT_ID
        );
        existing = alertRepository.save(existing);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.alertsTouched()).isEqualTo(1);
        assertThat(result.alertsInserted()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = alertRepository
                .findBySoftwareInstallIdAndVulnerabilityId(sw.getId(), vuln.getId())
                .orElse(null);

        assertThat(alert).isNotNull();
        assertThat(alert.getStatus()).isEqualTo(AlertStatus.OPEN);
        assertThat(alert.getCloseReason()).isNull();
        assertThat(alert.getClosedAt()).isNull();
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
    }

    @Test
    @DisplayName("matchAndUpsertAlerts does not reopen manually closed alert even if it matches again")
    void matchAndUpsertAlerts_doesNotReopenManuallyClosedAlert() {
        CpeVendor vendor = cpeVendorRepository.save(new CpeVendor("google", "Google"));
        CpeProduct product = cpeProductRepository.save(new CpeProduct(vendor, "chrome", "Google Chrome"));

        Asset asset = assetRepository.save(new Asset("Host-09"));

        SoftwareInstall sw = new SoftwareInstall(asset, "Google Chrome");
        sw.updateDetails("Google LLC", "Google Chrome", "145.0.7632.117", null);
        sw.linkCanonical(vendor.getId(), product.getId());
        sw = softwareInstallRepository.save(sw);

        Vulnerability vuln = new Vulnerability("NVD", "CVE-2099-0009");
        vuln.applyNvdDetails(
                "Test description 9",
                "3.1",
                new BigDecimal("8.8"),
                null,
                null
        );
        vuln = vulnerabilityRepository.save(vuln);

        affectedCpeRepository.save(new VulnerabilityAffectedCpe(
                vuln,
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                vendor.getId(),
                product.getId(),
                "google",
                "chrome",
                "a",
                "*",
                "*",
                "",
                "",
                "145.0.7632.159",
                ""
        ));

        Alert existing = new Alert(
                sw,
                vuln,
                java.time.LocalDateTime.now().minusDays(1),
                AlertCertainty.CONFIRMED,
                null,
                AlertMatchMethod.DICT_ID
        );
        existing.close(CloseReason.ACCEPTED_RISK, java.time.LocalDateTime.now().minusHours(10));
        existing = alertRepository.save(existing);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.alertsTouched()).isEqualTo(1);
        assertThat(result.alertsInserted()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = alertRepository
                .findBySoftwareInstallIdAndVulnerabilityId(sw.getId(), vuln.getId())
                .orElse(null);

        assertThat(alert).isNotNull();
        assertThat(alert.getId()).isEqualTo(existing.getId());
        assertThat(alert.getStatus()).isEqualTo(AlertStatus.CLOSED);
        assertThat(alert.getCloseReason()).isEqualTo(CloseReason.ACCEPTED_RISK);
        assertThat(alert.getClosedAt()).isNotNull();
    }

    private Asset saveAsset(String name, String platform) {
        Asset asset = new Asset(name);
        asset.setPlatform(platform);
        return assetRepository.save(asset);
    }

    private CpeVendor saveVendor(String nameNorm, String displayName) {
        return cpeVendorRepository.save(new CpeVendor(nameNorm, displayName));
    }

    private CpeProduct saveProduct(CpeVendor vendor, String nameNorm, String displayName) {
        return cpeProductRepository.save(new CpeProduct(vendor, nameNorm, displayName));
    }

    private SoftwareInstall saveSoftwareCanonical(
            Asset asset,
            String vendor,
            String product,
            String version,
            Long vendorId,
            Long productId
    ) {
        SoftwareInstall sw = new SoftwareInstall(asset, product);
        sw.updateDetails(vendor, product, version, null);
        sw.linkCanonical(vendorId, productId);
        return softwareInstallRepository.save(sw);
    }

    private SoftwareInstall saveSoftwareNormOnly(
            Asset asset,
            String vendor,
            String product,
            String version
    ) {
        SoftwareInstall sw = new SoftwareInstall(asset, product);
        sw.updateDetails(vendor, product, version, null);
        return softwareInstallRepository.save(sw);
    }

    private SoftwareInstall saveSoftwareWithCpeName(
            Asset asset,
            String vendor,
            String product,
            String version,
            String cpeName
    ) {
        SoftwareInstall sw = new SoftwareInstall(asset, product);
        sw.updateDetails(vendor, product, version, cpeName);
        return softwareInstallRepository.save(sw);
    }

    private Vulnerability saveVulnerability(String cveId, String description, BigDecimal score) {
        Vulnerability vuln = new Vulnerability("NVD", cveId);
        vuln.applyNvdDetails(
                description + " description",
                "3.1",
                score,
                null,
                null
        );
        return vulnerabilityRepository.save(vuln);
    }

    private VulnerabilityCriteriaNode saveOperatorNode(
            Vulnerability vuln,
            Long parentId,
            int rootGroupNo,
            int sortOrder,
            CriteriaOperator operator
    ) {
        return criteriaNodeRepository.save(new VulnerabilityCriteriaNode(
                vuln,
                parentId,
                rootGroupNo,
                CriteriaNodeType.OPERATOR,
                operator,
                false,
                sortOrder
        ));
    }

    private VulnerabilityCriteriaNode saveLeafNode(
            Vulnerability vuln,
            Long parentId,
            int rootGroupNo,
            int sortOrder
    ) {
        return criteriaNodeRepository.save(new VulnerabilityCriteriaNode(
                vuln,
                parentId,
                rootGroupNo,
                CriteriaNodeType.LEAF_GROUP,
                null,
                false,
                sortOrder
        ));
    }

    private VulnerabilityCriteriaCpe saveCriteriaCpe(
            VulnerabilityCriteriaNode node,
            Vulnerability vuln,
            String cpeName,
            Long vendorId,
            Long productId,
            String vendorNorm,
            String productNorm,
            String cpePart,
            String targetSw,
            String targetHw,
            String vsi,
            String vse,
            String vei,
            String vee
    ) {
        return criteriaCpeRepository.save(new VulnerabilityCriteriaCpe(
                node.getId(),
                vuln,
                cpeName,
                vendorId,
                productId,
                vendorNorm,
                productNorm,
                cpePart,
                targetSw,
                targetHw,
                vsi,
                vse,
                vei,
                vee,
                true
        ));
    }

    private VulnerabilityAffectedCpe saveAffectedFlat(
            Vulnerability vuln,
            String cpeName,
            Long vendorId,
            Long productId,
            String vendorNorm,
            String productNorm,
            String cpePart,
            String targetSw,
            String targetHw,
            String vsi,
            String vse,
            String vei,
            String vee,
            Long criteriaNodeId,
            int rootGroupNo
    ) {
        return affectedCpeRepository.save(new VulnerabilityAffectedCpe(
                vuln,
                cpeName,
                vendorId,
                productId,
                vendorNorm,
                productNorm,
                cpePart,
                targetSw,
                targetHw,
                vsi,
                vse,
                vei,
                vee,
                criteriaNodeId,
                rootGroupNo
        ));
    }

    private Alert findAlert(Long softwareInstallId, Long vulnerabilityId) {
        return alertRepository.findBySoftwareInstallIdAndVulnerabilityId(softwareInstallId, vulnerabilityId)
                .orElse(null);
    }

    private void assertNoAlert(Long softwareInstallId, Long vulnerabilityId) {
        assertThat(findAlert(softwareInstallId, vulnerabilityId)).isNull();
    }

    @Test
    @DisplayName("criteria OR match creates CONFIRMED alert")
    void matchAndUpsertAlerts_createsConfirmedAlert_forCriteriaOrMatch() {
        CpeVendor vendor = saveVendor("vendor21", "Vendor21");
        CpeProduct appA = saveProduct(vendor, "appa21", "AppA21");
        CpeProduct appB = saveProduct(vendor, "appb21", "AppB21");

        Asset asset = saveAsset("Host-21", "windows");
        SoftwareInstall swA = saveSoftwareCanonical(asset, "Vendor21", "AppA21", "1.5", vendor.getId(), appA.getId());

        Vulnerability vuln = saveVulnerability("CVE-2099-0021", "CASE-21", new BigDecimal("8.0"));

        VulnerabilityCriteriaNode root = saveOperatorNode(vuln, null, 0, 0, CriteriaOperator.OR);
        VulnerabilityCriteriaNode leaf = saveLeafNode(vuln, root.getId(), 0, 0);

        saveCriteriaCpe(leaf, vuln, "cpe:2.3:a:vendor21:appa21:*:*:*:*:*:*:*:*",
                vendor.getId(), appA.getId(), "vendor21", "appa21", "a", "*", "*",
                "1.0", "", "2.0", "");
        saveCriteriaCpe(leaf, vuln, "cpe:2.3:a:vendor21:appb21:*:*:*:*:*:*:*:*",
                vendor.getId(), appB.getId(), "vendor21", "appb21", "a", "*", "*",
                "1.0", "", "2.0", "");

        saveAffectedFlat(vuln, "cpe:2.3:a:vendor21:appa21:*:*:*:*:*:*:*:*",
                vendor.getId(), appA.getId(), "vendor21", "appa21", "a", "*", "*",
                "1.0", "", "2.0", "", leaf.getId(), 0);
        saveAffectedFlat(vuln, "cpe:2.3:a:vendor21:appb21:*:*:*:*:*:*:*:*",
                vendor.getId(), appB.getId(), "vendor21", "appb21", "a", "*", "*",
                "1.0", "", "2.0", "", leaf.getId(), 0);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isEqualTo(1);
        assertThat(result.alertsTouched()).isZero();

        Alert alert = findAlert(swA.getId(), vuln.getId());
        assertThat(alert).isNotNull();
        assertThat(alert.getStatus()).isEqualTo(AlertStatus.OPEN);
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
    }

    @Test
    @DisplayName("criteria OR no match creates no alert")
    void matchAndUpsertAlerts_createsNoAlert_forCriteriaOrNoMatch() {
        CpeVendor vendor = saveVendor("vendor22", "Vendor22");
        CpeProduct appA = saveProduct(vendor, "appa22", "AppA22");
        CpeProduct appB = saveProduct(vendor, "appb22", "AppB22");
        CpeProduct appC = saveProduct(vendor, "appc22", "AppC22");

        Asset asset = saveAsset("Host-22", "windows");
        SoftwareInstall swC = saveSoftwareCanonical(asset, "Vendor22", "AppC22", "1.5", vendor.getId(), appC.getId());

        Vulnerability vuln = saveVulnerability("CVE-2099-0022", "CASE-22", new BigDecimal("6.5"));

        VulnerabilityCriteriaNode root = saveOperatorNode(vuln, null, 0, 0, CriteriaOperator.OR);
        VulnerabilityCriteriaNode leaf = saveLeafNode(vuln, root.getId(), 0, 0);

        saveCriteriaCpe(leaf, vuln, "cpe:2.3:a:vendor22:appa22:*:*:*:*:*:*:*:*",
                vendor.getId(), appA.getId(), "vendor22", "appa22", "a", "*", "*",
                "1.0", "", "2.0", "");
        saveCriteriaCpe(leaf, vuln, "cpe:2.3:a:vendor22:appb22:*:*:*:*:*:*:*:*",
                vendor.getId(), appB.getId(), "vendor22", "appb22", "a", "*", "*",
                "1.0", "", "2.0", "");

        saveAffectedFlat(vuln, "cpe:2.3:a:vendor22:appa22:*:*:*:*:*:*:*:*",
                vendor.getId(), appA.getId(), "vendor22", "appa22", "a", "*", "*",
                "1.0", "", "2.0", "", leaf.getId(), 0);
        saveAffectedFlat(vuln, "cpe:2.3:a:vendor22:appb22:*:*:*:*:*:*:*:*",
                vendor.getId(), appB.getId(), "vendor22", "appb22", "a", "*", "*",
                "1.0", "", "2.0", "", leaf.getId(), 0);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result.pairsFound()).isZero();
        assertThat(result.alertsInserted()).isZero();
        assertThat(result.alertsTouched()).isZero();

        assertNoAlert(swC.getId(), vuln.getId());
        assertThat(alertRepository.findAll()).isEmpty();
    }

    @Test
    @DisplayName("criteria AND missing leg creates no alert")
    void matchAndUpsertAlerts_createsNoAlert_forCriteriaAndMissingLeg() {
        CpeVendor vendor = saveVendor("vendor23", "Vendor23");
        CpeProduct appA = saveProduct(vendor, "appa23", "AppA23");
        CpeProduct appB = saveProduct(vendor, "appb23", "AppB23");

        Asset asset = saveAsset("Host-23", "windows");
        SoftwareInstall swA = saveSoftwareCanonical(asset, "Vendor23", "AppA23", "3.0", vendor.getId(), appA.getId());

        Vulnerability vuln = saveVulnerability("CVE-2099-0023", "CASE-23", new BigDecimal("8.4"));

        VulnerabilityCriteriaNode root = saveOperatorNode(vuln, null, 0, 0, CriteriaOperator.AND);
        VulnerabilityCriteriaNode leafA = saveLeafNode(vuln, root.getId(), 0, 0);
        VulnerabilityCriteriaNode leafB = saveLeafNode(vuln, root.getId(), 0, 1);

        saveCriteriaCpe(leafA, vuln, "cpe:2.3:a:vendor23:appa23:*:*:*:*:*:*:*:*",
                vendor.getId(), appA.getId(), "vendor23", "appa23", "a", "*", "*",
                "2.0", "", "4.0", "");
        saveCriteriaCpe(leafB, vuln, "cpe:2.3:a:vendor23:appb23:*:*:*:*:*:*:*:*",
                vendor.getId(), appB.getId(), "vendor23", "appb23", "a", "*", "*",
                "2.0", "", "4.0", "");

        saveAffectedFlat(vuln, "cpe:2.3:a:vendor23:appa23:*:*:*:*:*:*:*:*",
                vendor.getId(), appA.getId(), "vendor23", "appa23", "a", "*", "*",
                "2.0", "", "4.0", "", leafA.getId(), 0);
        saveAffectedFlat(vuln, "cpe:2.3:a:vendor23:appb23:*:*:*:*:*:*:*:*",
                vendor.getId(), appB.getId(), "vendor23", "appb23", "a", "*", "*",
                "2.0", "", "4.0", "", leafB.getId(), 0);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isZero();
        assertThat(result.alertsTouched()).isZero();

        assertNoAlert(swA.getId(), vuln.getId());
    }

    @Test
    @DisplayName("criteria AND match creates CONFIRMED alert")
    void matchAndUpsertAlerts_createsConfirmedAlert_forCriteriaAndMatch() {
        CpeVendor vendor = saveVendor("vendor24", "Vendor24");
        CpeProduct appA = saveProduct(vendor, "appa24", "AppA24");
        CpeProduct appB = saveProduct(vendor, "appb24", "AppB24");

        Asset asset = saveAsset("Host-24", "windows");
        SoftwareInstall swA = saveSoftwareCanonical(asset, "Vendor24", "AppA24", "3.5", vendor.getId(), appA.getId());
        SoftwareInstall swB = saveSoftwareCanonical(asset, "Vendor24", "AppB24", "3.5", vendor.getId(), appB.getId());

        Vulnerability vuln = saveVulnerability("CVE-2099-0024", "CASE-24", new BigDecimal("9.1"));

        VulnerabilityCriteriaNode root = saveOperatorNode(vuln, null, 0, 0, CriteriaOperator.AND);
        VulnerabilityCriteriaNode leafA = saveLeafNode(vuln, root.getId(), 0, 0);
        VulnerabilityCriteriaNode leafB = saveLeafNode(vuln, root.getId(), 0, 1);

        saveCriteriaCpe(leafA, vuln, "cpe:2.3:a:vendor24:appa24:*:*:*:*:*:*:*:*",
                vendor.getId(), appA.getId(), "vendor24", "appa24", "a", "*", "*",
                "3.0", "", "4.0", "");
        saveCriteriaCpe(leafB, vuln, "cpe:2.3:a:vendor24:appb24:*:*:*:*:*:*:*:*",
                vendor.getId(), appB.getId(), "vendor24", "appb24", "a", "*", "*",
                "3.0", "", "4.0", "");

        saveAffectedFlat(vuln, "cpe:2.3:a:vendor24:appa24:*:*:*:*:*:*:*:*",
                vendor.getId(), appA.getId(), "vendor24", "appa24", "a", "*", "*",
                "3.0", "", "4.0", "", leafA.getId(), 0);
        saveAffectedFlat(vuln, "cpe:2.3:a:vendor24:appb24:*:*:*:*:*:*:*:*",
                vendor.getId(), appB.getId(), "vendor24", "appb24", "a", "*", "*",
                "3.0", "", "4.0", "", leafB.getId(), 0);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isEqualTo(1);

        Alert alert = findAlert(swA.getId(), vuln.getId());
        assertThat(alert).isNotNull();
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);

        assertNoAlert(swB.getId(), vuln.getId());
    }

    @Test
    @DisplayName("nested (A OR B) AND C creates CONFIRMED alert")
    void matchAndUpsertAlerts_createsConfirmedAlert_forNestedOrAndMatch() {
        CpeVendor vendor = saveVendor("vendor25", "Vendor25");
        CpeProduct appA = saveProduct(vendor, "appa25", "AppA25");
        CpeProduct appB = saveProduct(vendor, "appb25", "AppB25");
        CpeProduct appC = saveProduct(vendor, "appc25", "AppC25");

        Asset asset = saveAsset("Host-25", "windows");
        SoftwareInstall swB = saveSoftwareCanonical(asset, "Vendor25", "AppB25", "5.1", vendor.getId(), appB.getId());
        SoftwareInstall swC = saveSoftwareCanonical(asset, "Vendor25", "AppC25", "5.1", vendor.getId(), appC.getId());

        Vulnerability vuln = saveVulnerability("CVE-2099-0025", "CASE-25", new BigDecimal("8.7"));

        VulnerabilityCriteriaNode root = saveOperatorNode(vuln, null, 0, 0, CriteriaOperator.AND);
        VulnerabilityCriteriaNode left = saveLeafNode(vuln, root.getId(), 0, 0);
        VulnerabilityCriteriaNode right = saveLeafNode(vuln, root.getId(), 0, 1);

        saveCriteriaCpe(left, vuln, "cpe:2.3:a:vendor25:appa25:*:*:*:*:*:*:*:*",
                vendor.getId(), appA.getId(), "vendor25", "appa25", "a", "*", "*",
                "5.0", "", "6.0", "");
        saveCriteriaCpe(left, vuln, "cpe:2.3:a:vendor25:appb25:*:*:*:*:*:*:*:*",
                vendor.getId(), appB.getId(), "vendor25", "appb25", "a", "*", "*",
                "5.0", "", "6.0", "");
        saveCriteriaCpe(right, vuln, "cpe:2.3:a:vendor25:appc25:*:*:*:*:*:*:*:*",
                vendor.getId(), appC.getId(), "vendor25", "appc25", "a", "*", "*",
                "5.0", "", "6.0", "");

        saveAffectedFlat(vuln, "cpe:2.3:a:vendor25:appa25:*:*:*:*:*:*:*:*",
                vendor.getId(), appA.getId(), "vendor25", "appa25", "a", "*", "*",
                "5.0", "", "6.0", "", left.getId(), 0);
        saveAffectedFlat(vuln, "cpe:2.3:a:vendor25:appb25:*:*:*:*:*:*:*:*",
                vendor.getId(), appB.getId(), "vendor25", "appb25", "a", "*", "*",
                "5.0", "", "6.0", "", left.getId(), 0);
        saveAffectedFlat(vuln, "cpe:2.3:a:vendor25:appc25:*:*:*:*:*:*:*:*",
                vendor.getId(), appC.getId(), "vendor25", "appc25", "a", "*", "*",
                "5.0", "", "6.0", "", right.getId(), 0);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isEqualTo(1);

        Alert alert = findAlert(swB.getId(), vuln.getId());
        assertThat(alert).isNotNull();
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);

        assertNoAlert(swC.getId(), vuln.getId());
    }

    @Test
    @DisplayName("nested (A OR B) AND C with missing C creates no alert")
    void matchAndUpsertAlerts_createsNoAlert_forNestedOrAndMissingLeg() {
        CpeVendor vendor = saveVendor("vendor26", "Vendor26");
        CpeProduct appA = saveProduct(vendor, "appa26", "AppA26");
        CpeProduct appB = saveProduct(vendor, "appb26", "AppB26");
        CpeProduct appC = saveProduct(vendor, "appc26", "AppC26");

        Asset asset = saveAsset("Host-26", "windows");
        SoftwareInstall swB = saveSoftwareCanonical(asset, "Vendor26", "AppB26", "5.1", vendor.getId(), appB.getId());

        Vulnerability vuln = saveVulnerability("CVE-2099-0026", "CASE-26", new BigDecimal("8.2"));

        VulnerabilityCriteriaNode root = saveOperatorNode(vuln, null, 0, 0, CriteriaOperator.AND);
        VulnerabilityCriteriaNode left = saveLeafNode(vuln, root.getId(), 0, 0);
        VulnerabilityCriteriaNode right = saveLeafNode(vuln, root.getId(), 0, 1);

        saveCriteriaCpe(left, vuln, "cpe:2.3:a:vendor26:appa26:*:*:*:*:*:*:*:*",
                vendor.getId(), appA.getId(), "vendor26", "appa26", "a", "*", "*",
                "5.0", "", "6.0", "");
        saveCriteriaCpe(left, vuln, "cpe:2.3:a:vendor26:appb26:*:*:*:*:*:*:*:*",
                vendor.getId(), appB.getId(), "vendor26", "appb26", "a", "*", "*",
                "5.0", "", "6.0", "");
        saveCriteriaCpe(right, vuln, "cpe:2.3:a:vendor26:appc26:*:*:*:*:*:*:*:*",
                vendor.getId(), appC.getId(), "vendor26", "appc26", "a", "*", "*",
                "5.0", "", "6.0", "");

        saveAffectedFlat(vuln, "cpe:2.3:a:vendor26:appa26:*:*:*:*:*:*:*:*",
                vendor.getId(), appA.getId(), "vendor26", "appa26", "a", "*", "*",
                "5.0", "", "6.0", "", left.getId(), 0);
        saveAffectedFlat(vuln, "cpe:2.3:a:vendor26:appb26:*:*:*:*:*:*:*:*",
                vendor.getId(), appB.getId(), "vendor26", "appb26", "a", "*", "*",
                "5.0", "", "6.0", "", left.getId(), 0);
        saveAffectedFlat(vuln, "cpe:2.3:a:vendor26:appc26:*:*:*:*:*:*:*:*",
                vendor.getId(), appC.getId(), "vendor26", "appc26", "a", "*", "*",
                "5.0", "", "6.0", "", right.getId(), 0);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isZero();
        assertThat(result.alertsTouched()).isZero();

        assertNoAlert(swB.getId(), vuln.getId());
    }

    @Test
    @DisplayName("nested version uncertainty in one AND leg creates UNCONFIRMED alert")
    void matchAndUpsertAlerts_createsUnconfirmedAlert_forNestedVersionUnconfirmed() {
        CpeVendor vendor = saveVendor("vendor27", "Vendor27");
        CpeProduct appA = saveProduct(vendor, "appa27", "AppA27");
        CpeProduct appC = saveProduct(vendor, "appc27", "AppC27");

        Asset asset = saveAsset("Host-27", "windows");
        SoftwareInstall swA = saveSoftwareCanonical(asset, "Vendor27", "AppA27", "", vendor.getId(), appA.getId());
        SoftwareInstall swC = saveSoftwareCanonical(asset, "Vendor27", "AppC27", "7.1", vendor.getId(), appC.getId());

        Vulnerability vuln = saveVulnerability("CVE-2099-0027", "CASE-27", new BigDecimal("8.5"));

        VulnerabilityCriteriaNode root = saveOperatorNode(vuln, null, 0, 0, CriteriaOperator.AND);
        VulnerabilityCriteriaNode leafA = saveLeafNode(vuln, root.getId(), 0, 0);
        VulnerabilityCriteriaNode leafC = saveLeafNode(vuln, root.getId(), 0, 1);

        saveCriteriaCpe(leafA, vuln, "cpe:2.3:a:vendor27:appa27:*:*:*:*:*:*:*:*",
                vendor.getId(), appA.getId(), "vendor27", "appa27", "a", "*", "*",
                "7.0", "", "8.0", "");
        saveCriteriaCpe(leafC, vuln, "cpe:2.3:a:vendor27:appc27:*:*:*:*:*:*:*:*",
                vendor.getId(), appC.getId(), "vendor27", "appc27", "a", "*", "*",
                "7.0", "", "8.0", "");

        saveAffectedFlat(vuln, "cpe:2.3:a:vendor27:appa27:*:*:*:*:*:*:*:*",
                vendor.getId(), appA.getId(), "vendor27", "appa27", "a", "*", "*",
                "7.0", "", "8.0", "", leafA.getId(), 0);
        saveAffectedFlat(vuln, "cpe:2.3:a:vendor27:appc27:*:*:*:*:*:*:*:*",
                vendor.getId(), appC.getId(), "vendor27", "appc27", "a", "*", "*",
                "7.0", "", "8.0", "", leafC.getId(), 0);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isEqualTo(1);

        Alert alert = findAlert(swC.getId(), vuln.getId());
        assertThat(alert).isNotNull();
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.UNCONFIRMED);
        assertThat(alert.getUncertainReason()).isEqualTo(AlertUncertainReason.MISSING_SOFTWARE_VERSION);
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);

        assertNoAlert(swA.getId(), vuln.getId());
    }

    @Test
    @DisplayName("target_sw inside criteria leaf prevents match on different host OS")
    void matchAndUpsertAlerts_createsNoAlert_forTargetSwInsideLeafOnDifferentHost() {
        CpeVendor vendor = saveVendor("vendor28", "Vendor28");
        CpeProduct appA = saveProduct(vendor, "appa28", "AppA28");

        Asset asset = saveAsset("Host-28", "mac");
        SoftwareInstall swA = saveSoftwareCanonical(asset, "Vendor28", "AppA28", "8.1", vendor.getId(), appA.getId());

        Vulnerability vuln = saveVulnerability("CVE-2099-0028", "CASE-28", new BigDecimal("6.9"));

        VulnerabilityCriteriaNode leaf = saveLeafNode(vuln, null, 0, 0);

        saveCriteriaCpe(leaf, vuln, "cpe:2.3:a:vendor28:appa28:*:*:*:*:*:windows:*:*",
                vendor.getId(), appA.getId(), "vendor28", "appa28", "a", "windows", "*",
                "8.0", "", "9.0", "");

        saveAffectedFlat(vuln, "cpe:2.3:a:vendor28:appa28:*:*:*:*:*:windows:*:*",
                vendor.getId(), appA.getId(), "vendor28", "appa28", "a", "windows", "*",
                "8.0", "", "9.0", "", leaf.getId(), 0);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isZero();
        assertThat(result.alertsTouched()).isZero();

        assertNoAlert(swA.getId(), vuln.getId());
    }

    @Test
    @DisplayName("multiple root groups behave as OR across roots")
    void matchAndUpsertAlerts_createsConfirmedAlert_forMultipleRootGroupsOr() {
        CpeVendor vendor = saveVendor("vendor29", "Vendor29");
        CpeProduct appA = saveProduct(vendor, "appa29", "AppA29");
        CpeProduct appB = saveProduct(vendor, "appb29", "AppB29");
        CpeProduct appD = saveProduct(vendor, "appd29", "AppD29");

        Asset asset = saveAsset("Host-29", "windows");
        SoftwareInstall swD = saveSoftwareCanonical(asset, "Vendor29", "AppD29", "9.5", vendor.getId(), appD.getId());

        Vulnerability vuln = saveVulnerability("CVE-2099-0029", "CASE-29", new BigDecimal("9.4"));

        VulnerabilityCriteriaNode root0 = saveOperatorNode(vuln, null, 0, 0, CriteriaOperator.AND);
        VulnerabilityCriteriaNode root0A = saveLeafNode(vuln, root0.getId(), 0, 0);
        VulnerabilityCriteriaNode root0B = saveLeafNode(vuln, root0.getId(), 0, 1);
        VulnerabilityCriteriaNode root1D = saveLeafNode(vuln, null, 1, 0);

        saveCriteriaCpe(root0A, vuln, "cpe:2.3:a:vendor29:appa29:*:*:*:*:*:*:*:*",
                vendor.getId(), appA.getId(), "vendor29", "appa29", "a", "*", "*",
                "9.0", "", "10.0", "");
        saveCriteriaCpe(root0B, vuln, "cpe:2.3:a:vendor29:appb29:*:*:*:*:*:*:*:*",
                vendor.getId(), appB.getId(), "vendor29", "appb29", "a", "*", "*",
                "9.0", "", "10.0", "");
        saveCriteriaCpe(root1D, vuln, "cpe:2.3:a:vendor29:appd29:*:*:*:*:*:*:*:*",
                vendor.getId(), appD.getId(), "vendor29", "appd29", "a", "*", "*",
                "9.0", "", "10.0", "");

        saveAffectedFlat(vuln, "cpe:2.3:a:vendor29:appa29:*:*:*:*:*:*:*:*",
                vendor.getId(), appA.getId(), "vendor29", "appa29", "a", "*", "*",
                "9.0", "", "10.0", "", root0A.getId(), 0);
        saveAffectedFlat(vuln, "cpe:2.3:a:vendor29:appb29:*:*:*:*:*:*:*:*",
                vendor.getId(), appB.getId(), "vendor29", "appb29", "a", "*", "*",
                "9.0", "", "10.0", "", root0B.getId(), 0);
        saveAffectedFlat(vuln, "cpe:2.3:a:vendor29:appd29:*:*:*:*:*:*:*:*",
                vendor.getId(), appD.getId(), "vendor29", "appd29", "a", "*", "*",
                "9.0", "", "10.0", "", root1D.getId(), 1);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isEqualTo(1);

        Alert alert = findAlert(swD.getId(), vuln.getId());
        assertThat(alert).isNotNull();
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
    }

    @Test
    @DisplayName("criteria match reopens AUTO_CLOSED alert")
    void matchAndUpsertAlerts_reopensAutoClosedAlert_forCriteriaMatch() {
        CpeVendor vendor = saveVendor("vendor30", "Vendor30");
        CpeProduct appA = saveProduct(vendor, "appa30", "AppA30");
        CpeProduct appB = saveProduct(vendor, "appb30", "AppB30");

        Asset asset = saveAsset("Host-30", "windows");
        SoftwareInstall swA = saveSoftwareCanonical(asset, "Vendor30", "AppA30", "10.2", vendor.getId(), appA.getId());
        SoftwareInstall swB = saveSoftwareCanonical(asset, "Vendor30", "AppB30", "10.2", vendor.getId(), appB.getId());

        Vulnerability vuln = saveVulnerability("CVE-2099-0030", "CASE-30", new BigDecimal("8.9"));

        VulnerabilityCriteriaNode root = saveOperatorNode(vuln, null, 0, 0, CriteriaOperator.AND);
        VulnerabilityCriteriaNode leafA = saveLeafNode(vuln, root.getId(), 0, 0);
        VulnerabilityCriteriaNode leafB = saveLeafNode(vuln, root.getId(), 0, 1);

        saveCriteriaCpe(leafA, vuln, "cpe:2.3:a:vendor30:appa30:*:*:*:*:*:*:*:*",
                vendor.getId(), appA.getId(), "vendor30", "appa30", "a", "*", "*",
                "10.0", "", "11.0", "");
        saveCriteriaCpe(leafB, vuln, "cpe:2.3:a:vendor30:appb30:*:*:*:*:*:*:*:*",
                vendor.getId(), appB.getId(), "vendor30", "appb30", "a", "*", "*",
                "10.0", "", "11.0", "");

        saveAffectedFlat(vuln, "cpe:2.3:a:vendor30:appa30:*:*:*:*:*:*:*:*",
                vendor.getId(), appA.getId(), "vendor30", "appa30", "a", "*", "*",
                "10.0", "", "11.0", "", leafA.getId(), 0);
        saveAffectedFlat(vuln, "cpe:2.3:a:vendor30:appb30:*:*:*:*:*:*:*:*",
                vendor.getId(), appB.getId(), "vendor30", "appb30", "a", "*", "*",
                "10.0", "", "11.0", "", leafB.getId(), 0);

        Alert closed = new Alert(
                swA,
                vuln,
                LocalDateTime.now().minusDays(2),
                AlertCertainty.CONFIRMED,
                null,
                AlertMatchMethod.DICT_ID
        );
        closed.close(CloseReason.AUTO_CLOSED_NO_LONGER_AFFECTED, LocalDateTime.now().minusDays(1));
        alertRepository.save(closed);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isZero();
        assertThat(result.alertsTouched()).isEqualTo(1);

        Alert alert = findAlert(swA.getId(), vuln.getId());
        assertThat(alert).isNotNull();
        assertThat(alert.getStatus()).isEqualTo(AlertStatus.OPEN);
        assertThat(alert.getCloseReason()).isNull();
        assertThat(alert.getClosedAt()).isNull();
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);

        assertNoAlert(swB.getId(), vuln.getId());
    }

    @Test
    @DisplayName("criteria leaf match still selects the correct install when the same asset has extra candidate installs")
    void matchAndUpsertAlerts_criteriaLeafMatch_ignoresExtraCandidateInstallInSameAsset() {
        CpeVendor vendor = saveVendor("vendor31", "Vendor31");
        CpeProduct appA = saveProduct(vendor, "appa31", "AppA31");
        CpeProduct appB = saveProduct(vendor, "appb31", "AppB31");

        Asset asset = saveAsset("Host-31", "windows");

        SoftwareInstall swA = saveSoftwareCanonical(
                asset,
                "Vendor31",
                "AppA31",
                "10.5",
                vendor.getId(),
                appA.getId()
        );

        SoftwareInstall swB = saveSoftwareCanonical(
                asset,
                "Vendor31",
                "AppB31",
                "10.5",
                vendor.getId(),
                appB.getId()
        );

        Vulnerability vuln = saveVulnerability("CVE-2099-0031", "CASE-31", new BigDecimal("8.1"));

        VulnerabilityCriteriaNode root = saveOperatorNode(vuln, null, 0, 0, CriteriaOperator.OR);
        VulnerabilityCriteriaNode leafA = saveLeafNode(vuln, root.getId(), 0, 0);

        saveCriteriaCpe(
                leafA,
                vuln,
                "cpe:2.3:a:vendor31:appa31:*:*:*:*:*:*:*:*",
                vendor.getId(),
                appA.getId(),
                "vendor31",
                "appa31",
                "a",
                "*",
                "*",
                "10.0",
                "",
                "11.0",
                ""
        );

        saveAffectedFlat(
                vuln,
                "cpe:2.3:a:vendor31:appa31:*:*:*:*:*:*:*:*",
                vendor.getId(),
                appA.getId(),
                "vendor31",
                "appa31",
                "a",
                "*",
                "*",
                "10.0",
                "",
                "11.0",
                "",
                leafA.getId(),
                0
        );

        saveAffectedFlat(
                vuln,
                "cpe:2.3:a:vendor31:appb31:*:*:*:*:*:*:*:*",
                vendor.getId(),
                appB.getId(),
                "vendor31",
                "appb31",
                "a",
                "*",
                "*",
                "10.0",
                "",
                "11.0",
                "",
                leafA.getId(),
                0
        );

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isEqualTo(1);
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(swA.getId(), vuln.getId());
        assertThat(alert).isNotNull();
        assertThat(alert.getStatus()).isEqualTo(AlertStatus.OPEN);
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);

        assertNoAlert(swB.getId(), vuln.getId());
        assertThat(alertRepository.findAll()).hasSize(1);
    }

    @Test
    @DisplayName("matchAndUpsertAlerts does not create alert when only same-vendor different-product canonical row exists")
    void matchAndUpsertAlerts_doesNotCreateAlert_forSameVendorDifferentProductCanonicalRow() {
        CpeVendor vendor = cpeVendorRepository.save(new CpeVendor("vendor_exact_pair", "Vendor Exact Pair"));
        CpeProduct appA = cpeProductRepository.save(new CpeProduct(vendor, "appa_exact_pair", "AppA Exact Pair"));
        CpeProduct appB = cpeProductRepository.save(new CpeProduct(vendor, "appb_exact_pair", "AppB Exact Pair"));

        Asset asset = assetRepository.save(new Asset("Host-ExactPair-01"));

        SoftwareInstall sw = new SoftwareInstall(asset, "AppA Exact Pair");
        sw.updateDetails("Vendor Exact Pair", "AppA Exact Pair", "10.5", null);
        sw.linkCanonical(vendor.getId(), appA.getId());
        sw = softwareInstallRepository.save(sw);

        Vulnerability vuln = new Vulnerability("NVD", "CVE-2099-9001");
        vuln.applyNvdDetails(
                "Should not match when only same-vendor different-product affected row exists",
                "3.1",
                new BigDecimal("7.5"),
                null,
                null
        );
        vuln = vulnerabilityRepository.save(vuln);

        affectedCpeRepository.save(new VulnerabilityAffectedCpe(
                vuln,
                "cpe:2.3:a:vendor_exact_pair:appb_exact_pair:*:*:*:*:*:*:*:*",
                vendor.getId(),
                appB.getId(),
                "vendor_exact_pair",
                "appb_exact_pair",
                "a",
                "*",
                "*",
                "10.0",
                "",
                "11.0",
                ""
        ));

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isZero();
        assertThat(result.alertsInserted()).isZero();
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = alertRepository
                .findBySoftwareInstallIdAndVulnerabilityId(sw.getId(), vuln.getId())
                .orElse(null);

        assertThat(alert).isNull();
        assertThat(alertRepository.findAll()).isEmpty();
    }
}