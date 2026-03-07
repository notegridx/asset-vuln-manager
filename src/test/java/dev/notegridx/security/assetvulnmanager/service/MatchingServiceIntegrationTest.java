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
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertUncertainReason;
import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityAffectedCpeRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityRepository;
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
                "Test vulnerability",
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
                "Test vulnerability 2",
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
                "Test vulnerability 3",
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
                "Test vulnerability 4",
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
                "Test vulnerability 5",
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
                "Test vulnerability 6",
                "Test description 6",
                "3.1",
                new BigDecimal("9.0"),
                null,
                null
        );
        vuln = vulnerabilityRepository.save(vuln);

        // weaker candidate: no version constraint -> UNCONFIRMED
        affectedCpeRepository.save(new VulnerabilityAffectedCpe(
                vuln,
                "cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*",
                vendor.getId(),
                product.getId(),
                "microsoft",
                "edge",
                "",
                "",
                "",
                ""
        ));

        // better candidate: in-range -> CONFIRMED
        affectedCpeRepository.save(new VulnerabilityAffectedCpe(
                vuln,
                "cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*",
                vendor.getId(),
                product.getId(),
                "microsoft",
                "edge",
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
}