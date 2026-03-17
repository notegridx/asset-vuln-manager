package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.PageRequest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class SoftwareInstallRepositoryTest {

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private SoftwareInstallRepository softwareInstallRepository;

    @Test
    @DisplayName("findNeedsCanonicalLink excludes canonicalLinkDisabled rows")
    void findNeedsCanonicalLink_excludesDisabledRows() {
        Asset asset = assetRepository.save(new Asset("asset-001"));

        SoftwareInstall enabled = new SoftwareInstall(asset, "VirtualBox");
        enabled.updateDetails("Oracle", "VirtualBox", "7.0.10", null);

        SoftwareInstall disabled = new SoftwareInstall(asset, "VirtualBox");
        disabled.updateDetails("Oracle", "VirtualBox", "7.0.11", null);
        disabled.disableCanonicalLink();

        softwareInstallRepository.saveAll(List.of(enabled, disabled));

        List<SoftwareInstall> rows = softwareInstallRepository.findNeedsCanonicalLink();

        assertThat(rows).extracting(SoftwareInstall::getId)
                .contains(enabled.getId())
                .doesNotContain(disabled.getId());
    }

    @Test
    @DisplayName("findNeedsCanonicalLinkIds excludes canonicalLinkDisabled rows")
    void findNeedsCanonicalLinkIds_excludesDisabledRows() {
        Asset asset = assetRepository.save(new Asset("asset-001"));

        SoftwareInstall enabled = new SoftwareInstall(asset, "VirtualBox");
        enabled.updateDetails("Oracle", "VirtualBox", "7.0.10", null);

        SoftwareInstall disabled = new SoftwareInstall(asset, "VirtualBox");
        disabled.updateDetails("Oracle", "VirtualBox", "7.0.11", null);
        disabled.disableCanonicalLink();

        softwareInstallRepository.saveAll(List.of(enabled, disabled));

        List<Long> ids = softwareInstallRepository.findNeedsCanonicalLinkIds(PageRequest.of(0, 50)).getContent();

        assertThat(ids)
                .contains(enabled.getId())
                .doesNotContain(disabled.getId());
    }
}