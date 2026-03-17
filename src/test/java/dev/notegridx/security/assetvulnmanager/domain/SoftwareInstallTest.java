package dev.notegridx.security.assetvulnmanager.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SoftwareInstallTest {

    @Test
    @DisplayName("disableCanonicalLink clears canonical ids and cpeName")
    void disableCanonicalLink_clearsCanonicalFields() {
        Asset asset = new Asset("asset-001");
        SoftwareInstall si = new SoftwareInstall(asset, "VirtualBox");

        si.updateDetails("Oracle", "VirtualBox", "7.0.10", "cpe:2.3:a:oracle:virtualbox:7.0.10:*:*:*:*:*:*:*");
        si.linkCanonical(100L, 200L);

        si.disableCanonicalLink();

        assertThat(si.isCanonicalLinkDisabled()).isTrue();
        assertThat(si.getCpeVendorId()).isNull();
        assertThat(si.getCpeProductId()).isNull();
        assertThat(si.getCpeName()).isNull();
    }

    @Test
    @DisplayName("enableCanonicalLink only flips disabled flag")
    void enableCanonicalLink_onlyFlipsFlag() {
        Asset asset = new Asset("asset-001");
        SoftwareInstall si = new SoftwareInstall(asset, "VirtualBox");

        si.disableCanonicalLink();
        si.enableCanonicalLink();

        assertThat(si.isCanonicalLinkDisabled()).isFalse();
        assertThat(si.getCpeVendorId()).isNull();
        assertThat(si.getCpeProductId()).isNull();
        assertThat(si.getCpeName()).isNull();
    }
}