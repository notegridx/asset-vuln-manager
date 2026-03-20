package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.web.form.SoftwareInstallForm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class SoftwareInstallServiceTest {

    @Test
    @DisplayName("updateDetails keeps canonical fields cleared when canonicalLinkDisabled is true")
    void updateDetails_keepsCanonicalFieldsCleared_whenDisabled() {
        SoftwareInstallRepository softwareRepo = mock(SoftwareInstallRepository.class);
        AlertRepository alertRepo = mock(AlertRepository.class);
        SoftwareDictionaryValidator dictValidator = mock(SoftwareDictionaryValidator.class);

        SoftwareInstallService service = new SoftwareInstallService(
                softwareRepo,
                alertRepo,
                dictValidator,
                "LENIENT"
        );

        Asset asset = new Asset("test-asset");
        SoftwareInstall si = new SoftwareInstall(asset, "VirtualBox");
        si.updateDetails(
                "Oracle",
                "VirtualBox",
                "7.0.10",
                "cpe:2.3:a:oracle:virtualbox:7.0.10:*:*:*:*:*:*:*"
        );
        si.linkCanonical(10L, 20L);
        si.disableCanonicalLink();

        when(softwareRepo.findById(si.getId())).thenReturn(Optional.of(si));
        when(softwareRepo.save(any(SoftwareInstall.class))).thenAnswer(inv -> inv.getArgument(0));
        when(dictValidator.resolve(anyString(), anyString()))
                .thenReturn(new SoftwareDictionaryValidator.Resolve(
                        true,
                        10L,
                        20L,
                        null,
                        null,
                        null,
                        null,
                        null
                ));

        SoftwareInstall saved = service.updateDetails(
                si.getId(),
                "Oracle",
                "VirtualBox",
                "7.0.11",
                "cpe:2.3:a:oracle:virtualbox:7.0.11:*:*:*:*:*:*:*"
        );

        assertThat(saved.isCanonicalLinkDisabled()).isTrue();
        assertThat(saved.getCpeVendorId()).isNull();
        assertThat(saved.getCpeProductId()).isNull();
        assertThat(saved.getCpeName()).isNull();

        verify(dictValidator).resolve("Oracle", "VirtualBox");
        verify(softwareRepo).save(si);
    }

    @Test
    @DisplayName("updateEditableFields keeps canonical fields cleared when canonicalLinkDisabled is true")
    void updateEditableFields_keepsCanonicalFieldsCleared_whenDisabled() {
        SoftwareInstallRepository softwareRepo = mock(SoftwareInstallRepository.class);
        AlertRepository alertRepo = mock(AlertRepository.class);
        SoftwareDictionaryValidator dictValidator = mock(SoftwareDictionaryValidator.class);

        SoftwareInstallService service = new SoftwareInstallService(
                softwareRepo,
                alertRepo,
                dictValidator,
                "LENIENT"
        );

        Asset asset = new Asset("test-asset");
        SoftwareInstall si = new SoftwareInstall(asset, "VirtualBox");
        si.updateDetails(
                "Oracle",
                "VirtualBox",
                "7.0.10",
                "cpe:2.3:a:oracle:virtualbox:7.0.10:*:*:*:*:*:*:*"
        );
        si.linkCanonical(10L, 20L);
        si.disableCanonicalLink();

        SoftwareInstallForm form = new SoftwareInstallForm();
        form.setVendor("Oracle");
        form.setProduct("VirtualBox");
        form.setVersion("7.0.11");
        form.setCpeName("cpe:2.3:a:oracle:virtualbox:7.0.11:*:*:*:*:*:*:*");
        form.setType("APPLICATION");
        form.setSource("MANUAL");
        form.setVendorRaw("Oracle");
        form.setProductRaw("VirtualBox");
        form.setVersionRaw("7.0.11");
        form.setSourceType("JSON_UPLOAD");

        when(softwareRepo.findById(si.getId())).thenReturn(Optional.of(si));
        when(softwareRepo.save(any(SoftwareInstall.class))).thenAnswer(inv -> inv.getArgument(0));
        when(dictValidator.resolve(anyString(), anyString()))
                .thenReturn(new SoftwareDictionaryValidator.Resolve(
                        true,
                        10L,
                        20L,
                        null,
                        null,
                        null,
                        null,
                        null
                ));

        SoftwareInstall saved = service.updateEditableFields(si.getId(), form);

        assertThat(saved.isCanonicalLinkDisabled()).isTrue();
        assertThat(saved.getCpeVendorId()).isNull();
        assertThat(saved.getCpeProductId()).isNull();
        assertThat(saved.getCpeName()).isNull();

        verify(dictValidator, never()).resolve(anyString(), anyString());
        verify(softwareRepo).save(si);
    }

    @Test
    @DisplayName("updateDetails restores canonical link normally when canonicalLinkDisabled is false")
    void updateDetails_linksNormally_whenEnabled() {
        SoftwareInstallRepository softwareRepo = mock(SoftwareInstallRepository.class);
        AlertRepository alertRepo = mock(AlertRepository.class);
        SoftwareDictionaryValidator dictValidator = mock(SoftwareDictionaryValidator.class);

        SoftwareInstallService service = new SoftwareInstallService(
                softwareRepo,
                alertRepo,
                dictValidator,
                "LENIENT"
        );

        Asset asset = new Asset("test-asset");
        SoftwareInstall si = new SoftwareInstall(asset, "VirtualBox");
        si.updateDetails("Oracle", "VirtualBox", "7.0.10", null);

        when(softwareRepo.findById(si.getId())).thenReturn(Optional.of(si));
        when(softwareRepo.save(any(SoftwareInstall.class))).thenAnswer(inv -> inv.getArgument(0));
        when(dictValidator.resolve(anyString(), anyString()))
                .thenReturn(new SoftwareDictionaryValidator.Resolve(
                        true,
                        10L,
                        20L,
                        null,
                        null,
                        null,
                        null,
                        null
                ));

        SoftwareInstall saved = service.updateDetails(
                si.getId(),
                "Oracle",
                "VirtualBox",
                "7.0.11",
                null
        );

        assertThat(saved.isCanonicalLinkDisabled()).isFalse();
        assertThat(saved.getCpeVendorId()).isEqualTo(10L);
        assertThat(saved.getCpeProductId()).isEqualTo(20L);
    }
}