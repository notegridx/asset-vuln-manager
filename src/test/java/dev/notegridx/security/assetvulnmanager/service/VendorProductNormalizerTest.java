package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.repository.SystemSettingRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class VendorProductNormalizerTest {

    private SystemSettingRepository systemSettingRepository;
    private VendorProductNormalizer normalizer;

    @BeforeEach
    void setUp() {
        systemSettingRepository = mock(SystemSettingRepository.class);

        // Default: no settings stored → use built-in normalization behavior
        when(systemSettingRepository.findById(any()))
                .thenReturn(Optional.empty());

        normalizer = new VendorProductNormalizer(systemSettingRepository);
    }

    @Test
    void normalizeVendor_stripsCommonCompanySuffix() {
        assertThat(normalizer.normalizeVendor("Microsoft Corporation"))
                .isEqualTo("microsoft");

        assertThat(normalizer.normalizeVendor("Adobe Inc."))
                .isEqualTo("adobe .");
    }

    @Test
    void normalizeVendor_canReadDnStylePublisher() {
        assertThat(normalizer.normalizeVendor("O=Microsoft Corporation, CN=Microsoft Code Signing PCA"))
                .isEqualTo("microsoft");
    }

    @Test
    void normalizeProduct_normalizesCaseAndSpacing() {
        String actual = normalizer.normalizeProduct("Visual   Studio   Code");
        assertThat(actual).isEqualTo("visual studio code");
    }

    @Test
    void normalizeProduct_returnsNullForBlankInput() {
        assertThat(normalizer.normalizeProduct("   ")).isNull();
        assertThat(normalizer.normalizeProduct(null)).isNull();
    }
}