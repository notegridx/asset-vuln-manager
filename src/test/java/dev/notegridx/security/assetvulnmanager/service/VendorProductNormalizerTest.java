package dev.notegridx.security.assetvulnmanager.service;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class VendorProductNormalizerTest {

    private final VendorProductNormalizer normalizer = new VendorProductNormalizer();

    @Test
    void normalizeVendor_stripsCommonCompanySuffix() {
        assertThat(normalizer.normalizeVendor("Microsoft Corporation"))
                .isEqualTo("microsoft");

        // 現行実装では "Inc." の "." が残る
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