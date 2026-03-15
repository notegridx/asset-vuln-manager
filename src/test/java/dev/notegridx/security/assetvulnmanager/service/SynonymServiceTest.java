package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeProductAlias;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendorAlias;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductAliasRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorAliasRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("mysqltest")
class SynonymServiceTest {

    @Autowired
    SynonymService synonymService;

    @Autowired
    CpeVendorRepository vendorRepository;

    @Autowired
    CpeProductRepository productRepository;

    @Autowired
    CpeVendorAliasRepository vendorAliasRepository;

    @Autowired
    CpeProductAliasRepository productAliasRepository;

    @BeforeEach
    void reset() {
        productAliasRepository.deleteAll();
        vendorAliasRepository.deleteAll();
        productRepository.deleteAll();
        vendorRepository.deleteAll();
        synonymService.clearCaches();
    }

    @Test
    void canonicalVendorOrSame_resolvesAlias() {
        CpeVendor v = vendorRepository.save(new CpeVendor("microsoft", "Microsoft"));
        vendorAliasRepository.save(new CpeVendorAlias(v.getId(), "ms", "alias"));

        String result = synonymService.canonicalVendorOrSame("ms");

        assertThat(result).isEqualTo("microsoft");
    }

    @Test
    void canonicalVendorOrSame_returnsSameIfAliasNotFound() {
        vendorRepository.save(new CpeVendor("microsoft", "Microsoft"));

        String result = synonymService.canonicalVendorOrSame("microsoft");

        assertThat(result).isEqualTo("microsoft");
    }

    @Test
    void canonicalVendorOrSame_ignoresInactiveAlias() {
        CpeVendor v = vendorRepository.save(new CpeVendor("microsoft", "Microsoft"));

        CpeVendorAlias alias = new CpeVendorAlias(v.getId(), "ms", "alias");
        alias.setStatus(CpeVendorAlias.STATUS_INACTIVE);
        vendorAliasRepository.save(alias);

        String result = synonymService.canonicalVendorOrSame("ms");

        assertThat(result).isEqualTo("ms");
    }

    @Test
    void canonicalProductOrSame_resolvesAlias() {
        CpeVendor v = vendorRepository.save(new CpeVendor("google", "Google"));
        CpeProduct p = productRepository.save(new CpeProduct(v, "chrome", "Chrome"));

        CpeProductAlias alias = new CpeProductAlias(v.getId(), p.getId(), "google chrome", "alias");
        alias.setConfidence(0);
        productAliasRepository.save(alias);

        String result = synonymService.canonicalProductOrSame("google", "google chrome");

        assertThat(result).isEqualTo("chrome");
    }

    @Test
    void canonicalProductOrSame_vendorScope() {
        CpeVendor google = vendorRepository.save(new CpeVendor("google", "Google"));
        CpeVendor other = vendorRepository.save(new CpeVendor("other", "Other"));

        CpeProduct chrome = productRepository.save(new CpeProduct(google, "chrome", "Chrome"));

        CpeProductAlias alias = new CpeProductAlias(google.getId(), chrome.getId(), "browser", "alias");
        alias.setConfidence(0);
        productAliasRepository.save(alias);

        String result1 = synonymService.canonicalProductOrSame("google", "browser");
        String result2 = synonymService.canonicalProductOrSame("other", "browser");

        assertThat(result1).isEqualTo("chrome");
        assertThat(result2).isEqualTo("browser");
    }

    @Test
    void canonicalProductOrSame_vendorNotFound() {
        String result = synonymService.canonicalProductOrSame("unknown", "chrome");

        assertThat(result).isEqualTo("chrome");
    }

    @Test
    void canonicalVendorOrSame_cacheWorks() {
        CpeVendor v = vendorRepository.save(new CpeVendor("microsoft", "Microsoft"));
        vendorAliasRepository.save(new CpeVendorAlias(v.getId(), "ms", "alias"));

        String r1 = synonymService.canonicalVendorOrSame("ms");
        String r2 = synonymService.canonicalVendorOrSame("ms");

        assertThat(r1).isEqualTo("microsoft");
        assertThat(r2).isEqualTo("microsoft");
    }
}