package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.repository.UnresolvedMappingRepository;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class CanonicalBackfillServiceTest {

    private SoftwareInstallRepository softwareRepo;
    private CanonicalCpeLinkingService linker;
    private UnresolvedMappingRepository unresolvedMappingRepository;
    private VendorProductNormalizer normalizer;
    private CpeVendorRepository cpeVendorRepository;
    private CpeProductRepository cpeProductRepository;
    private EntityManager em;
    private PlatformTransactionManager txManager;

    private CanonicalBackfillService service;

    @BeforeEach
    void setUp() {
        softwareRepo = mock(SoftwareInstallRepository.class);
        linker = mock(CanonicalCpeLinkingService.class);
        unresolvedMappingRepository = mock(UnresolvedMappingRepository.class);
        normalizer = mock(VendorProductNormalizer.class);
        cpeVendorRepository = mock(CpeVendorRepository.class);
        cpeProductRepository = mock(CpeProductRepository.class);
        em = mock(EntityManager.class);
        txManager = mock(PlatformTransactionManager.class);

        TransactionStatus txStatus = mock(TransactionStatus.class);
        when(txManager.getTransaction(any(TransactionDefinition.class))).thenReturn(txStatus);

        service = new CanonicalBackfillService(
                softwareRepo,
                linker,
                unresolvedMappingRepository,
                normalizer,
                cpeVendorRepository,
                cpeProductRepository,
                em,
                txManager
        );

        when(normalizer.normalizeVendor(anyString()))
                .thenAnswer(inv -> inv.getArgument(0));
        when(normalizer.normalizeProduct(anyString()))
                .thenAnswer(inv -> inv.getArgument(0));

        when(cpeVendorRepository.findTop20ByNameNormStartingWithOrderByNameNormAsc(anyString()))
                .thenReturn(List.of());
        when(unresolvedMappingRepository.save(any(UnresolvedMapping.class)))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    @DisplayName("backfill: full hit resolves existing unresolved mapping to RESOLVED")
    void backfill_fullHit_resolvesExistingUnresolvedMapping() {
        SoftwareInstall s = software("Oracle", "VirtualBox", "7.0.10");

        UnresolvedMapping existing = UnresolvedMapping.create(
                "JSON_UPLOAD",
                "Oracle",
                "VirtualBox",
                "7.0.9"
        );

        when(softwareRepo.findNeedsCanonicalLink()).thenReturn(List.of(s));
        when(linker.resolve(any(SoftwareInstall.class)))
                .thenReturn(CanonicalCpeLinkingService.ResolveResult.hit(
                        101L, 202L, "oracle", "virtualbox", false
                ));
        when(unresolvedMappingRepository.findTopByVendorRawAndProductRaw("Oracle", "VirtualBox"))
                .thenReturn(Optional.of(existing));

        CanonicalBackfillService.BackfillResult result = service.backfill(100, false);

        assertThat(result.scanned()).isEqualTo(1);
        assertThat(result.linked()).isEqualTo(1);
        assertThat(result.missed()).isEqualTo(0);
        assertThat(result.forceRebuild()).isFalse();

        assertThat(s.getCpeVendorId()).isEqualTo(101L);
        assertThat(s.getCpeProductId()).isEqualTo(202L);

        verify(unresolvedMappingRepository, times(1))
                .findTopByVendorRawAndProductRaw("Oracle", "VirtualBox");
        verify(unresolvedMappingRepository, times(1))
                .save(existing);

        assertThat(existing.getStatus()).isEqualTo("RESOLVED");
        assertThat(existing.getLastSeenAt()).isNotNull();
    }

    @Test
    @DisplayName("backfillForSoftwareIds: full hit resolves existing unresolved mapping to RESOLVED")
    void backfillForSoftwareIds_fullHit_resolvesExistingUnresolvedMapping() {
        SoftwareInstall s = software("Oracle", "VirtualBox", "7.0.10");

        UnresolvedMapping existing = UnresolvedMapping.create(
                "JSON_UPLOAD",
                "Oracle",
                "VirtualBox",
                "7.0.9"
        );

        when(softwareRepo.findAllById(List.of(10L))).thenReturn(List.of(s));
        when(linker.resolve(any(SoftwareInstall.class)))
                .thenReturn(CanonicalCpeLinkingService.ResolveResult.hit(
                        101L, 202L, "oracle", "virtualbox", false
                ));
        when(unresolvedMappingRepository.findTopByVendorRawAndProductRaw("Oracle", "VirtualBox"))
                .thenReturn(Optional.of(existing));

        CanonicalBackfillService.BackfillResult result =
                service.backfillForSoftwareIds(List.of(10L), false);

        assertThat(result.scanned()).isEqualTo(1);
        assertThat(result.linked()).isEqualTo(1);
        assertThat(result.missed()).isEqualTo(0);
        assertThat(result.forceRebuild()).isFalse();

        assertThat(s.getCpeVendorId()).isEqualTo(101L);
        assertThat(s.getCpeProductId()).isEqualTo(202L);

        verify(softwareRepo).findAllById(List.of(10L));
        verify(unresolvedMappingRepository, times(1))
                .findTopByVendorRawAndProductRaw("Oracle", "VirtualBox");
        verify(unresolvedMappingRepository, times(1))
                .save(existing);

        assertThat(existing.getStatus()).isEqualTo("RESOLVED");
        assertThat(existing.getLastSeenAt()).isNotNull();
    }

    @Test
    @DisplayName("backfill: upsert each unresolved key only once per run, while keeping missed count based on software rows")
    void backfill_dedupesUnresolvedUpsert_butKeepsMissedCount() {
        SoftwareInstall s1 = software(" raw-vendor ", " raw-product ", "1.0");
        SoftwareInstall s2 = software("raw-vendor", "raw-product", "2.0");

        when(softwareRepo.findNeedsCanonicalLink()).thenReturn(List.of(s1, s2));
        when(linker.resolve(any(SoftwareInstall.class)))
                .thenReturn(CanonicalCpeLinkingService.ResolveResult.vendorOnly(
                        101L, "raw-vendor", "raw-product", "product unresolved", false
                ));

        when(unresolvedMappingRepository.findTopByVendorRawAndProductRaw("raw-vendor", "raw-product"))
                .thenReturn(Optional.empty());

        CanonicalBackfillService.BackfillResult result = service.backfill(100, false);

        assertThat(result.scanned()).isEqualTo(2);
        assertThat(result.linked()).isEqualTo(2);
        assertThat(result.missed()).isEqualTo(2);
        assertThat(result.forceRebuild()).isFalse();

        verify(unresolvedMappingRepository, times(1))
                .findTopByVendorRawAndProductRaw("raw-vendor", "raw-product");
        verify(unresolvedMappingRepository, times(1))
                .save(any(UnresolvedMapping.class));

        ArgumentCaptor<UnresolvedMapping> captor = ArgumentCaptor.forClass(UnresolvedMapping.class);
        verify(unresolvedMappingRepository).save(captor.capture());

        UnresolvedMapping saved = captor.getValue();
        assertThat(saved.getVendorRaw()).isEqualTo("raw-vendor");
        assertThat(saved.getProductRaw()).isEqualTo("raw-product");
        assertThat(saved.getVersionRaw()).isEqualTo("1.0");
    }

    @Test
    @DisplayName("backfillForSoftwareIds: upserts each unresolved key only once per run and keeps missed count based on software rows")
    void backfillForSoftwareIds_dedupesUnresolvedUpsert_butKeepsMissedCount() {
        SoftwareInstall s1 = software(" same-vendor ", " same-product ", "3.1");
        SoftwareInstall s2 = software("same-vendor", "same-product", "3.2");
        SoftwareInstall s3 = software("same-vendor", "same-product", "3.3");

        when(softwareRepo.findAllById(anyList())).thenReturn(List.of(s1, s2, s3));
        when(linker.resolve(any(SoftwareInstall.class)))
                .thenReturn(CanonicalCpeLinkingService.ResolveResult.miss(
                        "vendor unresolved", false, null, null, null
                ));

        when(unresolvedMappingRepository.findTopByVendorRawAndProductRaw("same-vendor", "same-product"))
                .thenReturn(Optional.empty());

        CanonicalBackfillService.BackfillResult result =
                service.backfillForSoftwareIds(List.of(10L, 20L, 30L), false);

        assertThat(result.scanned()).isEqualTo(3);
        assertThat(result.linked()).isEqualTo(0);
        assertThat(result.missed()).isEqualTo(3);
        assertThat(result.forceRebuild()).isFalse();

        verify(unresolvedMappingRepository, times(1))
                .findTopByVendorRawAndProductRaw("same-vendor", "same-product");
        verify(unresolvedMappingRepository, times(1))
                .save(any(UnresolvedMapping.class));

        ArgumentCaptor<UnresolvedMapping> captor = ArgumentCaptor.forClass(UnresolvedMapping.class);
        verify(unresolvedMappingRepository).save(captor.capture());

        UnresolvedMapping saved = captor.getValue();
        assertThat(saved.getVendorRaw()).isEqualTo("same-vendor");
        assertThat(saved.getProductRaw()).isEqualTo("same-product");
        assertThat(saved.getVersionRaw()).isEqualTo("3.1");
    }

    @Test
    @DisplayName("backfill skips canonicalLinkDisabled row even when resolve returns vendorOnly")
    void backfill_skipsDisabledRow() {
        SoftwareInstall disabled = software("Oracle", "VirtualBox", "7.0.10");
        disabled.disableCanonicalLink();

        SoftwareInstall enabled = software("Oracle", "VirtualBox", "7.0.11");

        when(softwareRepo.findNeedsCanonicalLink()).thenReturn(List.of(disabled, enabled));
        when(linker.resolve(enabled))
                .thenReturn(CanonicalCpeLinkingService.ResolveResult.vendorOnly(
                        101L, "oracle", "virtualbox", "product unresolved", false
                ));

        when(unresolvedMappingRepository.findTopByVendorRawAndProductRaw("Oracle", "VirtualBox"))
                .thenReturn(Optional.empty());

        CanonicalBackfillService.BackfillResult result = service.backfill(100, false);

        assertThat(result.scanned()).isEqualTo(2);
        assertThat(result.linked()).isEqualTo(1);
        assertThat(result.missed()).isEqualTo(1);
        assertThat(result.forceRebuild()).isFalse();

        assertThat(disabled.getCpeVendorId()).isNull();
        assertThat(disabled.getCpeProductId()).isNull();

        assertThat(enabled.getCpeVendorId()).isEqualTo(101L);
        assertThat(enabled.getCpeProductId()).isNull();

        verify(linker, never()).resolve(disabled);
        verify(linker, times(1)).resolve(enabled);
        verify(unresolvedMappingRepository, times(1))
                .findTopByVendorRawAndProductRaw("Oracle", "VirtualBox");
        verify(unresolvedMappingRepository, times(1))
                .save(any(UnresolvedMapping.class));
    }

    @Test
    @DisplayName("backfillForSoftwareIds skips canonicalLinkDisabled row even when resolve returns vendorOnly")
    void backfillForSoftwareIds_skipsDisabledRow() {
        SoftwareInstall disabled = software("Oracle", "VirtualBox", "7.0.10");
        disabled.disableCanonicalLink();

        SoftwareInstall enabled = software("Oracle", "VirtualBox", "7.0.11");

        when(softwareRepo.findAllById(List.of(10L, 11L))).thenReturn(List.of(disabled, enabled));
        when(linker.resolve(enabled))
                .thenReturn(CanonicalCpeLinkingService.ResolveResult.vendorOnly(
                        101L, "oracle", "virtualbox", "product unresolved", false
                ));

        when(unresolvedMappingRepository.findTopByVendorRawAndProductRaw("Oracle", "VirtualBox"))
                .thenReturn(Optional.empty());

        CanonicalBackfillService.BackfillResult result =
                service.backfillForSoftwareIds(List.of(10L, 11L), false);

        assertThat(result.scanned()).isEqualTo(2);
        assertThat(result.linked()).isEqualTo(1);
        assertThat(result.missed()).isEqualTo(1);
        assertThat(result.forceRebuild()).isFalse();

        assertThat(disabled.getCpeVendorId()).isNull();
        assertThat(disabled.getCpeProductId()).isNull();

        assertThat(enabled.getCpeVendorId()).isEqualTo(101L);
        assertThat(enabled.getCpeProductId()).isNull();

        verify(softwareRepo).findAllById(List.of(10L, 11L));
        verify(linker, never()).resolve(disabled);
        verify(linker, times(1)).resolve(enabled);
        verify(unresolvedMappingRepository, times(1))
                .findTopByVendorRawAndProductRaw("Oracle", "VirtualBox");
        verify(unresolvedMappingRepository, times(1))
                .save(any(UnresolvedMapping.class));
    }

    @Test
    @DisplayName("backfill caches resolve results within a single run for identical software keys")
    void backfill_cachesResolveResultsWithinSingleRun() {
        SoftwareInstall s1 = software("Google LLC", "Google Chrome", "145.0.7632.159");
        SoftwareInstall s2 = software("Google LLC", "Google Chrome", "145.0.7632.159");

        when(softwareRepo.findNeedsCanonicalLink()).thenReturn(List.of(s1, s2));
        when(linker.resolve(any(SoftwareInstall.class)))
                .thenReturn(CanonicalCpeLinkingService.ResolveResult.vendorOnly(
                        97L,
                        "google",
                        "chrome",
                        "product unresolved",
                        false
                ));

        when(unresolvedMappingRepository.findTopByVendorRawAndProductRaw("Google LLC", "Google Chrome"))
                .thenReturn(Optional.empty());

        CanonicalBackfillService.BackfillResult result = service.backfill(100, false);

        assertThat(result.scanned()).isEqualTo(2);
        assertThat(result.linked()).isEqualTo(2);
        assertThat(result.missed()).isEqualTo(2);
        assertThat(result.forceRebuild()).isFalse();

        verify(linker, times(1)).resolve(any(SoftwareInstall.class));
        verify(unresolvedMappingRepository, times(1))
                .findTopByVendorRawAndProductRaw("Google LLC", "Google Chrome");
        verify(unresolvedMappingRepository, times(1))
                .save(any(UnresolvedMapping.class));

        assertThat(s1.getCpeVendorId()).isEqualTo(97L);
        assertThat(s1.getCpeProductId()).isNull();
        assertThat(s2.getCpeVendorId()).isEqualTo(97L);
        assertThat(s2.getCpeProductId()).isNull();
    }

    @Test
    @DisplayName("backfillForSoftwareIds caches resolve results within a single run for identical software keys")
    void backfillForSoftwareIds_cachesResolveResultsWithinSingleRun() {
        SoftwareInstall s1 = software("Google LLC", "Google Chrome", "145.0.7632.159");
        SoftwareInstall s2 = software("Google LLC", "Google Chrome", "145.0.7632.159");

        when(softwareRepo.findAllById(List.of(10L, 11L))).thenReturn(List.of(s1, s2));
        when(linker.resolve(any(SoftwareInstall.class)))
                .thenReturn(CanonicalCpeLinkingService.ResolveResult.vendorOnly(
                        97L,
                        "google",
                        "chrome",
                        "product unresolved",
                        false
                ));

        when(unresolvedMappingRepository.findTopByVendorRawAndProductRaw("Google LLC", "Google Chrome"))
                .thenReturn(Optional.empty());

        CanonicalBackfillService.BackfillResult result =
                service.backfillForSoftwareIds(List.of(10L, 11L), false);

        assertThat(result.scanned()).isEqualTo(2);
        assertThat(result.linked()).isEqualTo(2);
        assertThat(result.missed()).isEqualTo(2);
        assertThat(result.forceRebuild()).isFalse();

        verify(softwareRepo).findAllById(List.of(10L, 11L));
        verify(linker, times(1)).resolve(any(SoftwareInstall.class));
        verify(unresolvedMappingRepository, times(1))
                .findTopByVendorRawAndProductRaw("Google LLC", "Google Chrome");
        verify(unresolvedMappingRepository, times(1))
                .save(any(UnresolvedMapping.class));

        assertThat(s1.getCpeVendorId()).isEqualTo(97L);
        assertThat(s1.getCpeProductId()).isNull();
        assertThat(s2.getCpeVendorId()).isEqualTo(97L);
        assertThat(s2.getCpeProductId()).isNull();
    }

    private SoftwareInstall software(String vendorRaw, String productRaw, String versionRaw) {
        Asset asset = new Asset("test-asset");
        SoftwareInstall s = new SoftwareInstall(asset, productRaw.trim());
        s.updateDetails(vendorRaw, productRaw, versionRaw, null);
        s.captureRaw(vendorRaw, productRaw, versionRaw);
        s.setSource("JSON_UPLOAD");
        return s;
    }
}