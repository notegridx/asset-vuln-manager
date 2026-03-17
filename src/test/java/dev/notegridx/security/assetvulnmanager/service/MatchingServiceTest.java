package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityAffectedCpeRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityRepository;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class MatchingServiceTest {

    @Test
    @DisplayName("matchAndUpsertAlerts skips canonicalLinkDisabled installs")
    void matchAndUpsertAlerts_skipsDisabledInstalls() {
        SoftwareInstallRepository softwareRepo = mock(SoftwareInstallRepository.class);
        VulnerabilityAffectedCpeRepository affectedRepo = mock(VulnerabilityAffectedCpeRepository.class);
        VulnerabilityRepository vulnerabilityRepo = mock(VulnerabilityRepository.class);
        AlertRepository alertRepo = mock(AlertRepository.class);
        CanonicalBackfillService canonicalBackfillService = mock(CanonicalBackfillService.class);
        CriteriaTreeLoader criteriaTreeLoader = mock(CriteriaTreeLoader.class);
        CriteriaEvaluator criteriaEvaluator = mock(CriteriaEvaluator.class);
        EntityManager entityManager = mock(EntityManager.class);

        MatchingService service = new MatchingService(
                softwareRepo,
                affectedRepo,
                vulnerabilityRepo,
                alertRepo,
                canonicalBackfillService,
                criteriaTreeLoader,
                criteriaEvaluator,
                entityManager
        );

        Asset asset = new Asset("asset-001");

        SoftwareInstall disabled = new SoftwareInstall(asset, "VirtualBox");
        disabled.updateDetails("Oracle", "VirtualBox", "7.0.10", "cpe:2.3:a:oracle:virtualbox:7.0.10:*:*:*:*:*:*:*");
        disabled.disableCanonicalLink();

        when(softwareRepo.findAllWithAsset()).thenReturn(List.of(disabled));
        when(alertRepo.closeStaleOpenAlerts(any(), any(), any())).thenReturn(1);

        service.matchAndUpsertAlerts();

        verify(affectedRepo, never()).findAllByCanonicalPairs(anyList());
        verify(affectedRepo, never()).findAllByNormPairs(anyList());
        verify(affectedRepo, never()).findByCpeNameIn(anyList());
        verify(alertRepo, never()).saveAll(anyList());
        verify(alertRepo).closeStaleOpenAlerts(any(), any(), any());
    }
}