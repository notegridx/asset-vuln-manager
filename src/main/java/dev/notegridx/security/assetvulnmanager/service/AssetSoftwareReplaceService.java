package dev.notegridx.security.assetvulnmanager.service;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import dev.notegridx.security.assetvulnmanager.domain.Alert;
import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.ImportStagingSoftware;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportStagingSoftwareRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;

@Service
public class AssetSoftwareReplaceService {

    private final ImportStagingSoftwareRepository stagingSoftwareRepository;
    private final AssetRepository assetRepository;
    private final SoftwareInstallRepository softwareInstallRepository;
    private final AlertRepository alertRepository;
    private final AlertService alertService;

    public AssetSoftwareReplaceService(
            ImportStagingSoftwareRepository stagingSoftwareRepository,
            AssetRepository assetRepository,
            SoftwareInstallRepository softwareInstallRepository,
            AlertRepository alertRepository,
            AlertService alertService
    ) {
        this.stagingSoftwareRepository = stagingSoftwareRepository;
        this.assetRepository = assetRepository;
        this.softwareInstallRepository = softwareInstallRepository;
        this.alertRepository = alertRepository;
        this.alertService = alertService;
    }

    @Transactional
    public void prepareReplaceForRun(Long runId) {
        List<ImportStagingSoftware> rows = stagingSoftwareRepository.findByImportRunIdOrderByRowNoAsc(runId);

        Set<String> externalKeys = rows.stream()
                .filter(ImportStagingSoftware::isValid)
                .map(ImportStagingSoftware::getExternalKey)
                .filter(this::hasText)
                .collect(Collectors.toCollection(LinkedHashSet::new));

        for (String externalKey : externalKeys) {
            Asset asset = assetRepository.findByExternalKey(externalKey).orElse(null);
            if (asset == null) continue;

            List<SoftwareInstall> existing = softwareInstallRepository.findByAssetIdOrderByIdAsc(asset.getId());
            if (existing.isEmpty()) continue;

            List<Long> softwareIds = existing.stream()
                    .map(SoftwareInstall::getId)
                    .toList();

            List<Alert> relatedAlerts = alertRepository.findBySoftwareInstallIdIn(softwareIds);
            alertService.detachForDeletedSoftware(relatedAlerts);

            softwareInstallRepository.deleteByAssetId(asset.getId());
        }
    }

    private boolean hasText(String s) {
        return s != null && !s.trim().isEmpty();
    }
}