package dev.notegridx.security.assetvulnmanager.service;

import java.util.List;

import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import jakarta.persistence.EntityNotFoundException;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;

@Service
public class AssetService {

    private final AssetRepository assetRepository;
    private final SoftwareInstallRepository softwareInstallRepository;
    private final AlertRepository alertRepository;

    public AssetService(
            AssetRepository assetRepository,
            SoftwareInstallRepository softwareInstallRepository,
            AlertRepository alertRepository
    ) {
        this.assetRepository = assetRepository;
        this.softwareInstallRepository = softwareInstallRepository;
        this.alertRepository = alertRepository;
    }

    @Transactional
    public void deleteCascade(Long assetId) {
        var installs = softwareInstallRepository.findByAssetIdOrderByIdAsc(assetId);
        var installIds = installs.stream().map(i -> i.getId()).toList();

        if (!installIds.isEmpty()) {
            alertRepository.deleteBySoftwareInstallIdIn(installIds);
        }
        softwareInstallRepository.deleteByAssetId(assetId);
        assetRepository.deleteById(assetId);
    }

    @Transactional(readOnly = true)
    public List<Asset> findAll() {
        return assetRepository.findAll();
    }

    @Transactional(readOnly = true)
    public Asset getRequired(Long id) {
        return assetRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Asset not found. id=" + id));
    }

    @Transactional
    public Asset create(String externalKey, String name, String assetType, String owner, String note) {
        Asset asset = new Asset(name);
        asset.updateDetails(externalKey, assetType, owner, note);
        return assetRepository.save(asset);
    }

}
