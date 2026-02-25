package dev.notegridx.security.assetvulnmanager.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import dev.notegridx.security.assetvulnmanager.domain.ImportStagingAsset;

public interface ImportStagingAssetRepository extends JpaRepository<ImportStagingAsset, Long> {
    List<ImportStagingAsset> findByImportRunIdOrderByRowNoAsc(Long importRunId);

    long deleteByImportRunId(Long importRunId);
}