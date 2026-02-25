package dev.notegridx.security.assetvulnmanager.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import dev.notegridx.security.assetvulnmanager.domain.ImportStagingSoftware;

public interface ImportStagingSoftwareRepository extends JpaRepository<ImportStagingSoftware, Long> {
    List<ImportStagingSoftware> findByImportRunIdOrderByRowNoAsc(Long importRunId);

    long deleteByImportRunId(Long importRunId);
}