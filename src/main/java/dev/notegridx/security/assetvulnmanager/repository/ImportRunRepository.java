package dev.notegridx.security.assetvulnmanager.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import dev.notegridx.security.assetvulnmanager.domain.ImportRun;

public interface ImportRunRepository extends JpaRepository<ImportRun, Long> {
}