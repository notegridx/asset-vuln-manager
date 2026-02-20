package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.AdminSyncRun;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AdminSyncRunRepository extends JpaRepository<AdminSyncRun, Long> {
    Optional<AdminSyncRun> findTop1ByOrderByRanAtDesc();
}
