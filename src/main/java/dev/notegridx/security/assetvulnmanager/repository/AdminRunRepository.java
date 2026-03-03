package dev.notegridx.security.assetvulnmanager.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import dev.notegridx.security.assetvulnmanager.domain.AdminRun;

public interface AdminRunRepository extends JpaRepository<AdminRun, Long> {

    // /admin/runs の一覧で「直近N件」を引く用途（必要なら）
    List<AdminRun> findTop200ByOrderByStartedAtDescIdDesc();
}