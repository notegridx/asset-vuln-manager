package dev.notegridx.security.assetvulnmanager.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import dev.notegridx.security.assetvulnmanager.domain.AdminRun;
import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;

public interface AdminRunRepository extends JpaRepository<AdminRun, Long> {

    // /admin/runs の一覧で「直近N件」を引く用途（必要なら）
    List<AdminRun> findTop200ByOrderByStartedAtDescIdDesc();

    // /admin/sync で「このジョブの直近1件」を表示する用途
    Optional<AdminRun> findTop1ByJobTypeOrderByStartedAtDescIdDesc(AdminJobType jobType);
}